// Command audittrail-stress is Task 2.4: fire N concurrent appends for ONE
// tenant (optionally spread across several API instances) and then prove the
// resulting chain has zero broken links, zero gaps and no lost or duplicated
// events. Also exercises the 409 paths and idempotent replay.
//
//	audittrail-stress -api http://localhost:8080,http://localhost:8081 -n 1000
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/canon"
	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/verify"
)

var (
	apis   []string
	admin  string
	client = &http.Client{Timeout: 120 * time.Second, Transport: &http.Transport{
		MaxIdleConns: 2000, MaxIdleConnsPerHost: 2000, IdleConnTimeout: 30 * time.Second}}
)

func uuid() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func call(method, url, auth string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && len(data) > 0 {
		_ = json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

func fail(format string, a ...any) {
	fmt.Printf("FAIL: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	config.LoadDotEnv()
	apiFlag := flag.String("api", "http://localhost:8080", "comma-separated API base URLs (requests round-robin across them)")
	n := flag.Int("n", 1000, "concurrent requests")
	flag.Parse()
	for _, a := range strings.Split(*apiFlag, ",") {
		apis = append(apis, strings.TrimRight(strings.TrimSpace(a), "/"))
	}
	admin = os.Getenv("AUDITTRAIL_ADMIN_TOKEN")
	if admin == "" {
		fail("AUDITTRAIL_ADMIN_TOKEN not set")
	}

	// Fresh tenant with a limit high enough not to throttle the burst.
	var created struct {
		Tenant struct{ ID string } `json:"tenant"`
		APIKey string              `json:"api_key"`
	}
	code, err := call("POST", apis[0]+"/v1/admin/tenants", admin, map[string]any{
		"name": "stress-" + time.Now().Format("150405"), "rate_limit_rps": 100000, "rate_limit_burst": 100000}, &created)
	if err != nil || code != 201 {
		fail("create tenant: %d %v", code, err)
	}
	key, tenantID := created.APIKey, created.Tenant.ID
	fmt.Printf("tenant %s, %d instance(s), firing %d concurrent appends...\n", tenantID, len(apis), *n)

	// ---- the burst ----------------------------------------------------------
	type result struct {
		code int
		rec  ledger.Record
		sub  map[string]any
		err  error
	}
	results := make([]result, *n)
	var mu sync.Mutex
	transportRetries := 0
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sub := map[string]any{
				"id": uuid(), "timestamp": time.Now().UTC().Format(time.RFC3339Nano),
				"human_principal_id": fmt.Sprintf("user-%d", i%17), "agent_id": fmt.Sprintf("agent-%d", i%5),
				"model_id": "stress-model", "action": "stress.write", "target_resource": fmt.Sprintf("res/%d", i),
				"outcome": []string{"allowed", "denied", "error"}[i%3],
				"metadata": map[string]any{"i": i, "nested": map[string]any{"z": 1, "a": []any{1.5, "x", nil}}},
				"delegation_chain": []any{map[string]any{"type": "human", "id": fmt.Sprintf("user-%d", i%17)}},
			}
			<-gate
			var rec ledger.Record
			var c int
			var err error
			// Transport errors (e.g. listen-backlog resets when 1000 sockets
			// connect at once) are retried with the SAME id: the server's
			// idempotency makes that safe, exactly as the SDK does.
			for attempt := 0; attempt < 8; attempt++ {
				c, err = call("POST", apis[(i+attempt)%len(apis)]+"/v1/events", key, sub, &rec)
				if err == nil {
					break
				}
				mu.Lock()
				transportRetries++
				mu.Unlock()
				time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
			}
			results[i] = result{c, rec, sub, err}
		}(i)
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	close(gate)
	wg.Wait()
	elapsed := time.Since(start)

	codes := map[int]int{}
	for _, r := range results {
		if r.err != nil {
			fail("transport error: %v", r.err)
		}
		codes[r.code]++
	}
	fmt.Printf("burst done in %v (%.0f req/s): status codes %v, client transport retries %d\n", elapsed.Round(time.Millisecond), float64(*n)/elapsed.Seconds(), codes, transportRetries)
	// A retried request whose first attempt was actually committed comes back
	// as 200 (idempotent replay) — still exactly one row.
	if codes[201]+codes[200] != *n {
		fail("expected %d x 201/200", *n)
	}

	// ---- 409 paths ------------------------------------------------------------
	stale := map[string]any{"agent_id": "a", "action": "x", "target_resource": "r", "outcome": "allowed",
		"previous_hash": strings.Repeat("f", 64)}
	if c, _ := call("POST", apis[0]+"/v1/events", key, stale, nil); c != 409 {
		fail("stale previous_hash: expected 409, got %d", c)
	}
	var head struct {
		Hash string
		Seq  int64
	}
	call("GET", apis[0]+"/v1/chain/head", key, nil, &head)
	badHash := map[string]any{"agent_id": "a", "action": "x", "target_resource": "r", "outcome": "allowed",
		"previous_hash": head.Hash, "hash": strings.Repeat("a", 64)}
	if c, _ := call("POST", apis[0]+"/v1/events", key, badHash, nil); c != 409 {
		fail("wrong claimed hash: expected 409, got %d", c)
	}
	// Optimistic mode done right: client computes the hash itself.
	id, ts := uuid(), time.Now().UTC()
	ev := canon.Event{ID: id, TenantID: tenantID, Timestamp: ts, AgentID: "optimistic-client", Action: "stress.optimistic",
		TargetResource: "res/opt", Outcome: "allowed", Metadata: json.RawMessage(`{"mode":"optimistic"}`)}
	h, _, _ := canon.HashEvent(head.Hash, ev)
	good := map[string]any{"id": id, "timestamp": canon.FormatTime(ts), "agent_id": "optimistic-client", "action": "stress.optimistic",
		"target_resource": "res/opt", "outcome": "allowed", "metadata": map[string]any{"mode": "optimistic"},
		"previous_hash": head.Hash, "hash": h}
	if c, _ := call("POST", apis[0]+"/v1/events", key, good, nil); c != 201 {
		fail("client-computed hash: expected 201, got %d", c)
	}
	fmt.Println("409 on stale head: ok | 409 on wrong hash: ok | client-computed hash accepted: ok")

	// ---- idempotent replay ----------------------------------------------------
	for i := 0; i < 10; i++ {
		var rec ledger.Record
		c, _ := call("POST", apis[(i+1)%len(apis)]+"/v1/events", key, results[i].sub, &rec)
		if c != 200 || rec.Hash != results[i].rec.Hash {
			fail("replay %d: expected 200 with original record, got %d", i, c)
		}
	}
	fmt.Println("idempotent replay of 10 events: ok (no duplicates)")

	// ---- pull the whole chain back and verify it ------------------------------
	var all []ledger.Record
	after := int64(0)
	for {
		var page struct{ Events []ledger.Record }
		call("GET", fmt.Sprintf("%s/v1/events?after_seq=%d&limit=1000", apis[0], after), key, nil, &page)
		if len(page.Events) == 0 {
			break
		}
		all = append(all, page.Events...)
		after = page.Events[len(page.Events)-1].Seq
	}
	var pk struct{ Keys []verify.PublicKey }
	call("GET", apis[0]+"/v1/tenants/"+tenantID+"/public-keys", "", nil, &pk)

	want := *n + 2 // + tenant.created admin event + optimistic event
	if len(all) != want {
		fail("expected %d rows, found %d", want, len(all))
	}
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.rec.ID] = true
	}
	found := 0
	for _, e := range all {
		if seen[e.ID] {
			found++
		}
	}
	if found != *n {
		fail("only %d of %d acknowledged events are in the ledger", found, *n)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	broken := 0
	for i := 1; i < len(all); i++ {
		if all[i].PreviousHash != all[i-1].Hash || all[i].Seq != all[i-1].Seq+1 {
			broken++
		}
	}
	rep := verify.Verify(verify.Bundle{Format: verify.BundleFormat, Tenant: verify.BundleTenant{ID: tenantID},
		PublicKeys: pk.Keys, Events: all}, verify.Options{})
	fmt.Printf("chain: %d rows, seq %d..%d, broken links: %d, verifier ok=%v (hashes recomputed: %d, signatures: %d)\n",
		len(all), all[0].Seq, all[len(all)-1].Seq, broken, rep.OK, rep.EventsChecked, rep.SignaturesVerified)
	if broken != 0 || !rep.OK {
		b, _ := json.MarshalIndent(rep.Issues, "", "  ")
		fail("chain verification failed:\n%s", b)
	}
	fmt.Println("PASS: zero broken links, zero gaps, every acknowledged event present exactly once")
	_ = context.Background
}
