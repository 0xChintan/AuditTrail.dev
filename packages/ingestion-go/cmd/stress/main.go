// Command audittrail-stress (v2 task 1.3 gate): N concurrent writers for ONE
// tenant through signed POST /v2/events. Optionally spawns the API itself
// and kill -9s it mid-run, restarting it while clients keep retrying the same
// bodies. Afterwards it proves: zero gaps, zero duplicates, every link and
// hash valid, and every acknowledged event present exactly once.
//
//	audittrail-stress -n 10000 -c 256                       # against a running API
//	audittrail-stress -n 10000 -c 256 -spawn ./bin/api -kill-at 0.4
//	audittrail-stress -n 10000 -spawn ./bin/api -batch 1    # group commit off (baseline)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/v2client"
)

func fail(format string, a ...any) {
	fmt.Printf("FAIL: "+format+"\n", a...)
	os.Exit(1)
}

type apiProc struct {
	bin, addr string
	env       []string
	cmd       *exec.Cmd
}

func (p *apiProc) start() {
	p.cmd = exec.Command(p.bin) // #nosec G204 -- operator-supplied binary path for a test harness
	p.cmd.Env = append(os.Environ(), append(p.env, "LISTEN_ADDR="+p.addr)...)
	p.cmd.Stdout, p.cmd.Stderr = io.Discard, io.Discard
	if err := p.cmd.Start(); err != nil {
		fail("start api: %v", err)
	}
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", "127.0.0.1"+p.addr, 100*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	fail("api did not come up")
}

func (p *apiProc) kill9() {
	_ = p.cmd.Process.Signal(syscall.SIGKILL)
	_, _ = p.cmd.Process.Wait()
}

func main() {
	config.LoadDotEnv()
	api := flag.String("api", "http://127.0.0.1:18090", "API base URL")
	n := flag.Int("n", 10000, "writers (one event each)")
	conc := flag.Int("c", 256, "max in-flight HTTP requests")
	spawn := flag.String("spawn", "", "path to the api binary to run (and optionally kill)")
	killAt := flag.Float64("kill-at", 0, "fraction of acks after which to kill -9 the spawned API (0 = never)")
	batch := flag.Int("batch", 256, "SEQUENCER_MAX_BATCH for the spawned API")
	flag.Parse()

	var proc *apiProc
	if *spawn != "" {
		addr := (*api)[strings.LastIndex(*api, ":"):]
		proc = &apiProc{bin: *spawn, addr: addr, env: []string{fmt.Sprintf("SEQUENCER_MAX_BATCH=%d", *batch)}}
		proc.start()
		defer proc.kill9()
	}
	admin := os.Getenv("AUDITTRAIL_ADMIN_TOKEN")
	body, _ := json.Marshal(map[string]any{"name": "stress-v2-" + time.Now().Format("150405"), "rate_limit_rps": 1000000, "rate_limit_burst": 1000000})
	req, _ := http.NewRequest("POST", *api+"/v1/admin/tenants", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+admin)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 201 {
		fail("create tenant: %v", err)
	}
	var created struct {
		Tenant struct{ ID string } `json:"tenant"`
		APIKey string              `json:"api_key"`
	}
	json.NewDecoder(res.Body).Decode(&created)
	res.Body.Close()

	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxConnsPerHost: *conc, MaxIdleConnsPerHost: *conc}}
	cl := &v2client.Client{BaseURL: *api, APIKey: created.APIKey, HTTP: hc}
	fmt.Printf("tenant %s: %d writers, %d in flight, server batch %d, kill-at %.0f%%\n", created.Tenant.ID, *n, *conc, *batch, *killAt*100)

	bodies := make([][]byte, *n)
	ids := make([]string, *n)
	for i := range bodies {
		ev := &v2client.Event{Agent: map[string]any{"id": fmt.Sprintf("agent-%d", i%7)}, Action: "stress.write",
			Resource: fmt.Sprintf("res/%d", i), Outcome: []string{"allowed", "denied", "error"}[i%3],
			Principal: map[string]any{"id": fmt.Sprintf("user-%d", i%13), "type": "human"},
			Payload:   map[string]any{"i": i, "blob": strings.Repeat("x", i%64)}}
		b, err := ev.Body()
		if err != nil {
			fail("build: %v", err)
		}
		bodies[i], ids[i] = b, ev.EventID
	}

	var acked, replays, retries, killed atomic.Int64
	var codeMu sync.Mutex
	status := map[int]int64{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, *conc)
	var killOnce sync.Once
	restarted := make(chan struct{})
	start := time.Now()
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r, rt, err := cl.Submit(context.Background(), bodies[i])
			retries.Add(int64(rt))
			if err != nil {
				fail("writer %d: %v", i, err)
			}
			codeMu.Lock()
			status[r.Status]++
			codeMu.Unlock()
			if r.Status != 202 && r.Status != 200 {
				fail("writer %d: HTTP %d %s", i, r.Status, r.Body)
			}
			if r.Status == 200 {
				replays.Add(1)
			}
			if a := acked.Add(1); proc != nil && *killAt > 0 && float64(a) >= *killAt*float64(*n) {
				killOnce.Do(func() {
					go func() {
						proc.kill9()
						killed.Add(1)
						fmt.Printf("  kill -9 after %d acks (mid-batch, requests in flight); restarting…\n", a)
						time.Sleep(300 * time.Millisecond)
						proc.start()
						close(restarted)
					}()
				})
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	if killed.Load() > 0 {
		<-restarted
	}
	fmt.Printf("done in %v → %.0f events/s; statuses %v; client retries %d; replays %d; kills %d\n",
		elapsed.Round(time.Millisecond), float64(*n)/elapsed.Seconds(), status, retries.Load(), replays.Load(), killed.Load())

	// ---- verify the whole chain --------------------------------------------------------
	var all []ledger.Record
	after := int64(0)
	for {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/events?after_seq=%d&limit=1000", *api, after), nil)
		req.Header.Set("Authorization", "Bearer "+created.APIKey)
		res, err := hc.Do(req)
		if err != nil {
			fail("read back: %v", err)
		}
		var page struct{ Events []ledger.Record }
		json.NewDecoder(res.Body).Decode(&page)
		res.Body.Close()
		if len(page.Events) == 0 {
			break
		}
		all = append(all, page.Events...)
		after = page.Events[len(page.Events)-1].Seq
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	want := *n + 1 // + tenant.created
	if len(all) != want {
		fail("expected %d rows, found %d", want, len(all))
	}
	seen := map[string]int{}
	prev := contract.Genesis
	for i, e := range all {
		if e.Seq != int64(i+1) {
			fail("gap: row %d has seq %d", i, e.Seq)
		}
		if e.PreviousHash != prev {
			fail("broken link at seq %d", e.Seq)
		}
		if h, err := e.RecomputeHash(); err != nil || h != e.Hash {
			fail("hash mismatch at seq %d: %v", e.Seq, err)
		}
		if !e.PayloadIntact() {
			fail("payload mismatch at seq %d", e.Seq)
		}
		seen[e.ID]++
		prev = e.Hash
	}
	for _, id := range ids {
		if seen[id] != 1 {
			fail("event %s present %d times", id, seen[id])
		}
	}
	fmt.Printf("PASS: %d rows, seq 1..%d, 0 gaps, 0 duplicates, every hash/link/payload valid, all %d acknowledged events present exactly once\n",
		len(all), len(all), *n)
}
