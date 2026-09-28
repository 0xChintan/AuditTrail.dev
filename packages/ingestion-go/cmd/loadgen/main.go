// Command audittrail-loadgen pre-signs requests for k6 (v2 task 7.2): k6
// cannot compute our Ed25519 request signatures, so each event gets a few
// independently signed attempts (same body, fresh nonce/timestamp) that the
// k6 script uses for retries. Signatures are valid for ±5 min: run k6 soon.
//
//	audittrail-loadgen -n 20000 -out /tmp/load.jsonl   (prints tenant id + key)
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/v2client"
)

func main() {
	config.LoadDotEnv()
	api := flag.String("api", "http://localhost:8080", "API base URL")
	n := flag.Int("n", 20000, "events")
	attempts := flag.Int("attempts", 3, "signed attempts per event")
	out := flag.String("out", "load.jsonl", "output file")
	flag.Parse()
	body, _ := json.Marshal(map[string]any{"name": "k6-load-" + time.Now().Format("150405"), "rate_limit_rps": 1000000, "rate_limit_burst": 1000000})
	req, _ := http.NewRequest("POST", *api+"/v1/admin/tenants", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("AUDITTRAIL_ADMIN_TOKEN"))
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 201 {
		fmt.Fprintln(os.Stderr, "create tenant failed", err)
		os.Exit(1)
	}
	var t struct {
		Tenant struct{ ID string } `json:"tenant"`
		APIKey string              `json:"api_key"`
	}
	json.NewDecoder(res.Body).Decode(&t)
	f, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	w := bufio.NewWriter(f)
	for i := 0; i < *n; i++ {
		ev := &v2client.Event{Agent: map[string]any{"id": fmt.Sprintf("agent-%d", i%11)}, Action: "load.write",
			Resource: fmt.Sprintf("res/%d", i), Outcome: []string{"allowed", "denied", "error"}[i%3],
			Principal: map[string]any{"id": fmt.Sprintf("user-%d", i%101), "type": "human"},
			Payload:   map[string]any{"i": i, "note": "k6 load test"}}
		b, _ := ev.Body()
		var tries []map[string]string
		for a := 0; a < *attempts; a++ {
			nb := make([]byte, 18)
			rand.Read(nb)
			nonce := base64.RawURLEncoding.EncodeToString(nb)
			ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
			tries = append(tries, map[string]string{"ts": ts, "nonce": nonce, "sig": contract.SignRequest(t.APIKey, "POST", "/v2/events", ts, nonce, b)})
		}
		line, _ := json.Marshal(map[string]any{"id": ev.EventID, "body": string(b), "tries": tries})
		w.Write(append(line, '\n'))
	}
	w.Flush()
	f.Close()
	fmt.Printf("%s %s\n", t.Tenant.ID, t.APIKey)
}
