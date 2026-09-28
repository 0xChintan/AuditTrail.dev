// Command audittrail-witness runs a C2SP tlog-witness.
//
//	audittrail-witness -name witness.example/w1 -key w1.seed -state w1.json -listen :7101 \
//	    -log "audittrail.dev/log/<tenant>+<id>+<b64>" ...        # pinned log keys
//	    -tofu http://localhost:8080                                # OR: dev-only trust-on-first-use
//
// Production witnesses are run by independent parties and configured with
// log keys out of band. -tofu fetches a log's key from the log itself the
// first time it is seen and pins it; use it only for local development.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/tlog"
	"audittrail.dev/packages/ingestion-go/internal/witness"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func loadSeed(path string) ed25519.PrivateKey {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			log.Fatal(err)
		}
		return ed25519.NewKeyFromSeed(seed)
	}
	if err != nil || len(b) != ed25519.SeedSize {
		log.Fatalf("bad key file %s", path)
	}
	return ed25519.NewKeyFromSeed(b)
}

func main() {
	name := flag.String("name", "witness.audittrail.local/w1", "witness name (key name in cosignatures)")
	keyPath := flag.String("key", "witness.seed", "Ed25519 seed file (created if missing)")
	statePath := flag.String("state", "witness-state.json", "state file")
	listen := flag.String("listen", ":7101", "listen address")
	tofu := flag.String("tofu", "", "DEV ONLY: AuditTrail API base URL to fetch unknown log keys from (trust on first use)")
	var logs multi
	flag.Var(&logs, "log", "trusted log vkey (repeatable)")
	flag.Parse()

	c := tlog.Cosigner{Name: *name, Priv: loadSeed(*keyPath)}
	pinned := map[string][]witness.LogKey{}
	for _, v := range logs {
		n, typ, pub, err := tlog.ParseVkey(v)
		if err != nil || typ != tlog.TypeEd25519 {
			log.Fatalf("bad -log vkey %q", v)
		}
		pinned[n] = append(pinned[n], witness.LogKey{Name: n, Pub: pub})
	}
	var mu sync.Mutex
	resolve := func(ctx context.Context, origin string) ([]witness.LogKey, error) {
		mu.Lock()
		defer mu.Unlock()
		if ks, ok := pinned[origin]; ok {
			return ks, nil
		}
		tenant, ok := strings.CutPrefix(origin, "audittrail.dev/log/")
		if *tofu == "" || !ok {
			return nil, nil
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(*tofu, "/")+"/v2/tenants/"+tenant+"/log", nil)
		res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		var body struct {
			Origin string   `json:"origin"`
			Vkeys  []string `json:"vkeys"`
		}
		if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&body) != nil || body.Origin != origin {
			return nil, nil
		}
		for _, v := range body.Vkeys {
			if n, typ, pub, err := tlog.ParseVkey(v); err == nil && typ == tlog.TypeEd25519 && n == origin {
				pinned[origin] = append(pinned[origin], witness.LogKey{Name: n, Pub: pub})
			}
		}
		log.Printf("TOFU: pinned %d key(s) for %s", len(pinned[origin]), origin)
		return pinned[origin], nil
	}
	srv, err := witness.NewServer(c, resolve, *statePath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(c.Vkey())
	log.Printf("witness %s listening on %s", *name, *listen)
	hs := &http.Server{Addr: *listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(hs.ListenAndServe())
}
