package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/tlog"
	"audittrail.dev/packages/ingestion-go/internal/treehead"
	"audittrail.dev/packages/ingestion-go/internal/verify2"
	"audittrail.dev/packages/ingestion-go/internal/witness"
)

// TestTreeHeadCarriesWitnessCosignatures: the worker's configured witness
// names ("w1") need not match the witnesses' key names; the stored note must
// still carry a verifiable cosignature from every witness it reports.
func TestTreeHeadCarriesWitnessCosignatures(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for i := range 5 {
		if r, _, err := e.client(e.kA).Submit(ctx, mustBody(t, event(fmt.Sprintf("th.test.%d", i)))); err != nil || r.Status != 202 {
			t.Fatalf("submit: %v %d", err, r.Status)
		}
	}
	// The witnesses learn the tenant's log key from the API (as -tofu does).
	resolve := func(ctx context.Context, origin string) ([]witness.LogKey, error) {
		code, b := get(t, e, "", "/v2/tenants/"+e.tA.ID+"/log")
		var info struct{ Vkeys []string }
		if code != 200 || json.Unmarshal(b, &info) != nil {
			return nil, nil
		}
		var ks []witness.LogKey
		for _, v := range info.Vkeys {
			if n, _, pub, err := tlog.ParseVkey(v); err == nil && n == origin {
				ks = append(ks, witness.LogKey{Name: n, Pub: pub})
			}
		}
		return ks, nil
	}
	var cfgs []treehead.WitnessCfg
	var trusted []tlog.Witness
	for i := 1; i <= 3; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		c := tlog.Cosigner{Name: fmt.Sprintf("witness.test.local/w%d", i), Priv: priv}
		srv, err := witness.NewServer(c, resolve, "")
		if err != nil {
			t.Fatal(err)
		}
		hs := httptest.NewServer(srv)
		t.Cleanup(hs.Close)
		cfgs = append(cfgs, treehead.WitnessCfg{Name: fmt.Sprintf("w%d", i), URL: hs.URL})
		w, err := tlog.WitnessFromVkey(c.Vkey())
		if err != nil {
			t.Fatal(err)
		}
		trusted = append(trusted, w)
	}
	pool, err := db.Connect(ctx, config.WorkerDBURL(), 4)
	if err != nil {
		t.Skipf("worker role not reachable: %v", err)
	}
	t.Cleanup(pool.Close)
	master, err := keys.ParseMasterKey(os.Getenv("AUDITTRAIL_MASTER_KEY"))
	if err != nil {
		t.Skip(err)
	}
	wk := &treehead.Worker{Pool: pool, Master: master, Witnesses: cfgs, HTTP: http.DefaultClient}
	h, err := wk.Run(ctx, e.tA.ID)
	if err != nil || h == nil {
		t.Fatalf("tree head: %v", err)
	}
	if len(h.Witnesses) != 3 {
		t.Fatalf("worker reports %d witnesses, want 3: %v", len(h.Witnesses), h.Witnesses)
	}
	var stored string
	if err := pool.QueryRow(ctx, `SELECT note FROM tree_heads WHERE tenant_id=$1 AND tree_size=$2`, e.tA.ID, h.TreeSize).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, note := range []string{h.Note, stored} {
		n, err := tlog.ParseNote([]byte(note))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range trusted {
			if _, ok, err := tlog.VerifyCosig(n, w); !ok || err != nil {
				t.Errorf("no valid cosignature from %s in note (ok=%v err=%v):\n%s", w.Name, ok, err, note)
			}
		}
	}
}

// TestExportSurvivesDeletedRow: a row deleted behind the API's back (as a
// DB superuser) must not break the evidence export; the offline verifier
// names the missing seq instead.
func TestExportSurvivesDeletedRow(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for i := range 6 {
		if r, _, err := e.client(e.kA).Submit(ctx, mustBody(t, event(fmt.Sprintf("gap.test.%d", i)))); err != nil || r.Status != 202 {
			t.Fatalf("submit: %v %d", err, r.Status)
		}
	}
	pool, err := db.Connect(ctx, config.WorkerDBURL(), 4)
	if err != nil {
		t.Skipf("worker role not reachable: %v", err)
	}
	t.Cleanup(pool.Close)
	master, err := keys.ParseMasterKey(os.Getenv("AUDITTRAIL_MASTER_KEY"))
	if err != nil {
		t.Skip(err)
	}
	if _, err := (&treehead.Worker{Pool: pool, Master: master}).Run(ctx, e.tA.ID); err != nil {
		t.Fatal(err)
	}
	admin, err := db.Connect(ctx, config.AdminDBURL(), 2)
	if err != nil {
		t.Skipf("admin role not reachable: %v", err)
	}
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, `DELETE FROM agent_events WHERE tenant_id=$1 AND seq=3`, e.tA.ID); err != nil {
		t.Skipf("cannot tamper as admin: %v", err)
	}
	code, body := get(t, e, e.kA, "/v2/export")
	if code != 200 {
		t.Fatalf("export of a tampered log: HTTP %d %s", code, body)
	}
	var b verify2.Bundle
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatal(err)
	}
	rep := verify2.Verify(&b, verify2.Options{})
	if rep.OK || !slices.Contains(rep.TamperedSeqs, 3) {
		t.Fatalf("verifier must flag seq 3: ok=%v tampered=%v failures=%v", rep.OK, rep.TamperedSeqs, rep.Failures)
	}
}
