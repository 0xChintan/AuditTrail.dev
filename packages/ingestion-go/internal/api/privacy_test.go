package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/export"
	"audittrail.dev/packages/ingestion-go/internal/v2client"
	"audittrail.dev/packages/ingestion-go/internal/verify2"
)

// Phase 5 gate: after crypto-shredding, the plaintext is unrecoverable
// while the chain, proofs and the offline verifier still pass.
func TestCryptoShredding(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	key, _, err := e.srv.Tenants.CreateAPIKey(ctx, e.tA.ID, "privacy", []string{"events:write", "events:read", "pii:read", "subjects:erase", "export:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := e.client(key)
	secret := "Jane Q. Patient, DOB 1980-02-29, MRN 7731-SECRET"
	var ids []string
	for i, subject := range []string{"patient-42", "patient-42", "patient-7"} {
		ev := &v2client.Event{Agent: map[string]any{"id": "prior-auth-agent"}, Action: "record.read", Resource: "ehr/patient", Outcome: "allowed",
			Payload: map[string]any{"i": i}, PII: map[string]any{"subject": subject, "fields": map[string]any{"name": secret + " #" + subject, "email": "jane@example.com"}}}
		r, err := c.PostOnce(ctx, "/v2/events", mustBody(t, ev))
		if err != nil || r.Status != 202 {
			t.Fatalf("submit with pii: %d %s", r.Status, r.Body)
		}
		ids = append(ids, ev.EventID)
	}
	read := func(id string) (int, map[string]any) {
		code, b := get(t, e, key, "/v2/events/"+id+"/pii")
		var m map[string]any
		json.Unmarshal(b, &m)
		return code, m
	}
	if code, m := read(ids[0]); code != 200 || !strings.Contains(m["fields"].(map[string]any)["name"].(string), "Jane") {
		t.Fatalf("decrypt before erasure: %d %v", code, m)
	}
	// The plaintext is nowhere in the database: only ciphertext is stored.
	err = db.InTenant(ctx, e.app, e.tA.ID, func(tx pgx.Tx) error {
		var n int
		tx.QueryRow(ctx, `SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND (agent_events::text ILIKE '%Jane%' OR agent_events::text ILIKE '%jane@example%')`, e.tA.ID).Scan(&n)
		if n != 0 {
			t.Errorf("plaintext PII found in %d stored rows", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Erase patient-42 (signed request, subjects:erase scope).
	req, _ := c.SignedRequest(ctx, "/v2/subjects/patient-42/erase", []byte(`{"reason":"GDPR Art. 17 request #1234"}`))
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("erase: %v %d", err, res.StatusCode)
	}
	var er map[string]any
	json.NewDecoder(res.Body).Decode(&er)
	res.Body.Close()
	if len(er["destroyed_keys"].([]any)) != 1 {
		t.Fatalf("erase response: %v", er)
	}
	for _, id := range ids[:2] {
		if code, _ := read(id); code != 410 {
			t.Fatalf("after erasure: want 410 for %s, got %d", id, code)
		}
	}
	if code, _ := read(ids[2]); code != 200 {
		t.Fatalf("other subject must still decrypt, got %d", code)
	}
	// The key material is gone from the database: nothing left to decrypt with.
	var live int
	db.InTenant(ctx, e.app, e.tA.ID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM subject_keys WHERE tenant_id=$1 AND subject='patient-42' AND wrapped_dek IS NOT NULL`, e.tA.ID).Scan(&live)
	})
	if live != 0 {
		t.Fatal("wrapped DEK still present after erasure")
	}
	// The erasure itself is in the ledger, without the subject's identifier.
	_, list := get(t, e, key, "/v1/events?action=audittrail.subject/erased")
	if !strings.Contains(string(list), "subject_sha256") || strings.Contains(string(list), "patient-42") {
		t.Fatalf("erasure event missing or leaks the subject: %s", list)
	}
	// Chain + hashes + signatures still verify offline after shredding.
	pubs, _ := e.srv.Tenants.PublicKeys(ctx, e.tA.ID)
	var b *verify2.Bundle
	db.InTenant(ctx, e.app, e.tA.ID, func(tx pgx.Tx) error {
		var err error
		b, err = export.BuildBundleV2(ctx, tx, e.tA, pubs, export.Range{})
		return err
	})
	if r := verify2.Verify(b, verify2.Options{}); !r.OK {
		t.Fatalf("verifier fails after shredding: %+v", r.Failures)
	}
	// New events for the erased subject get a fresh key and are readable.
	ev := &v2client.Event{Agent: map[string]any{"id": "a"}, Action: "record.read", Resource: "ehr", Outcome: "allowed",
		PII: map[string]any{"subject": "patient-42", "fields": map[string]any{"note": "new data after erasure"}}}
	if r, _ := c.PostOnce(ctx, "/v2/events", mustBody(t, ev)); r.Status != 202 {
		t.Fatalf("post-erasure submit: %d", r.Status)
	}
	if code, m := read(ev.EventID); code != 200 || m["fields"].(map[string]any)["note"] != "new data after erasure" {
		t.Fatalf("post-erasure read: %d %v", code, m)
	}
}
