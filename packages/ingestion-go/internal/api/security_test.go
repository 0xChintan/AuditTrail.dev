package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"audittrail.dev/packages/ingestion-go/internal/api"
	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/tenant"
	"audittrail.dev/packages/ingestion-go/internal/v2client"
)

type env struct {
	srv    *api.Server
	http   *httptest.Server
	app    *pgxpool.Pool
	admin  string
	tA, tB tenant.Tenant
	kA, kB string
}

func setup(t *testing.T) *env {
	t.Helper()
	config.LoadDotEnv()
	ctx := context.Background()
	app, err := db.Connect(ctx, config.AppDBURL(), 20)
	if err != nil {
		t.Skipf("database not reachable: %v", err)
	}
	control, err := db.Connect(ctx, config.ControlDBURL(), 5)
	if err != nil {
		t.Skipf("control role not reachable: %v", err)
	}
	master, err := keys.ParseMasterKey(os.Getenv("AUDITTRAIL_MASTER_KEY"))
	if err != nil {
		t.Skip(err)
	}
	pepper, err := keys.ParsePepper(os.Getenv("AUDITTRAIL_KEY_PEPPER"))
	if err != nil {
		t.Skip(err)
	}
	e := &env{app: app, admin: "test-admin-" + fmt.Sprint(time.Now().UnixNano())}
	e.srv = api.New(app, control, master, pepper, e.admin, nil, nil)
	api.RegisterExtensions(e.srv)
	e.http = httptest.NewServer(e.srv)
	t.Cleanup(func() { e.http.Close(); app.Close(); control.Close() })
	mk := func(name string) (tenant.Tenant, string) {
		tn, key, _, _, err := e.srv.Tenants.Create(ctx, tenant.CreateOptions{Name: name, RateLimitRPS: 10000, RateLimitBurst: 10000})
		if err != nil {
			t.Fatal(err)
		}
		return tn, key
	}
	e.tA, e.kA = mk("sec-test-A")
	e.tB, e.kB = mk("sec-test-B")
	return e
}

func (e *env) client(key string) *v2client.Client {
	return &v2client.Client{BaseURL: e.http.URL, APIKey: key}
}

func event(action string) *v2client.Event {
	return &v2client.Event{Agent: map[string]any{"id": "sec-test-agent"}, Action: action, Resource: "res/1", Outcome: "allowed",
		Principal: map[string]any{"id": "alice", "type": "human"}, Payload: map[string]any{"n": 1}}
}

func mustBody(t *testing.T, ev *v2client.Event) []byte {
	b, err := ev.Body()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func get(t *testing.T, e *env, key, path string) (int, []byte) {
	req, _ := http.NewRequest("GET", e.http.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

func TestIngestV2IdempotencyAndHash(t *testing.T) {
	e := setup(t)
	c := e.client(e.kA)
	ctx := context.Background()
	ev := event("test.ingest")
	body := mustBody(t, ev)
	r1, err := c.PostOnce(ctx, "/v2/events", body)
	if err != nil || r1.Status != 202 {
		t.Fatalf("first submit: %d %s %v", r1.Status, r1.Body, err)
	}
	r2, _ := c.PostOnce(ctx, "/v2/events", body)
	if r2.Status != 200 || r2.Receipt["hash"] != r1.Receipt["hash"] {
		t.Fatalf("replay: %d %s", r2.Status, r2.Body)
	}
	ev.Outcome = "denied"
	r3, _ := c.PostOnce(ctx, "/v2/events", mustBody(t, ev))
	if r3.Status != 409 {
		t.Fatalf("same id, different body: want 409, got %d", r3.Status)
	}
	code, b := get(t, e, e.kA, "/v1/events/"+ev.EventID)
	if code != 200 {
		t.Fatalf("get: %d", code)
	}
	var rec ledger.Record
	json.Unmarshal(b, &rec)
	if h, err := rec.RecomputeHash(); err != nil || h != rec.Hash || rec.SpecVersion != 2 || !rec.PayloadIntact() {
		t.Fatalf("stored v2 row does not recompute: %v %s %s", err, h, rec.Hash)
	}
}

// S1: bad signatures are rejected.
func TestS1BadSignature(t *testing.T) {
	e := setup(t)
	c := e.client(e.kA)
	ctx := context.Background()
	body := mustBody(t, event("s1"))
	cases := map[string]func(*http.Request){
		"flipped signature": func(r *http.Request) {
			sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-AT-Signature"))
			sig[0] ^= 1
			r.Header.Set("X-AT-Signature", base64.StdEncoding.EncodeToString(sig))
		},
		"signed by another tenant's key": func(r *http.Request) {
			o, _ := e.client(e.kB).SignedRequest(ctx, "/v2/events", body)
			r.Header.Set("X-AT-Signature", o.Header.Get("X-AT-Signature"))
			r.Header.Set("X-AT-Timestamp", o.Header.Get("X-AT-Timestamp"))
			r.Header.Set("X-AT-Nonce", o.Header.Get("X-AT-Nonce"))
		},
		"missing signature": func(r *http.Request) { r.Header.Del("X-AT-Signature") },
		"body swapped after signing": func(r *http.Request) {
			other := mustBody(t, event("s1-other"))
			r.Body = io.NopCloser(strings.NewReader(string(other)))
			r.ContentLength = int64(len(other))
		},
		"path changed after signing": func(r *http.Request) { r.URL.Path = "/v2/events/" },
		"garbage key": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer at2_000000000000_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		},
	}
	for name, mutate := range cases {
		req, _ := c.SignedRequest(ctx, "/v2/events", body)
		mutate(req)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if name == "path changed after signing" && res.StatusCode == 404 {
			continue // no such route: also rejected
		}
		if res.StatusCode != 401 {
			t.Errorf("%s: want 401, got %d %s", name, res.StatusCode, b)
		}
		if strings.Contains(string(b), "signature") || strings.Contains(string(b), "nonce") {
			t.Errorf("%s: error body leaks the reason: %s", name, b)
		}
	}
}

// S2: revoked keys stop working immediately.
func TestS2RevokedKey(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	full, k, err := e.srv.Tenants.CreateAPIKey(ctx, e.tA.ID, "to-revoke", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := e.client(full)
	if r, _ := c.PostOnce(ctx, "/v2/events", mustBody(t, event("s2-before"))); r.Status != 202 {
		t.Fatalf("before revoke: %d", r.Status)
	}
	if err := e.srv.Tenants.RevokeAPIKey(ctx, e.tA.ID, k.ID); err != nil {
		t.Fatal(err)
	}
	if r, _ := c.PostOnce(ctx, "/v2/events", mustBody(t, event("s2-after"))); r.Status != 401 {
		t.Fatalf("after revoke: want 401, got %d", r.Status)
	}
	if code, _ := get(t, e, full, "/v1/events"); code != 401 {
		t.Fatalf("revoked key read: want 401, got %d", code)
	}
}

// S3: expired keys and out-of-window timestamps are rejected.
func TestS3ExpiredKeyAndSkew(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	full, _, err := e.srv.Tenants.CreateAPIKey(ctx, e.tA.ID, "expired", nil, &past)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := e.client(full).PostOnce(ctx, "/v2/events", mustBody(t, event("s3"))); r.Status != 401 {
		t.Fatalf("expired key: want 401, got %d", r.Status)
	}
	for _, skew := range []time.Duration{6 * time.Minute, -6 * time.Minute} {
		c := e.client(e.kA)
		c.Now = func() time.Time { return time.Now().Add(skew) }
		if r, _ := c.PostOnce(ctx, "/v2/events", mustBody(t, event("s3-skew"))); r.Status != 401 {
			t.Fatalf("skew %v: want 401, got %d", skew, r.Status)
		}
	}
	c := e.client(e.kA)
	c.Now = func() time.Time { return time.Now().Add(4 * time.Minute) }
	if r, _ := c.PostOnce(ctx, "/v2/events", mustBody(t, event("s3-in-window"))); r.Status != 202 {
		t.Fatalf("4 min skew should be accepted, got %d", r.Status)
	}
}

// S4: an exact replay of a signed request (same nonce) is rejected, even
// though the event itself would be an idempotent no-op.
func TestS4NonceReplay(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	body := mustBody(t, event("s4"))
	req, _ := e.client(e.kA).SignedRequest(ctx, "/v2/events", body)
	send := func() int {
		r2, _ := http.NewRequest("POST", req.URL.String(), strings.NewReader(string(body)))
		r2.Header = req.Header.Clone()
		res, err := http.DefaultClient.Do(r2)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if c := send(); c != 202 {
		t.Fatalf("first: %d", c)
	}
	if c := send(); c != 401 {
		t.Fatalf("replayed nonce: want 401, got %d", c)
	}
}

func TestScopes(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	ro, _, err := e.srv.Tenants.CreateAPIKey(ctx, e.tA.ID, "read-only", []string{"events:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := e.client(ro).PostOnce(ctx, "/v2/events", mustBody(t, event("scope"))); r.Status != 403 {
		t.Fatalf("read-only key write: want 403, got %d", r.Status)
	}
	if code, _ := get(t, e, ro, "/v1/export?format=bundle"); code != 403 {
		t.Fatalf("read-only key export: want 403, got %d", code)
	}
	if code, _ := get(t, e, ro, "/v1/events"); code != 200 {
		t.Fatalf("read-only key read: want 200, got %d", code)
	}
}

// S5: tenant isolation, both through the API (IDOR) and at the database
// (RLS) even if application code forgot a WHERE clause.
func TestS5TenantIsolation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	evB := event("s5-b-secret")
	if r, _ := e.client(e.kB).PostOnce(ctx, "/v2/events", mustBody(t, evB)); r.Status != 202 {
		t.Fatalf("B submit: %d", r.Status)
	}
	// API: A cannot fetch B's event by id, nor see it in lists / exports.
	if code, _ := get(t, e, e.kA, "/v1/events/"+evB.EventID); code != 404 {
		t.Fatalf("IDOR: tenant A fetched tenant B's event (status %d)", code)
	}
	_, list := get(t, e, e.kA, "/v1/events?limit=1000")
	if strings.Contains(string(list), evB.EventID) || strings.Contains(string(list), "s5-b-secret") {
		t.Fatal("tenant A's list leaks tenant B's event")
	}
	_, bundle := get(t, e, e.kA, "/v1/export?format=bundle")
	if strings.Contains(string(bundle), evB.EventID) {
		t.Fatal("tenant A's export leaks tenant B's event")
	}
	// DB: as the app role, scoped to A, deliberately *without* tenant filters.
	err := db.InTenant(ctx, e.app, e.tA.ID, func(tx pgx.Tx) error {
		var n int
		tx.QueryRow(ctx, `SELECT count(*) FROM agent_events WHERE tenant_id=$1`, e.tB.ID).Scan(&n)
		if n != 0 {
			return fmt.Errorf("RLS: saw %d of tenant B's rows", n)
		}
		tx.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n)
		if n != 1 {
			return fmt.Errorf("RLS: saw %d tenants, want only A", n)
		}
		tx.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE tenant_id <> $1`, e.tA.ID).Scan(&n)
		if n != 0 {
			return fmt.Errorf("RLS: saw other tenants' API keys")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Writing a row for B while scoped to A violates the RLS WITH CHECK.
	err = db.InTenant(ctx, e.app, e.tA.ID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE chain_state SET last_seq = last_seq WHERE tenant_id=$1`, e.tB.ID)
		if err != nil {
			return err
		}
		ct, _ := tx.Exec(ctx, `UPDATE chain_state SET last_seq = last_seq WHERE tenant_id=$1`, e.tB.ID)
		if ct.RowsAffected() != 0 {
			return fmt.Errorf("RLS: updated tenant B's chain head")
		}
		_, err = tx.Exec(ctx, `INSERT INTO request_nonces VALUES (gen_random_uuid(), 'x', now())`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = db.InTenant(ctx, e.app, e.tA.ID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO chain_state (tenant_id) VALUES ($1)`, e.tB.ID)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("RLS WITH CHECK: want violation, got %v", err)
	}
	// No tenant set at all: fail closed.
	var n int
	e.app.QueryRow(ctx, `SELECT count(*) FROM agent_events`).Scan(&n)
	if n != 0 {
		t.Fatalf("RLS: %d rows visible without app.tenant_id", n)
	}
	// And the app role still cannot UPDATE/DELETE the ledger at all.
	err = db.InTenant(ctx, e.app, e.tA.ID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agent_events SET outcome='allowed'`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("UPDATE on ledger: want permission denied, got %v", err)
	}
}

// S6: every hostile vector gets its exact status + code over HTTP, never 500.
func TestS6HostileVectorsOverHTTP(t *testing.T) {
	e := setup(t)
	raw, err := os.ReadFile("../../../../schemas/v2/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Invalid []struct {
			Name    string `json:"name"`
			Body    string `json:"body"`
			BodyB64 string `json:"body_b64"`
			BodyGen string `json:"body_gen"`
			Status  int    `json:"status"`
			Code    string `json:"code"`
		} `json:"invalid_envelopes"`
	}
	json.Unmarshal(raw, &vf)
	c := e.client(e.kA)
	ctx := context.Background()
	for _, v := range vf.Invalid {
		body := []byte(v.Body)
		if v.BodyB64 != "" {
			body, _ = base64.StdEncoding.DecodeString(v.BodyB64)
		}
		if strings.HasPrefix(v.BodyGen, "oversize:") {
			var n int
			fmt.Sscanf(strings.TrimPrefix(v.BodyGen, "oversize:"), "%d", &n)
			body = []byte(`{"pad":"` + strings.Repeat("a", n) + `"}`)
		}
		r, err := c.PostOnce(ctx, "/v2/events", body)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		var eb struct {
			Error struct{ Code string } `json:"error"`
		}
		json.Unmarshal(r.Body, &eb)
		if r.Status != v.Status || eb.Error.Code != v.Code {
			t.Errorf("%s: got %d %s, want %d %s", v.Name, r.Status, eb.Error.Code, v.Status, v.Code)
		}
	}
	t.Logf("%d hostile vectors rejected with the exact status/code", len(vf.Invalid))
}

// Every valid vector survives the trip through the API and Postgres jsonb:
// the stored row re-canonicalizes to the same record hash and payload hash.
func TestValidVectorsRoundTripThroughPostgres(t *testing.T) {
	e := setup(t)
	raw, err := os.ReadFile("../../../../schemas/v2/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Valid []struct {
			Name string `json:"name"`
			Body string `json:"body"`
		} `json:"valid_envelopes"`
	}
	json.Unmarshal(raw, &vf)
	c := e.client(e.kA)
	ctx := context.Background()
	n := 0
	for _, v := range vf.Valid {
		if strings.Contains(v.Name, "pii") {
			continue // PII needs the phase-5 encrypter
		}
		// Fresh event_id per run (vectors use fixed ids).
		var m map[string]json.RawMessage
		json.Unmarshal([]byte(v.Body), &m)
		id := keys.NewUUIDv7(time.Now())
		m["event_id"] = json.RawMessage(`"` + id + `"`)
		body, _ := json.Marshal(m)
		r, err := c.PostOnce(ctx, "/v2/events", body)
		if err != nil || r.Status != 202 {
			t.Fatalf("%s: %d %s %v", v.Name, r.Status, r.Body, err)
		}
		code, b := get(t, e, e.kA, "/v1/events/"+id)
		if code != 200 {
			t.Fatalf("%s: read back %d", v.Name, code)
		}
		var rec ledger.Record
		json.Unmarshal(b, &rec)
		if h, err := rec.RecomputeHash(); err != nil || h != rec.Hash {
			t.Fatalf("%s: stored row does not recompute (%v)", v.Name, err)
		}
		if !rec.PayloadIntact() {
			t.Fatalf("%s: stored payload no longer matches payload_hash", v.Name)
		}
		n++
	}
	t.Logf("%d valid vectors round-tripped through Postgres jsonb and re-verified", n)
}
