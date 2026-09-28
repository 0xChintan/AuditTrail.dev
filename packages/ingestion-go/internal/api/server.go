// Package api is the HTTP front door of the ingestion service.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/pii"
	"audittrail.dev/packages/ingestion-go/internal/ratelimit"
	"audittrail.dev/packages/ingestion-go/internal/sequencer"
	"audittrail.dev/packages/ingestion-go/internal/tenant"
)

const maxAdminBody = 64 << 10

type Server struct {
	PII         *pii.Encrypter
	Pool        *pgxpool.Pool // app role (RLS)
	Control     *pgxpool.Pool // control-plane role
	Seq         *sequencer.Sequencer
	Tenants     *tenant.Store
	AdminToken  string
	CORSOrigins []string
	Log         *slog.Logger
	Now         func() time.Time

	// Rate limits: shared across instances through Postgres (default), or
	// per instance when Rate is nil (RATE_LIMIT_MODE=local).
	Rate     *ratelimit.Shared
	limMu    sync.Mutex
	limiters map[string]*rate.Limiter

	mux *http.ServeMux
}

func New(pool, control *pgxpool.Pool, master *keys.MasterKey, pepper keys.Pepper, adminToken string, cors []string, log *slog.Logger) *Server {
	s := &Server{
		PII:         &pii.Encrypter{KEK: master},
		Pool:        pool,
		Control:     control,
		Seq:         sequencer.New(pool, master),
		Tenants:     &tenant.Store{Pool: pool, Control: control, Master: master, Pepper: pepper},
		AdminToken:  adminToken,
		CORSOrigins: cors,
		Log:         log,
		Now:         time.Now,
		limiters:    map[string]*rate.Limiter{},
		mux:         http.NewServeMux(),
	}
	s.Seq.PII = s.PII
	if control != nil {
		s.Rate = &ratelimit.Shared{Pool: control, Log: log}
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Pool.Ping(r.Context()); err != nil {
			writeErr(w, 503, "db_unavailable", "database unavailable")
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	// Public: verification must not require an account with us.
	m.HandleFunc("GET /v1/tenants/{id}/public-keys", s.handlePublicKeys)

	// v2 ingest: signed requests only.
	m.Handle("POST /v2/events", s.auth("events:write", true, s.handleIngest))
	m.Handle("POST /v2/subjects/{subject}/erase", s.auth("subjects:erase", true, s.handleErase))
	m.Handle("GET /v2/events/{id}/pii", s.auth("pii:read", false, s.handlePIIRead))
	// v1 ingest is retired: the server is the only sequencer.
	m.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, 410, "gone", "POST /v1/events is retired; use POST /v2/events (spec_version 2, signed requests)")
	})

	m.Handle("GET /v1/events", s.auth("events:read", false, s.handleListEvents))
	m.Handle("GET /v1/events/{id}", s.auth("events:read", false, s.handleGetEvent))
	m.Handle("GET /v1/chain/head", s.auth("events:read", false, s.handleHead))
	m.Handle("GET /v1/stats", s.auth("events:read", false, s.handleStats))
	m.Handle("GET /v1/me", s.auth("", false, s.handleMe))

	m.Handle("GET /v1/admin/tenants", s.adminAuth(http.HandlerFunc(s.handleListTenants)))
	m.Handle("POST /v1/admin/tenants", s.adminAuth(http.HandlerFunc(s.handleCreateTenant)))
	m.Handle("GET /v1/admin/tenants/{id}", s.adminAuth(http.HandlerFunc(s.handleGetTenant)))
	m.Handle("PATCH /v1/admin/tenants/{id}", s.adminAuth(http.HandlerFunc(s.handleUpdateTenant)))
	m.Handle("GET /v1/admin/tenants/{id}/api-keys", s.adminAuth(http.HandlerFunc(s.handleListAPIKeys)))
	m.Handle("POST /v1/admin/tenants/{id}/api-keys", s.adminAuth(http.HandlerFunc(s.handleCreateAPIKey)))
	m.Handle("DELETE /v1/admin/tenants/{id}/api-keys/{keyId}", s.adminAuth(http.HandlerFunc(s.handleRevokeAPIKey)))
	m.Handle("POST /v1/admin/tenants/{id}/signing-keys/rotate", s.adminAuth(http.HandlerFunc(s.handleRotateKey)))
}

// Handle lets later phases register extra routes.
func (s *Server) Handle(pattern string, h http.Handler) { s.mux.Handle(pattern, h) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	if origin := r.Header.Get("Origin"); origin != "" && s.corsAllowed(origin) {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Vary", "Origin")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-AuditTrail-Tenant, X-AuditTrail-Operator, X-AT-Timestamp, X-AT-Nonce, X-AT-Signature")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
	}
	defer func() {
		if rec := recover(); rec != nil {
			if s.Log != nil {
				s.Log.Error("panic", "err", rec, "path", r.URL.Path)
			}
			writeErr(w, 500, "internal", "internal error")
		}
	}()
	s.mux.ServeHTTP(w, r)
}

func (s *Server) corsAllowed(origin string) bool {
	for _, o := range s.CORSOrigins {
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}

// ---- auth -----------------------------------------------------------------------

// Auth is the resolved caller of a tenant route.
type Auth struct {
	Tenant tenant.Tenant
	Cred   *tenant.Credential // nil for admin-as-tenant
	Body   []byte             // signed routes: the verified body
}

type authed func(w http.ResponseWriter, r *http.Request, a *Auth)

func bearer(r *http.Request) string {
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func (s *Server) isAdmin(r *http.Request) bool {
	return s.AdminToken != "" && keys.HashesEqual(bearer(r), s.AdminToken)
}

func (s *Server) unauthorized(w http.ResponseWriter, why string) {
	// One generic answer for every failure; the reason is only logged.
	if s.Log != nil {
		s.Log.Info("auth rejected", "reason", why)
	}
	writeErr(w, 401, "unauthorized", "authentication failed")
}

// auth resolves the tenant from an API key (or the admin token + tenant
// header for read routes), checks the scope, and for signed routes verifies
// the request signature and burns its nonce.
func (s *Server) auth(scope string, signed bool, next authed) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		a := &Auth{}
		var tenantID string
		if s.isAdmin(r) && !signed {
			if op := operatorFrom(r); op != "" {
				ctx = context.WithValue(ctx, operatorKey{}, op)
				r = r.WithContext(ctx)
			}
			tenantID = r.Header.Get("X-AuditTrail-Tenant")
			if !isUUID(tenantID) {
				writeErr(w, 400, "tenant_required", "admin requests to tenant routes need X-AuditTrail-Tenant")
				return
			}
		} else {
			cred, err := s.Tenants.Authenticate(ctx, bearer(r))
			if err != nil {
				s.unauthorized(w, "bad_or_revoked_or_expired_key")
				return
			}
			if scope != "" && !cred.Has(scope) {
				writeErr(w, 403, "forbidden", "API key lacks scope "+scope)
				return
			}
			a.Cred, tenantID = &cred, cred.TenantID
		}
		if signed {
			if a.Cred == nil || a.Cred.Version != 2 || a.Cred.SignPub == nil {
				s.unauthorized(w, "unsigned_credential")
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, contract.MaxBodyBytes+1))
			if err != nil {
				writeErr(w, 400, "bad_request", "could not read body")
				return
			}
			if len(body) > contract.MaxBodyBytes {
				writeErr(w, 413, "body_too_large", fmt.Sprintf("body exceeds %d bytes", contract.MaxBodyBytes))
				return
			}
			ts, nonce, sig := r.Header.Get("X-AT-Timestamp"), r.Header.Get("X-AT-Nonce"), r.Header.Get("X-AT-Signature")
			if ok, why := contract.VerifyRequest(a.Cred.SignPub, r.Method, r.URL.EscapedPath(), ts, nonce, sig, body, s.Now()); !ok {
				s.unauthorized(w, why)
				return
			}
			ct, err := s.Pool.Exec(ctx, `INSERT INTO request_nonces (key_id, nonce, expires_at)
				VALUES ($1, $2, NOW() + interval '15 minutes') ON CONFLICT DO NOTHING`, a.Cred.KeyID, nonce)
			if err != nil {
				s.internal(w, err)
				return
			}
			if ct.RowsAffected() == 0 {
				s.unauthorized(w, "nonce_replayed")
				return
			}
			a.Body = body
		}
		err := db.InTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
			t, err := tenant.GetTx(ctx, tx, tenantID)
			if err != nil {
				return err
			}
			a.Tenant = t
			if a.Cred != nil {
				tenant.Touch(ctx, tx, a.Cred.KeyID)
			}
			return nil
		})
		if err != nil {
			s.unauthorized(w, "tenant_not_found")
			return
		}
		next(w, r, a)
	})
}

func (s *Server) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isAdmin(r) {
			s.unauthorized(w, "admin_token")
			return
		}
		if op := operatorFrom(r); op != "" {
			r = r.WithContext(context.WithValue(r.Context(), operatorKey{}, op))
		}
		next.ServeHTTP(w, r)
	})
}

// tx runs fn in a transaction scoped to the caller's tenant (RLS).
func (s *Server) tx(r *http.Request, a *Auth, fn func(pgx.Tx) error) error {
	return db.InTenant(r.Context(), s.Pool, a.Tenant.ID, fn)
}

// StartNonceJanitor deletes expired nonces periodically.
func (s *Server) StartNonceJanitor(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_, _ = s.Pool.Exec(ctx, `DELETE FROM request_nonces WHERE expires_at < NOW()`)
			}
		}
	}()
}

// ---- rate limiting: per-tenant token bucket --------------------------------------

func (s *Server) limited(w http.ResponseWriter, r *http.Request, t tenant.Tenant) bool {
	if s.Rate != nil {
		ok, wait := s.Rate.Allow(r.Context(), t.ID, t.RateLimitRPS, t.RateLimitBurst)
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			writeErr(w, 429, "rate_limited", "tenant rate limit exceeded")
		}
		return !ok
	}
	s.limMu.Lock()
	l, ok := s.limiters[t.ID]
	if !ok {
		l = rate.NewLimiter(rate.Limit(t.RateLimitRPS), t.RateLimitBurst)
		s.limiters[t.ID] = l
	} else if l.Limit() != rate.Limit(t.RateLimitRPS) || l.Burst() != t.RateLimitBurst {
		l.SetLimit(rate.Limit(t.RateLimitRPS))
		l.SetBurst(t.RateLimitBurst)
	}
	s.limMu.Unlock()
	res := l.Reserve()
	if d := res.Delay(); d > 0 {
		res.Cancel()
		w.Header().Set("Retry-After", strconv.Itoa(int(d.Seconds())+1))
		writeErr(w, 429, "rate_limited", "tenant rate limit exceeded")
		return true
	}
	return false
}

// ---- helpers ---------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, "invalid_json", "request body is not valid JSON for this endpoint")
		return false
	}
	if dec.More() {
		writeErr(w, 400, "invalid_json", "trailing data after JSON body")
		return false
	}
	return true
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	if s.Log != nil {
		s.Log.Error("internal error", "err", err)
	}
	writeErr(w, 500, "internal", "internal error")
}

// ---- v2 ingest ---------------------------------------------------------------------

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request, a *Auth) {
	if s.limited(w, r, a.Tenant) {
		return
	}
	env, cerr := contract.ValidateEnvelope(a.Body)
	if cerr != nil {
		writeErr(w, cerr.Status, cerr.Code, cerr.Msg)
		return
	}
	rec, replay, err := s.Seq.Submit(r.Context(), a.Tenant.ID, env)
	switch {
	case errors.Is(err, sequencer.ErrConflict):
		writeErr(w, 409, "idempotency_conflict", "event_id was already used with a different body")
	case errors.Is(err, sequencer.ErrPIIDisabled):
		writeErr(w, 422, "pii_unsupported", "PII encryption is not enabled on this server")
	case err != nil:
		s.internal(w, err)
	case replay:
		writeJSON(w, 200, rec)
	default:
		writeJSON(w, 202, rec)
	}
}

// Record seals a server-generated event (admin changes, monitor alerts).
func (s *Server) Record(ctx context.Context, tenantID, agentID, action, resource, outcome string, principal *contract.Value, payload any) {
	env, err := sequencer.Internal(s.Now(), agentID, action, resource, outcome, principal, payload)
	if err == nil {
		_, _, err = s.Seq.Submit(ctx, tenantID, env)
	}
	if err != nil && s.Log != nil {
		s.Log.Error("internal event not recorded", "err", err, "action", action)
	}
}

// ---- tenant reads --------------------------------------------------------------------

func parseFilter(r *http.Request) (ledger.Filter, error) {
	q := r.URL.Query()
	f := ledger.Filter{AgentID: q.Get("agent_id"), Outcome: q.Get("outcome"), Action: q.Get("action"),
		Principal: q.Get("human_principal_id"), Desc: q.Get("order") == "desc", Limit: 100}
	var err error
	num := func(k string, dst *int64) {
		if v := q.Get(k); v != "" && err == nil {
			*dst, err = strconv.ParseInt(v, 10, 64)
		}
	}
	num("after_seq", &f.AfterSeq)
	num("before_seq", &f.BeforeSeq)
	num("from_seq", &f.FromSeq)
	num("to_seq", &f.ToSeq)
	if v := q.Get("limit"); v != "" {
		if f.Limit, err = strconv.Atoi(v); err != nil || f.Limit < 1 || f.Limit > 1000 {
			return f, errors.New("limit must be 1..1000")
		}
	}
	tm := func(k string) *time.Time {
		if v := q.Get(k); v != "" && err == nil {
			t, e := time.Parse(time.RFC3339Nano, v)
			if e != nil {
				err = fmt.Errorf("%s must be RFC 3339", k)
				return nil
			}
			return &t
		}
		return nil
	}
	f.From, f.To = tm("from"), tm("to")
	return f, err
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request, a *Auth) {
	f, err := parseFilter(r)
	if err != nil {
		writeErr(w, 400, "bad_query", err.Error())
		return
	}
	var evs []ledger.Record
	if err := s.tx(r, a, func(tx pgx.Tx) error {
		evs, err = ledger.ListEvents(r.Context(), tx, a.Tenant.ID, f)
		return err
	}); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"events": evs})
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request, a *Auth) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, 404, "not_found", "event not found")
		return
	}
	var rec ledger.Record
	err := s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		rec, e = ledger.GetEvent(r.Context(), tx, a.Tenant.ID, id)
		return e
	})
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, 404, "not_found", "event not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, rec)
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (s *Server) handleHead(w http.ResponseWriter, r *http.Request, a *Auth) {
	var h string
	var seq int64
	if err := s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		h, seq, e = ledger.Head(r.Context(), tx, a.Tenant.ID)
		return e
	}); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tenant_id": a.Tenant.ID, "seq": seq, "hash": h})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, a *Auth) {
	var st ledger.Stats
	if err := s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		st, e = ledger.GetStats(r.Context(), tx, a.Tenant.ID)
		return e
	}); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, a *Auth) {
	out := map[string]any{"tenant": a.Tenant}
	if a.Cred != nil {
		out["key"] = map[string]any{"id": a.Cred.KeyID, "version": a.Cred.Version, "scopes": a.Cred.Scopes}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handlePublicKeys(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, 404, "not_found", "tenant not found")
		return
	}
	ks, err := s.Tenants.PublicKeys(r.Context(), id)
	if err != nil || len(ks) == 0 {
		writeErr(w, 404, "not_found", "tenant not found")
		return
	}
	writeJSON(w, 200, map[string]any{"tenant_id": id, "keys": ks})
}

// ---- admin (control plane) --------------------------------------------------------------

var adminPrincipal = contract.MustFromGo(map[string]string{"id": "admin-token", "type": "service"})

type operatorKey struct{}

// operatorFrom returns the operator asserted by an admin-token caller (the
// dashboard, after SSO) in X-AuditTrail-Operator, or "" if absent/invalid.
func operatorFrom(r *http.Request) string {
	op := strings.TrimSpace(r.Header.Get("X-AuditTrail-Operator"))
	if op == "" || len(op) > 254 {
		return ""
	}
	for _, c := range op {
		if c < 0x21 || c > 0x7e { // printable ASCII, no spaces or controls
			return ""
		}
	}
	return op
}

// adminEvent seals an admin action into the tenant's own ledger. When the
// dashboard names the signed-in operator, that person is the principal; the
// admin token that vouched for them is recorded alongside.
func (s *Server) adminEvent(ctx context.Context, tenantID, action, target string, meta map[string]any) {
	principal := adminPrincipal
	if op, _ := ctx.Value(operatorKey{}).(string); op != "" {
		principal = contract.MustFromGo(map[string]string{"id": op, "type": "human"})
		if meta == nil {
			meta = map[string]any{}
		}
		meta["operator_asserted_by"] = "admin-token"
	}
	s.Record(ctx, tenantID, "audittrail-admin", action, target, "allowed", principal, meta)
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Tenants.List(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tenants": ts})
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name           string `json:"name"`
		RetentionDays  int    `json:"retention_days"`
		RateLimitRPS   int    `json:"rate_limit_rps"`
		RateLimitBurst int    `json:"rate_limit_burst"`
	}
	if !decode(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Name) == "" || len(body.Name) > 200 {
		writeErr(w, 400, "validation_failed", "name is required (max 200 chars)")
		return
	}
	if body.RetentionDays != 0 && body.RetentionDays < 183 {
		writeErr(w, 400, "validation_failed", "retention_days must be >= 183 (EU AI Act six-month minimum)")
		return
	}
	t, full, ak, pk, err := s.Tenants.Create(r.Context(), tenant.CreateOptions{
		Name: body.Name, RetentionDays: body.RetentionDays, RateLimitRPS: body.RateLimitRPS, RateLimitBurst: body.RateLimitBurst})
	if err != nil {
		s.internal(w, err)
		return
	}
	s.adminEvent(r.Context(), t.ID, "tenant.created", "tenant:"+t.ID, map[string]any{"name": t.Name, "signing_key_id": pk.KeyID})
	writeJSON(w, 201, map[string]any{"tenant": t, "api_key": full, "api_key_info": ak, "signing_key": pk})
}

func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	t, err := s.Tenants.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, "not_found", "tenant not found")
		return
	}
	writeJSON(w, 200, t)
}

func (s *Server) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	var p tenant.Settings
	if !decode(w, r, &p) {
		return
	}
	if p.RetentionDays != nil && *p.RetentionDays < 183 {
		writeErr(w, 400, "validation_failed", "retention_days must be >= 183 (EU AI Act six-month minimum)")
		return
	}
	if p.LegalHold != nil && *p.LegalHold && (p.LegalHoldReason == nil || strings.TrimSpace(*p.LegalHoldReason) == "") {
		writeErr(w, 400, "validation_failed", "legal_hold_reason is required when setting a legal hold")
		return
	}
	id := r.PathValue("id")
	before, err := s.Tenants.Get(r.Context(), id)
	if err != nil {
		writeErr(w, 404, "not_found", "tenant not found")
		return
	}
	t, err := s.Tenants.Update(r.Context(), id, p)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.adminEvent(r.Context(), id, "tenant.settings_changed", "tenant:"+id, map[string]any{"before": before, "after": t})
	writeJSON(w, 200, t)
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.Tenants.ListAPIKeys(r.Context(), r.PathValue("id"))
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"api_keys": ks})
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if r.ContentLength != 0 && !decode(w, r, &body) {
		return
	}
	if body.Name == "" {
		body.Name = "key-" + time.Now().UTC().Format("20060102-150405")
	}
	id := r.PathValue("id")
	full, k, err := s.Tenants.CreateAPIKey(r.Context(), id, body.Name, body.Scopes, body.ExpiresAt)
	if errors.Is(err, tenant.ErrNotFound) {
		writeErr(w, 404, "not_found", "tenant not found")
		return
	}
	if err != nil && strings.HasPrefix(err.Error(), "unknown scope") {
		writeErr(w, 400, "validation_failed", err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.adminEvent(r.Context(), id, "api_key.created", "api_key:"+k.ID, map[string]any{"name": k.Name, "prefix": k.Prefix, "scopes": k.Scopes})
	writeJSON(w, 201, map[string]any{"api_key": full, "api_key_info": k})
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id, kid := r.PathValue("id"), r.PathValue("keyId")
	if err := s.Tenants.RevokeAPIKey(r.Context(), id, kid); err != nil {
		writeErr(w, 404, "not_found", "active API key not found")
		return
	}
	s.adminEvent(r.Context(), id, "api_key.revoked", "api_key:"+kid, nil)
	w.WriteHeader(204)
}

func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	pk, err := s.Tenants.RotateSigningKey(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.adminEvent(r.Context(), id, "signing_key.rotated", "signing_key:"+pk.KeyID, map[string]any{"new_key_id": pk.KeyID})
	writeJSON(w, 201, pk)
}

// ---- crypto-shredding (v2 phase 5) ------------------------------------------------

func (s *Server) handleErase(w http.ResponseWriter, r *http.Request, a *Auth) {
	subject := r.PathValue("subject")
	var body struct {
		Reason string `json:"reason"`
	}
	if len(a.Body) > 0 {
		if err := json.Unmarshal(a.Body, &body); err != nil {
			writeErr(w, 400, "invalid_json", "body must be {\"reason\": \"…\"}")
			return
		}
	}
	if strings.TrimSpace(body.Reason) == "" || len(body.Reason) > 500 || subject == "" || len(subject) > 256 {
		writeErr(w, 422, "invalid_value", "a subject and a reason (1..500 chars) are required")
		return
	}
	var dekIDs []string
	if err := s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		dekIDs, e = pii.Erase(r.Context(), tx, a.Tenant.ID, subject, body.Reason)
		return e
	}); err != nil {
		s.internal(w, err)
		return
	}
	digest := pii.SubjectDigest(a.Tenant.ID, subject)
	principal := contract.MustFromGo(map[string]string{"id": "api-key:" + a.Cred.KeyID, "type": "service"})
	env, err := sequencer.Internal(s.Now(), "audittrail-erasure", "audittrail.subject/erased", "subject:"+digest, "allowed", principal,
		map[string]any{"subject_sha256": digest, "destroyed_keys": dekIDs, "reason": body.Reason})
	var rec sequencer.Receipt
	if err == nil {
		rec, _, err = s.Seq.Submit(r.Context(), a.Tenant.ID, env)
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"subject_sha256": digest, "destroyed_keys": dekIDs, "erasure_event": rec})
}

func (s *Server) handlePIIRead(w http.ResponseWriter, r *http.Request, a *Auth) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, 404, "not_found", "event not found")
		return
	}
	var fields map[string]string
	err := s.tx(r, a, func(tx pgx.Tx) error {
		rec, e := ledger.GetEvent(r.Context(), tx, a.Tenant.ID, id)
		if e != nil {
			return e
		}
		if len(rec.PIICT) == 0 {
			return ledger.ErrNotFound
		}
		fields, e = s.PII.Decrypt(r.Context(), tx, a.Tenant.ID, id, rec.PIICT)
		return e
	})
	switch {
	case errors.Is(err, ledger.ErrNotFound):
		writeErr(w, 404, "not_found", "no PII on this event")
	case errors.Is(err, pii.ErrErased):
		writeErr(w, 410, "erased", "this subject's data has been crypto-shredded")
	case err != nil:
		s.internal(w, err)
	default:
		writeJSON(w, 200, map[string]any{"event_id": id, "fields": fields})
	}
}
