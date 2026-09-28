// Package api is the HTTP front door of the ingestion service.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/tenant"
)

const maxBody = 256 << 10

type Server struct {
	Pool        *pgxpool.Pool
	Sealer      *ledger.Sealer
	Tenants     *tenant.Store
	AdminToken  string
	CORSOrigins []string
	Log         *slog.Logger

	limMu    sync.Mutex
	limiters map[string]*rate.Limiter

	mux *http.ServeMux
}

func New(pool *pgxpool.Pool, master *keys.MasterKey, adminToken string, cors []string, log *slog.Logger) *Server {
	s := &Server{
		Pool:        pool,
		Sealer:      ledger.NewSealer(pool, master),
		Tenants:     &tenant.Store{Pool: pool, Master: master},
		AdminToken:  adminToken,
		CORSOrigins: cors,
		Log:         log,
		limiters:    map[string]*rate.Limiter{},
		mux:         http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Pool.Ping(r.Context()); err != nil {
			writeErr(w, 503, "db_unavailable", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	// Public: verification must not require trusting a session with us.
	m.HandleFunc("GET /v1/tenants/{id}/public-keys", s.handlePublicKeys)

	// Tenant-scoped (API key, or admin token + X-AuditTrail-Tenant).
	m.Handle("POST /v1/events", s.tenantAuth(s.rateLimited(http.HandlerFunc(s.handleSeal))))
	m.Handle("GET /v1/events", s.tenantAuth(http.HandlerFunc(s.handleListEvents)))
	m.Handle("GET /v1/events/{id}", s.tenantAuth(http.HandlerFunc(s.handleGetEvent)))
	m.Handle("GET /v1/chain/head", s.tenantAuth(http.HandlerFunc(s.handleHead)))
	m.Handle("GET /v1/stats", s.tenantAuth(http.HandlerFunc(s.handleStats)))
	m.Handle("GET /v1/me", s.tenantAuth(http.HandlerFunc(s.handleMe)))

	// Admin.
	m.Handle("GET /v1/admin/tenants", s.adminAuth(http.HandlerFunc(s.handleListTenants)))
	m.Handle("POST /v1/admin/tenants", s.adminAuth(http.HandlerFunc(s.handleCreateTenant)))
	m.Handle("GET /v1/admin/tenants/{id}", s.adminAuth(http.HandlerFunc(s.handleGetTenant)))
	m.Handle("PATCH /v1/admin/tenants/{id}", s.adminAuth(http.HandlerFunc(s.handleUpdateTenant)))
	m.Handle("GET /v1/admin/tenants/{id}/api-keys", s.adminAuth(http.HandlerFunc(s.handleListAPIKeys)))
	m.Handle("POST /v1/admin/tenants/{id}/api-keys", s.adminAuth(http.HandlerFunc(s.handleCreateAPIKey)))
	m.Handle("DELETE /v1/admin/tenants/{id}/api-keys/{keyId}", s.adminAuth(http.HandlerFunc(s.handleRevokeAPIKey)))
	m.Handle("POST /v1/admin/tenants/{id}/signing-keys/rotate", s.adminAuth(http.HandlerFunc(s.handleRotateKey)))
}

// Handle lets later phases register extra routes (checkpoints, exports).
func (s *Server) Handle(pattern string, h http.Handler) { s.mux.Handle(pattern, h) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if origin := r.Header.Get("Origin"); origin != "" && s.corsAllowed(origin) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Vary", "Origin")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-AuditTrail-Tenant")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
	}
	sw := &statusWriter{ResponseWriter: w, status: 200}
	s.mux.ServeHTTP(sw, r)
	if s.Log != nil && r.URL.Path != "/healthz" {
		s.Log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "dur_ms", time.Since(start).Milliseconds())
	}
}

func (s *Server) corsAllowed(origin string) bool {
	for _, o := range s.CORSOrigins {
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

// ---- auth -----------------------------------------------------------------

type ctxKey int

const tenantKey ctxKey = 1

func TenantFrom(ctx context.Context) tenant.Tenant {
	t, _ := ctx.Value(tenantKey).(tenant.Tenant)
	return t
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if v, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func (s *Server) isAdmin(r *http.Request) bool {
	return s.AdminToken != "" && keys.HashesEqual(bearer(r), s.AdminToken)
}

func (s *Server) tenantAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var t tenant.Tenant
		var err error
		if s.isAdmin(r) {
			id := r.Header.Get("X-AuditTrail-Tenant")
			if id == "" {
				writeErr(w, 400, "tenant_required", "admin requests to tenant routes need X-AuditTrail-Tenant")
				return
			}
			t, err = s.Tenants.Get(r.Context(), id)
		} else {
			t, _, err = s.Tenants.Authenticate(r.Context(), bearer(r))
		}
		if err != nil {
			writeErr(w, 401, "unauthorized", "missing, invalid or revoked API key")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantKey, t)))
	})
}

func (s *Server) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isAdmin(r) {
			writeErr(w, 401, "unauthorized", "admin token required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- rate limiting (Task 2.3): per-tenant token bucket, in memory ----------

func (s *Server) limiter(t tenant.Tenant) *rate.Limiter {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	l, ok := s.limiters[t.ID]
	if !ok {
		l = rate.NewLimiter(rate.Limit(t.RateLimitRPS), t.RateLimitBurst)
		s.limiters[t.ID] = l
	} else if l.Limit() != rate.Limit(t.RateLimitRPS) || l.Burst() != t.RateLimitBurst {
		l.SetLimit(rate.Limit(t.RateLimitRPS))
		l.SetBurst(t.RateLimitBurst)
	}
	return l
}

func (s *Server) rateLimited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := TenantFrom(r.Context())
		res := s.limiter(t).Reserve()
		if d := res.Delay(); d > 0 {
			res.Cancel()
			secs := int(d.Seconds()) + 1
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeErr(w, 429, "rate_limited", fmt.Sprintf("tenant rate limit exceeded (%d rps, burst %d)", t.RateLimitRPS, t.RateLimitBurst))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string, extra ...map[string]any) {
	e := map[string]any{"code": code, "message": msg}
	for _, x := range extra {
		for k, v := range x {
			e[k] = v
		}
	}
	writeJSON(w, status, map[string]any{"error": e})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, "invalid_json", err.Error())
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

// ---- tenant handlers ------------------------------------------------------

func (s *Server) handleSeal(w http.ResponseWriter, r *http.Request) {
	var sub ledger.Submission
	if !decode(w, r, &sub) {
		return
	}
	t := TenantFrom(r.Context())
	rec, replay, err := s.Sealer.Seal(r.Context(), t.ID, sub)
	var ve *ledger.ValidationError
	var ce *ledger.ConflictError
	switch {
	case err == nil && replay:
		w.Header().Set("Idempotent-Replay", "true")
		writeJSON(w, 200, rec)
	case err == nil:
		writeJSON(w, 201, rec)
	case errors.As(err, &ve):
		writeErr(w, 400, "validation_failed", ve.Msg)
	case errors.As(err, &ce):
		writeErr(w, 409, ce.Code, ce.Msg, map[string]any{
			"current_head": ce.CurrentHead, "current_seq": ce.CurrentSeq, "expected_hash": ce.Expected})
	default:
		s.internal(w, err)
	}
}

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

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		writeErr(w, 400, "bad_query", err.Error())
		return
	}
	evs, err := ledger.ListEvents(r.Context(), s.Pool, TenantFrom(r.Context()).ID, f)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"events": evs})
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	rec, err := ledger.GetEvent(r.Context(), s.Pool, TenantFrom(r.Context()).ID, r.PathValue("id"))
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, 404, "not_found", "event not found")
		return
	}
	if err != nil {
		writeErr(w, 400, "bad_request", "invalid event id")
		return
	}
	writeJSON(w, 200, rec)
}

func (s *Server) handleHead(w http.ResponseWriter, r *http.Request) {
	t := TenantFrom(r.Context())
	h, seq, err := ledger.Head(r.Context(), s.Pool, t.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tenant_id": t.ID, "seq": seq, "hash": h})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := ledger.GetStats(r.Context(), s.Pool, TenantFrom(r.Context()).ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, TenantFrom(r.Context()))
}

func (s *Server) handlePublicKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.Tenants.PublicKeys(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, "not_found", "tenant not found")
		return
	}
	writeJSON(w, 200, map[string]any{"tenant_id": r.PathValue("id"), "keys": ks})
}

// ---- admin handlers -------------------------------------------------------

// adminEvent records an administrative change in the tenant's own ledger, so
// retention / legal-hold / key changes are themselves tamper-evident.
func (s *Server) adminEvent(ctx context.Context, tenantID, action, target string, meta map[string]any) {
	md, _ := json.Marshal(meta)
	actor := "admin-token"
	_, _, err := s.Sealer.Seal(ctx, tenantID, ledger.Submission{
		HumanPrincipalID: &actor, AgentID: "audittrail-admin", Action: action, TargetResource: target,
		Outcome: "allowed", Metadata: md,
	})
	if err != nil && s.Log != nil {
		s.Log.Error("admin event not recorded", "err", err, "action", action)
	}
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
	if strings.TrimSpace(body.Name) == "" {
		writeErr(w, 400, "validation_failed", "name is required")
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
		Name string `json:"name"`
	}
	if r.ContentLength != 0 && !decode(w, r, &body) {
		return
	}
	if body.Name == "" {
		body.Name = "key-" + time.Now().UTC().Format("20060102-150405")
	}
	id := r.PathValue("id")
	full, k, err := s.Tenants.CreateAPIKey(r.Context(), id, body.Name)
	if errors.Is(err, tenant.ErrNotFound) {
		writeErr(w, 404, "not_found", "tenant not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.adminEvent(r.Context(), id, "api_key.created", "api_key:"+k.ID, map[string]any{"name": k.Name, "prefix": k.Prefix})
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

// drain is used by tests to discard bodies.
var _ = io.Discard
