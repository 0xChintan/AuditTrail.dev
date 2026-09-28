package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/export"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
	"audittrail.dev/packages/ingestion-go/internal/verify"
)

// RegisterExtensions wires routes from later phases (checkpoints, exports,
// verification, retention).
func RegisterExtensions(s *Server) {
	s.Handle("GET /v1/checkpoints", s.tenantAuth(http.HandlerFunc(s.handleListCheckpoints)))
	s.Handle("GET /v1/checkpoints/{id}", s.tenantAuth(http.HandlerFunc(s.handleGetCheckpoint)))
	s.Handle("GET /v1/events/{id}/proof", s.tenantAuth(http.HandlerFunc(s.handleProof)))
	s.Handle("GET /v1/export", s.tenantAuth(http.HandlerFunc(s.handleExport)))
	s.Handle("GET /v1/verify", s.tenantAuth(http.HandlerFunc(s.handleVerify)))
	s.Handle("GET /v1/purges", s.tenantAuth(http.HandlerFunc(s.handlePurges)))
	s.Handle("GET /v1/templates", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"templates": export.Templates})
	}))
}

func (s *Server) handleListCheckpoints(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	cps, err := ledger.ListCheckpoints(r.Context(), s.Pool, TenantFrom(r.Context()).ID, 0, 0, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"checkpoints": cps})
}

func (s *Server) handleGetCheckpoint(w http.ResponseWriter, r *http.Request) {
	cp, err := ledger.GetCheckpoint(r.Context(), s.Pool, TenantFrom(r.Context()).ID, r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, "not_found", "checkpoint not found")
		return
	}
	writeJSON(w, 200, cp)
}

// handleProof returns an RFC 6962 inclusion proof tying one event to the
// signed (and externally anchored) Merkle root of its checkpoint.
func (s *Server) handleProof(w http.ResponseWriter, r *http.Request) {
	t := TenantFrom(r.Context())
	ev, err := ledger.GetEvent(r.Context(), s.Pool, t.ID, r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, "not_found", "event not found")
		return
	}
	cp, err := ledger.CheckpointCovering(r.Context(), s.Pool, t.ID, ev.Seq)
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, 409, "not_checkpointed", "event is not yet covered by a checkpoint; try again after the next checkpoint run")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	rows, err := ledger.ListEvents(r.Context(), s.Pool, t.ID, ledger.Filter{FromSeq: cp.FirstSeq, ToSeq: cp.LastSeq})
	if err != nil {
		s.internal(w, err)
		return
	}
	hashes := make([]string, len(rows))
	for i, e := range rows {
		hashes[i] = e.Hash
	}
	idx := int(ev.Seq - cp.FirstSeq)
	path, err := merkle.InclusionProof(hashes, idx)
	if err != nil {
		s.internal(w, err)
		return
	}
	pubs, _ := s.Tenants.PublicKeys(r.Context(), t.ID)
	writeJSON(w, 200, map[string]any{
		"event": ev, "checkpoint": cp, "leaf_index": idx, "tree_size": len(hashes), "inclusion_path": path,
		"public_keys": pubs,
		"verified_by_server": merkle.VerifyInclusion(ev.Hash, idx, len(hashes), path, cp.MerkleRoot),
	})
}

func parseRange(r *http.Request) (export.Range, error) {
	q := r.URL.Query()
	var rg export.Range
	for _, k := range []string{"from", "to"} {
		if v := q.Get(k); v != "" {
			t, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				if t, err = time.Parse("2006-01-02", v); err != nil {
					return rg, fmt.Errorf("%s must be RFC 3339 or YYYY-MM-DD", k)
				}
				if k == "to" {
					t = t.Add(24*time.Hour - time.Nanosecond)
				}
			}
			if k == "from" {
				rg.From = &t
			} else {
				rg.To = &t
			}
		}
	}
	var err error
	if v := q.Get("from_seq"); v != "" {
		if rg.FromSeq, err = strconv.ParseInt(v, 10, 64); err != nil {
			return rg, errors.New("from_seq must be an integer")
		}
	}
	if v := q.Get("to_seq"); v != "" {
		if rg.ToSeq, err = strconv.ParseInt(v, 10, 64); err != nil {
			return rg, errors.New("to_seq must be an integer")
		}
	}
	return rg, nil
}

func (s *Server) bundleFor(r *http.Request) (verify.Bundle, error) {
	t := TenantFrom(r.Context())
	rg, err := parseRange(r)
	if err != nil {
		return verify.Bundle{}, &badRequest{err.Error()}
	}
	pubs, err := s.Tenants.PublicKeys(r.Context(), t.ID)
	if err != nil {
		return verify.Bundle{}, err
	}
	return export.BuildBundle(r.Context(), s.Pool, t, pubs, rg)
}

type badRequest struct{ msg string }

func (e *badRequest) Error() string { return e.msg }

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "bundle"
	}
	tplID := r.URL.Query().Get("template")
	var tpl *export.Template
	if tplID != "" {
		if tpl = export.TemplateByID(tplID); tpl == nil {
			writeErr(w, 400, "unknown_template", "template must be one of eu-ai-act-art12, soc2-cc7.2, nist-800-53-au3")
			return
		}
	} else if format != "bundle" {
		writeErr(w, 400, "template_required", "csv/pdf exports need ?template=")
		return
	}
	b, err := s.bundleFor(r)
	var br *badRequest
	if errors.As(err, &br) {
		writeErr(w, 400, "bad_query", br.msg)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	rep := verify.Verify(b, verify.Options{})
	stamp := time.Now().UTC().Format("20060102-150405")
	name := fmt.Sprintf("audittrail-%s-%s", shortID(b.Tenant.ID), stamp)
	if tpl != nil {
		name = fmt.Sprintf("audittrail-%s-%s-%s", tpl.ID, shortID(b.Tenant.ID), stamp)
		raw, _ := json.Marshal(tpl)
		rm := json.RawMessage(raw)
		b.Template = &rm
	}
	switch format {
	case "bundle", "json":
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.bundle.json"`, name))
		writeJSON(w, 200, b)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, name))
		if err := export.WriteCSV(w, b, *tpl, rep); err != nil {
			s.Log.Error("csv export", "err", err)
		}
	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, name))
		if err := export.WritePDF(w, b, *tpl, rep); err != nil {
			s.Log.Error("pdf export", "err", err)
		}
	default:
		writeErr(w, 400, "bad_format", "format must be bundle, csv or pdf")
	}
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	b, err := s.bundleFor(r)
	var br *badRequest
	if errors.As(err, &br) {
		writeErr(w, 400, "bad_query", br.msg)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, verify.Verify(b, verify.Options{}))
}

func (s *Server) handlePurges(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Pool.Query(r.Context(), `SELECT id, checkpoint_id, purged_through_seq, rows_deleted, performed_by, purged_at
		FROM purge_log WHERE tenant_id=$1 ORDER BY purged_at DESC LIMIT 100`, TenantFrom(r.Context()).ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, through, n int64
		var cp, by string
		var at time.Time
		if err := rows.Scan(&id, &cp, &through, &n, &by, &at); err != nil {
			s.internal(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "checkpoint_id": cp, "purged_through_seq": through, "rows_deleted": n, "performed_by": by, "purged_at": at})
	}
	writeJSON(w, 200, map[string]any{"purges": out})
}
