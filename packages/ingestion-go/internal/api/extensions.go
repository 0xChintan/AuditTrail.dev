package api

import (
	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/otel"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/export"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
	"audittrail.dev/packages/ingestion-go/internal/tlog"
	"audittrail.dev/packages/ingestion-go/internal/verify"
	"audittrail.dev/packages/ingestion-go/internal/verify2"
)

// RegisterExtensions wires routes from later phases (checkpoints, exports,
// verification, retention).
func RegisterExtensions(s *Server) {
	s.Handle("GET /v1/checkpoints", s.auth("events:read", false, s.handleListCheckpoints))
	s.Handle("GET /v1/checkpoints/{id}", s.auth("events:read", false, s.handleGetCheckpoint))
	s.Handle("GET /v1/events/{id}/proof", s.auth("events:read", false, s.handleProof))
	s.Handle("GET /v1/export", s.auth("export:read", false, s.handleExport))
	s.Handle("GET /v1/verify", s.auth("export:read", false, s.handleVerify))
	s.Handle("GET /v1/purges", s.auth("events:read", false, s.handlePurges))
	s.Handle("GET /v2/tenants/{id}/log", http.HandlerFunc(s.handleLogInfo))
	// OTLP/HTTP receiver for GenAI spans. OTel exporters cannot sign
	// requests, so this route uses a dedicated otlp:write scope instead of
	// request signatures (documented exception, see THREAT_MODEL.md).
	s.Handle("POST /v1/traces", s.auth("otlp:write", false, s.handleOTLP))
	s.Handle("GET /v2/export", s.auth("export:read", false, s.handleExportV2))
	s.Handle("GET /v2/tree-heads", s.auth("events:read", false, s.handleTreeHeads))
	s.Handle("GET /v1/templates", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"templates": export.Templates})
	}))
}

func (s *Server) handleListCheckpoints(w http.ResponseWriter, r *http.Request, a *Auth) {
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	var cps []ledger.Checkpoint
	if err := s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		cps, e = ledger.ListCheckpoints(r.Context(), tx, a.Tenant.ID, 0, 0, limit)
		return e
	}); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"checkpoints": cps})
}

func (s *Server) handleGetCheckpoint(w http.ResponseWriter, r *http.Request, a *Auth) {
	if !isUUID(r.PathValue("id")) {
		writeErr(w, 404, "not_found", "checkpoint not found")
		return
	}
	var cp ledger.Checkpoint
	err := s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		cp, e = ledger.GetCheckpoint(r.Context(), tx, a.Tenant.ID, r.PathValue("id"))
		return e
	})
	if err != nil {
		writeErr(w, 404, "not_found", "checkpoint not found")
		return
	}
	writeJSON(w, 200, cp)
}

// handleProof returns an RFC 6962 inclusion proof tying one event to the
// signed (and externally anchored) Merkle root of its checkpoint.
func (s *Server) handleProof(w http.ResponseWriter, r *http.Request, a *Auth) {
	if !isUUID(r.PathValue("id")) {
		writeErr(w, 404, "not_found", "event not found")
		return
	}
	var ev ledger.Record
	var cp ledger.Checkpoint
	var rows []ledger.Record
	err := s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		if ev, e = ledger.GetEvent(r.Context(), tx, a.Tenant.ID, r.PathValue("id")); e != nil {
			return e
		}
		if cp, e = ledger.CheckpointCovering(r.Context(), tx, a.Tenant.ID, ev.Seq); e != nil {
			return errNotCheckpointed
		}
		rows, e = ledger.ListEvents(r.Context(), tx, a.Tenant.ID, ledger.Filter{FromSeq: cp.FirstSeq, ToSeq: cp.LastSeq})
		return e
	})
	switch {
	case errors.Is(err, ledger.ErrNotFound):
		writeErr(w, 404, "not_found", "event not found")
		return
	case errors.Is(err, errNotCheckpointed):
		writeErr(w, 409, "not_checkpointed", "event is not yet covered by a checkpoint; try again after the next checkpoint run")
		return
	case err != nil:
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
	pubs, _ := s.Tenants.PublicKeys(r.Context(), a.Tenant.ID)
	writeJSON(w, 200, map[string]any{
		"event": ev, "checkpoint": cp, "leaf_index": idx, "tree_size": len(hashes), "inclusion_path": path,
		"public_keys":        pubs,
		"verified_by_server": merkle.VerifyInclusion(ev.Hash, idx, len(hashes), path, cp.MerkleRoot),
	})
}

var errNotCheckpointed = errors.New("not checkpointed")

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

func (s *Server) bundleFor(r *http.Request, a *Auth) (verify.Bundle, error) {
	t := a.Tenant
	rg, err := parseRange(r)
	if err != nil {
		return verify.Bundle{}, &badRequest{err.Error()}
	}
	pubs, err := s.Tenants.PublicKeys(r.Context(), t.ID)
	if err != nil {
		return verify.Bundle{}, err
	}
	var b verify.Bundle
	err = s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		b, e = export.BuildBundle(r.Context(), tx, t, pubs, rg)
		return e
	})
	return b, err
}

type badRequest struct{ msg string }

func (e *badRequest) Error() string { return e.msg }

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, a *Auth) {
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
	b, err := s.bundleFor(r, a)
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
		var heads []export.TreeHeadInfo
		_ = s.tx(r, a, func(tx pgx.Tx) error {
			rows, err := tx.Query(r.Context(), `SELECT tree_size, root_hash, witnesses, COALESCE(tsa_authority,'') || COALESCE(' @ ' || to_char(tsa_time AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),''), to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI'), note
				FROM tree_heads WHERE tenant_id=$1 ORDER BY tree_size DESC LIMIT 20`, a.Tenant.ID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var h export.TreeHeadInfo
				if rows.Scan(&h.TreeSize, &h.RootHash, &h.Witnesses, &h.TSA, &h.CreatedAt, &h.Note) == nil {
					heads = append(heads, h)
				}
			}
			return nil
		})
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, name))
		if err := export.WritePDF(w, b, *tpl, rep, heads...); err != nil {
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

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request, a *Auth) {
	b, err := s.bundleFor(r, a)
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

func (s *Server) handlePurges(w http.ResponseWriter, r *http.Request, a *Auth) {
	out := []map[string]any{}
	err := s.tx(r, a, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id, checkpoint_id, purged_through_seq, rows_deleted, performed_by, purged_at
			FROM purge_log WHERE tenant_id=$1 ORDER BY purged_at DESC LIMIT 100`, a.Tenant.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, through, n int64
			var cp, by string
			var at time.Time
			if err := rows.Scan(&id, &cp, &through, &n, &by, &at); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": id, "checkpoint_id": cp, "purged_through_seq": through, "rows_deleted": n, "performed_by": by, "purged_at": at})
		}
		return rows.Err()
	})
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"purges": out})
}

// handleLogInfo publishes a tenant log's origin and verification keys
// (C2SP vkeys) so verifiers and witnesses can pin them.
func (s *Server) handleLogInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, 404, "not_found", "log not found")
		return
	}
	pubs, err := s.Tenants.PublicKeys(r.Context(), id)
	if err != nil || len(pubs) == 0 {
		writeErr(w, 404, "not_found", "log not found")
		return
	}
	ks := export.LogKeys(id, pubs)
	vkeys := []string{}
	for _, k := range ks {
		vkeys = append(vkeys, k.Vkey)
	}
	writeJSON(w, 200, map[string]any{"origin": tlog.Origin(id), "vkeys": vkeys, "keys": ks})
}

func (s *Server) handleExportV2(w http.ResponseWriter, r *http.Request, a *Auth) {
	rg, err := parseRange(r)
	if err != nil {
		writeErr(w, 400, "bad_query", err.Error())
		return
	}
	pubs, err := s.Tenants.PublicKeys(r.Context(), a.Tenant.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	var b *verify2.Bundle
	err = s.tx(r, a, func(tx pgx.Tx) error {
		var e error
		b, e = export.BuildBundleV2(r.Context(), tx, a.Tenant, pubs, rg)
		return e
	})
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audittrail-%s-%s.bundle.v2.json"`, shortID(a.Tenant.ID), time.Now().UTC().Format("20060102-150405")))
	writeJSON(w, 200, b)
}

func (s *Server) handleTreeHeads(w http.ResponseWriter, r *http.Request, a *Auth) {
	out := []map[string]any{}
	err := s.tx(r, a, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT tree_size, root_hash, note, witnesses, tsa_status, tsa_authority, tsa_time, created_at
			FROM tree_heads WHERE tenant_id=$1 ORDER BY tree_size DESC LIMIT 200`, a.Tenant.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var size int64
			var root, note, status string
			var wits []string
			var auth *string
			var tsaTime *time.Time
			var created time.Time
			if err := rows.Scan(&size, &root, &note, &wits, &status, &auth, &tsaTime, &created); err != nil {
				return err
			}
			out = append(out, map[string]any{"tree_size": size, "root_hash": root, "note": note, "witnesses": wits,
				"tsa_status": status, "tsa_authority": auth, "tsa_time": tsaTime, "created_at": created})
		}
		return rows.Err()
	})
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"origin": tlog.Origin(a.Tenant.ID), "tree_heads": out})
}

func (s *Server) handleOTLP(w http.ResponseWriter, r *http.Request, a *Auth) {
	if s.limited(w, a.Tenant) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
	if err != nil || len(body) > 4<<20 {
		writeErr(w, 413, "body_too_large", "OTLP request exceeds 4 MiB")
		return
	}
	ct := r.Header.Get("Content-Type")
	var spans []otel.Span
	if strings.Contains(ct, "json") {
		spans, err = otel.DecodeJSON(body)
	} else {
		spans, err = otel.DecodeProto(body)
	}
	if err != nil {
		writeErr(w, 400, "invalid_otlp", err.Error())
		return
	}
	accepted, ignored, rejected := 0, 0, 0
	var firstErr string
	for _, sp := range spans {
		env, err := otel.Normalize(sp)
		if err != nil {
			rejected++
			firstErr = err.Error()
			continue
		}
		if env == nil {
			ignored++
			continue
		}
		e, cerr := contract.ValidateEnvelope(env)
		if cerr != nil {
			rejected++
			firstErr = cerr.Code + ": " + cerr.Msg
			continue
		}
		if _, _, err := s.Seq.Submit(r.Context(), a.Tenant.ID, e); err != nil {
			rejected++
			firstErr = "could not seal span"
			continue
		}
		accepted++
	}
	w.Header().Set("X-AuditTrail-Accepted", strconv.Itoa(accepted))
	w.Header().Set("X-AuditTrail-Ignored", strconv.Itoa(ignored))
	if !strings.Contains(ct, "json") {
		// An empty body is a valid encoding of ExportTraceServiceResponse.
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(200)
		return
	}
	resp := map[string]any{}
	if rejected > 0 {
		resp["partialSuccess"] = map[string]any{"rejectedSpans": rejected, "errorMessage": firstErr}
	}
	writeJSON(w, 200, resp)
}
