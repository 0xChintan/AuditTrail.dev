// Package treehead produces C2SP-signed tree heads over each tenant's whole
// log, collects witness cosignatures and RFC 3161 anchors (v2 3.1–3.2).
package treehead

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"audittrail.dev/packages/ingestion-go/internal/anchor"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
	"audittrail.dev/packages/ingestion-go/internal/tlog"
	"audittrail.dev/packages/ingestion-go/internal/witness"
)

type WitnessCfg struct {
	Name string // must match the witness's key name
	URL  string
}

type Worker struct {
	Pool      *pgxpool.Pool
	Master    *keys.MasterKey
	Witnesses []WitnessCfg
	TSA       *anchor.TSA
	Log       *slog.Logger
	HTTP      *http.Client
}

type Head struct {
	TenantID  string
	TreeSize  uint64
	RootHex   string
	Note      string
	Witnesses []string
	Anchored  bool
}

type IntegrityError struct {
	TenantID string
	Seq      int64
	Reason   string
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("tenant %s: integrity failure at seq %d (%s); tree head withheld", e.TenantID, e.Seq, e.Reason)
}

func (w *Worker) logf(msg string, args ...any) {
	if w.Log != nil {
		w.Log.Info(msg, args...)
	}
}

// Leaves returns the raw leaf hashes 1..size for a tenant (live + purged).
func Leaves(ctx context.Context, q ledger.Querier, tenantID string, size int64) ([][]byte, error) {
	rows, err := q.Query(ctx, `SELECT seq, hash FROM (
		SELECT seq, hash FROM agent_events WHERE tenant_id=$1 AND seq <= $2
		UNION ALL SELECT seq, hash FROM purged_leaves WHERE tenant_id=$1 AND seq <= $2) x ORDER BY seq`, tenantID, size)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([][]byte, 0, size)
	for rows.Next() {
		var seq int64
		var h string
		if err := rows.Scan(&seq, &h); err != nil {
			return nil, err
		}
		if seq != int64(len(out))+1 {
			return nil, &IntegrityError{tenantID, int64(len(out)) + 1, "leaf missing"}
		}
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return nil, &IntegrityError{tenantID, seq, "bad leaf hash"}
		}
		out = append(out, b)
	}
	if int64(len(out)) != size {
		return nil, &IntegrityError{tenantID, int64(len(out)) + 1, "leaf missing"}
	}
	return out, rows.Err()
}

// Run creates a new tree head if the log grew, then (re)collects witness
// cosignatures and an RFC 3161 anchor for the latest head.
func (w *Worker) Run(ctx context.Context, tenantID string) (*Head, error) {
	var headID string
	var leaves [][]byte
	var note string
	var size uint64
	err := pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('audittrail.treehead:' || $1::text))`, tenantID).Scan(&locked); err != nil || !locked {
			return err
		}
		var last int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(tree_size),0) FROM tree_heads WHERE tenant_id=$1`, tenantID).Scan(&last); err != nil {
			return err
		}
		var n int64
		if err := tx.QueryRow(ctx, `SELECT last_seq FROM chain_state WHERE tenant_id=$1`, tenantID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		var err error
		if leaves, err = Leaves(ctx, tx, tenantID, n); err != nil {
			return err
		}
		size = uint64(n) // #nosec G115 -- positive
		if n == last {
			return tx.QueryRow(ctx, `SELECT id, note FROM tree_heads WHERE tenant_id=$1 AND tree_size=$2`, tenantID, n).Scan(&headID, &note)
		}
		// Re-verify every row added since the last head before signing.
		if err := verifyRange(ctx, tx, tenantID, last+1, n, leaves); err != nil {
			return err
		}
		root := merkle.RootRaw(leaves)
		var keyID, sealed string
		if err := tx.QueryRow(ctx, `SELECT key_id, private_key_enc FROM signing_keys WHERE tenant_id=$1 AND retired_at IS NULL`, tenantID).Scan(&keyID, &sealed); err != nil {
			return fmt.Errorf("active signing key: %w", err)
		}
		priv, err := keys.OpenSigningKey(w.Master, tenantID, keyID, sealed)
		if err != nil {
			return err
		}
		cp := tlog.Checkpoint{Origin: tlog.Origin(tenantID), Size: size, Root: root}
		note = string(tlog.SignCheckpoint(cp, tlog.Signer{Name: cp.Origin, Priv: priv}))
		return tx.QueryRow(ctx, `INSERT INTO tree_heads (tenant_id, tree_size, root_hash, head_hash, note, key_id, tsa_status)
			VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, tenantID, n, hex.EncodeToString(root), hex.EncodeToString(leaves[n-1]),
			note, keyID, map[bool]string{true: "pending", false: "disabled"}[w.TSA != nil]).Scan(&headID)
	})
	if err != nil || headID == "" {
		return nil, err
	}
	h := &Head{TenantID: tenantID, TreeSize: size, RootHex: hex.EncodeToString(merkle.RootRaw(leaves)), Note: note}
	h.Note, h.Witnesses = w.cosign(ctx, tenantID, headID, note, leaves)
	h.Anchored = w.anchor(ctx, headID, h.Note)
	return h, nil
}

func verifyRange(ctx context.Context, tx pgx.Tx, tenantID string, from, to int64, leaves [][]byte) error {
	evs, err := ledger.ListEvents(ctx, tx, tenantID, ledger.Filter{FromSeq: from, ToSeq: to})
	if err != nil {
		return err
	}
	pubs := map[string]string{}
	rows, err := tx.Query(ctx, `SELECT key_id, public_key FROM signing_keys WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k, p string
		rows.Scan(&k, &p)
		pubs[k] = p
	}
	rows.Close()
	for _, e := range evs {
		if hex.EncodeToString(leaves[e.Seq-1]) != e.Hash {
			return &IntegrityError{tenantID, e.Seq, "leaf differs from row"}
		}
		if e.Seq > 1 && hex.EncodeToString(leaves[e.Seq-2]) != e.PreviousHash {
			return &IntegrityError{tenantID, e.Seq, "previous_hash does not link"}
		}
		if h, err := e.RecomputeHash(); err != nil || h != e.Hash {
			return &IntegrityError{tenantID, e.Seq, "content does not match hash"}
		}
		if !e.PayloadIntact() {
			return &IntegrityError{tenantID, e.Seq, "payload does not match payload_hash"}
		}
		if pk, ok := pubs[e.KeyID]; !ok || !keys.Verify(pk, e.SigningMessage(), e.Signature) {
			return &IntegrityError{tenantID, e.Seq, "bad row signature"}
		}
	}
	return nil
}

// cosign asks every configured witness to cosign note, sending the right
// consistency proof from the size it last cosigned.
func (w *Worker) cosign(ctx context.Context, tenantID, headID, note string, leaves [][]byte) (string, []string) {
	n, err := tlog.ParseNote([]byte(note))
	if err != nil {
		return note, nil
	}
	have := map[string]bool{}
	for _, s := range n.Sigs {
		have[s.Name] = true
	}
	size := uint64(len(leaves))
	var got []string
	for _, wc := range w.Witnesses {
		if have[wc.Name] {
			got = append(got, wc.Name)
			continue
		}
		var old uint64
		_ = w.Pool.QueryRow(ctx, `SELECT tree_size FROM witness_state WHERE tenant_id=$1 AND witness=$2`, tenantID, wc.Name).Scan(&old)
		for attempt := 0; attempt < 3; attempt++ {
			if old > size {
				break
			}
			var proof [][]byte
			if old > 0 && old < size {
				proof, _ = merkle.ConsistencyProof(leaves, int(old)) // #nosec G115 -- old < size
			}
			lines, err := witness.AddCheckpoint(ctx, w.HTTP, wc.URL, old, proof, []byte(note))
			var conflict *witness.ErrConflict
			if errors.As(err, &conflict) {
				old = conflict.Size
				continue
			}
			if err != nil {
				w.logf("witness refused or unreachable", "witness", wc.Name, "err", err)
				break
			}
			// The response holds only this witness's cosignature lines, named
			// by its key name (which need not match the configured name).
			// Count the witness only if a cosignature actually arrived; the
			// verifier decides which keys to trust.
			added := 0
			for _, l := range strings.SplitAfter(lines, "\n") {
				if strings.HasPrefix(l, tlog.Dash) && strings.HasSuffix(l, "\n") {
					if !strings.Contains(note, l) {
						note += l
					}
					added++
				}
			}
			if added == 0 {
				w.logf("witness returned no cosignature", "witness", wc.Name)
				break
			}
			got = append(got, wc.Name)
			_, _ = w.Pool.Exec(ctx, `INSERT INTO witness_state (tenant_id, witness, tree_size) VALUES ($1,$2,$3)
				ON CONFLICT (tenant_id, witness) DO UPDATE SET tree_size=$3, updated_at=NOW()`, tenantID, wc.Name, size)
			break
		}
	}
	_, _ = w.Pool.Exec(ctx, `UPDATE tree_heads SET note=$2, witnesses=$3 WHERE id=$1`, headID, note, got)
	return note, got
}

func (w *Worker) anchor(ctx context.Context, headID, note string) bool {
	if w.TSA == nil {
		return false
	}
	var status string
	_ = w.Pool.QueryRow(ctx, `SELECT tsa_status FROM tree_heads WHERE id=$1`, headID).Scan(&status)
	if status == "anchored" {
		return true
	}
	n, err := tlog.ParseNote([]byte(note))
	if err != nil {
		return false
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tok, err := w.TSA.Stamp(sctx, []byte(n.Text))
	if err != nil {
		w.logf("TSA unavailable; will retry", "err", err)
		return false
	}
	b64 := base64.StdEncoding.EncodeToString(tok)
	res, err := anchor.Verify(b64, []byte(n.Text), nil)
	if err != nil {
		return false
	}
	_, err = w.Pool.Exec(ctx, `UPDATE tree_heads SET tsa_token=$2, tsa_status='anchored', tsa_authority=$3, tsa_time=$4 WHERE id=$1`,
		headID, b64, res.Authority, res.Time)
	return err == nil
}

// RunAll processes every tenant.
func (w *Worker) RunAll(ctx context.Context) ([]*Head, []error) {
	rows, err := w.Pool.Query(ctx, `SELECT tenant_id FROM chain_state WHERE last_seq > 0`)
	if err != nil {
		return nil, []error{err}
	}
	ids, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	var heads []*Head
	var errs []error
	for _, id := range ids {
		h, err := w.Run(ctx, id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if h != nil {
			heads = append(heads, h)
		}
	}
	return heads, errs
}
