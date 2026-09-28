// Package checkpoint batches new ledger rows into signed Merkle checkpoints
// and anchors them with an external RFC 3161 Time-Stamp Authority (Tasks
// 5.1 + 5.2).
package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"audittrail.dev/packages/ingestion-go/internal/anchor"
	"audittrail.dev/packages/ingestion-go/internal/canon"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
)

type Worker struct {
	Pool    *pgxpool.Pool
	Master  *keys.MasterKey
	TSA     *anchor.TSA // nil = anchoring disabled
	MaxRows int
	Log     *slog.Logger
	Now     func() time.Time
}

// IntegrityError means the rows about to be checkpointed don't verify. The
// worker refuses to sign them: a checkpoint must never bless tampered data.
type IntegrityError struct {
	TenantID string
	Seq      int64
	Reason   string
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("tenant %s: chain integrity failure at seq %d (%s); checkpoint withheld", e.TenantID, e.Seq, e.Reason)
}

type Result struct {
	Created   []ledger.Checkpoint
	Anchored  int
	Integrity []error
}

// RunOnce checkpoints every tenant with new rows, then anchors pending checkpoints.
func (w *Worker) RunOnce(ctx context.Context) (Result, error) {
	var res Result
	rows, err := w.Pool.Query(ctx, `SELECT tenant_id FROM chain_state c WHERE last_seq > COALESCE(
		(SELECT max(last_seq) FROM checkpoints k WHERE k.tenant_id = c.tenant_id), 0)`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	return w.run(ctx, tenants)
}

// RunTenant is RunOnce restricted to one tenant.
func (w *Worker) RunTenant(ctx context.Context, tenantID string) (Result, error) {
	return w.run(ctx, []string{tenantID})
}

func (w *Worker) run(ctx context.Context, tenants []string) (Result, error) {
	var res Result
	for _, t := range tenants {
		for {
			cp, err := w.CheckpointTenant(ctx, t)
			var ie *IntegrityError
			if errors.As(err, &ie) {
				res.Integrity = append(res.Integrity, err)
				w.logf(slog.LevelError, "INTEGRITY", "err", err)
				break
			}
			if err != nil {
				return res, err
			}
			if cp == nil {
				break
			}
			res.Created = append(res.Created, *cp)
			w.logf(slog.LevelInfo, "checkpoint created", "tenant", t, "first_seq", cp.FirstSeq, "last_seq", cp.LastSeq, "root", cp.MerkleRoot[:16])
		}
	}
	if w.TSA != nil {
		n, err := w.AnchorPending(ctx)
		res.Anchored = n
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

func (w *Worker) logf(level slog.Level, msg string, args ...any) {
	if w.Log != nil {
		w.Log.Log(context.Background(), level, msg, args...)
	}
}

// CheckpointTenant creates at most one checkpoint covering the rows after
// the tenant's last checkpoint (up to MaxRows). Returns nil if nothing new.
func (w *Worker) CheckpointTenant(ctx context.Context, tenantID string) (*ledger.Checkpoint, error) {
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('audittrail.checkpoint:' || $1::text))`, tenantID).Scan(&locked); err != nil {
		return nil, err
	}
	if !locked {
		return nil, nil // another worker is on it
	}
	lastSeq, prevHead := int64(0), canon.Genesis
	err = tx.QueryRow(ctx, `SELECT last_seq, head_hash FROM checkpoints WHERE tenant_id=$1 ORDER BY last_seq DESC LIMIT 1`, tenantID).Scan(&lastSeq, &prevHead)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var headSeq int64
	if err := tx.QueryRow(ctx, `SELECT last_seq FROM chain_state WHERE tenant_id=$1`, tenantID).Scan(&headSeq); err != nil {
		return nil, err
	}
	if headSeq <= lastSeq {
		return nil, nil
	}
	maxRows := int64(w.MaxRows)
	if maxRows <= 0 {
		maxRows = 10000
	}
	to := min(headSeq, lastSeq+maxRows)
	evs, err := ledger.ListEvents(ctx, tx, tenantID, ledger.Filter{FromSeq: lastSeq + 1, ToSeq: to})
	if err != nil {
		return nil, err
	}
	pubs, err := publicKeys(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}

	// Re-verify everything we are about to sign.
	prev := prevHead
	hashes := make([]string, 0, len(evs))
	for i, e := range evs {
		want := lastSeq + 1 + int64(i)
		if e.Seq != want {
			return nil, &IntegrityError{tenantID, want, "row missing"}
		}
		if e.PreviousHash != prev {
			return nil, &IntegrityError{tenantID, e.Seq, "previous_hash does not link"}
		}
		if h, err := e.RecomputeHash(); err != nil || h != e.Hash {
			return nil, &IntegrityError{tenantID, e.Seq, "content does not match hash"}
		}
		if !e.PayloadIntact() {
			return nil, &IntegrityError{tenantID, e.Seq, "payload does not match payload_hash"}
		}
		if pk, ok := pubs[e.KeyID]; !ok || !keys.Verify(pk, e.SigningMessage(), e.Signature) {
			return nil, &IntegrityError{tenantID, e.Seq, "bad row signature"}
		}
		hashes = append(hashes, e.Hash)
		prev = e.Hash
	}
	if int64(len(evs)) != to-lastSeq {
		return nil, &IntegrityError{tenantID, lastSeq + int64(len(evs)) + 1, "rows missing"}
	}

	root, err := merkle.RootHex(hashes)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	st := canon.CheckpointStatement{
		Type: canon.CheckpointType, TenantID: tenantID, FirstSeq: lastSeq + 1, LastSeq: to,
		RowCount: to - lastSeq, MerkleRoot: root, HeadHash: prev, PrevCheckpointHead: prevHead,
		CreatedAt: canon.FormatTime(now()),
	}
	stBytes, err := st.Bytes()
	if err != nil {
		return nil, err
	}
	var keyID, sealed string
	if err := tx.QueryRow(ctx, `SELECT key_id, private_key_enc FROM signing_keys WHERE tenant_id=$1 AND retired_at IS NULL`, tenantID).Scan(&keyID, &sealed); err != nil {
		return nil, fmt.Errorf("active signing key: %w", err)
	}
	priv, err := keys.OpenSigningKey(w.Master, tenantID, keyID, sealed)
	if err != nil {
		return nil, err
	}
	status := "pending"
	if w.TSA == nil {
		status = "disabled"
	}
	cp, err := ledger.ScanCheckpoint(tx.QueryRow(ctx, `INSERT INTO checkpoints
		(tenant_id, first_seq, last_seq, head_hash, prev_checkpoint_head, merkle_root, statement, signature, key_id, anchor_status, row_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+ledger.CheckpointColumns,
		tenantID, st.FirstSeq, st.LastSeq, st.HeadHash, st.PrevCheckpointHead, st.MerkleRoot, string(stBytes),
		keys.Sign(priv, stBytes), keyID, status, st.RowCount))
	if err != nil {
		return nil, err
	}
	return &cp, tx.Commit(ctx)
}

func publicKeys(ctx context.Context, q ledger.Querier, tenantID string) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT key_id, public_key FROM signing_keys WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, p string
		if err := rows.Scan(&k, &p); err != nil {
			return nil, err
		}
		out[k] = p
	}
	return out, rows.Err()
}

const maxAnchorAttempts = 48

// AnchorPending time-stamps checkpoints still awaiting an external anchor.
// Failures are retried on later runs; after maxAnchorAttempts the
// checkpoint is marked failed (it remains signed, just not anchored).
func (w *Worker) AnchorPending(ctx context.Context) (int, error) {
	rows, err := w.Pool.Query(ctx, `SELECT id, statement, anchor_attempts FROM checkpoints
		WHERE anchor_status='pending' ORDER BY created_at LIMIT 50`)
	if err != nil {
		return 0, err
	}
	type item struct {
		id, stmt string
		attempts int
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.stmt, &it.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	rows.Close()
	n := 0
	for _, it := range items {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		tok, err := w.TSA.Stamp(sctx, []byte(it.stmt))
		cancel()
		if err != nil {
			status := "pending"
			if it.attempts+1 >= maxAnchorAttempts {
				status = "failed"
			}
			w.logf(slog.LevelWarn, "anchor attempt failed", "checkpoint", it.id, "attempt", it.attempts+1, "err", err)
			if _, err := w.Pool.Exec(ctx, `UPDATE checkpoints SET anchor_attempts=anchor_attempts+1, anchor_error=$2, anchor_status=$3 WHERE id=$1`,
				it.id, err.Error(), status); err != nil {
				return n, err
			}
			continue
		}
		res, err := anchor.Verify(b64(tok), []byte(it.stmt), nil)
		if err != nil {
			return n, fmt.Errorf("TSA returned an unverifiable token: %w", err)
		}
		if _, err := w.Pool.Exec(ctx, `UPDATE checkpoints SET external_anchor_proof=$2, anchor_status='anchored',
			anchor_authority=$3, anchored_at=$4, anchor_attempts=anchor_attempts+1, anchor_error=NULL WHERE id=$1`,
			it.id, b64(tok), fmt.Sprintf("%s (%s)", res.Authority, w.TSA.URL), res.Time); err != nil {
			return n, err
		}
		w.logf(slog.LevelInfo, "checkpoint anchored", "checkpoint", it.id, "tsa", res.Authority, "time", res.Time)
		n++
	}
	return n, nil
}
