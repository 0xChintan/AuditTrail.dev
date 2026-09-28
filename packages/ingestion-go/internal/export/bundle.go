// Package export builds evidence bundles and compliance reports.
package export

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/tenant"
	"audittrail.dev/packages/ingestion-go/internal/verify"
)

// Range selects rows; zero values mean unbounded.
type Range struct {
	From, To       *time.Time
	FromSeq, ToSeq int64
}

// MaxBundleRows bounds a single export.
const MaxBundleRows = 250_000

// BuildBundle collects the rows in range, widened to whole checkpoint
// boundaries so every covering Merkle root can be recomputed, plus the
// checkpoint that ends just before the first row (the chain-start anchor
// when earlier rows are out of range or purged), and all public keys.
func BuildBundle(ctx context.Context, pool *pgxpool.Pool, t tenant.Tenant, pubs []tenant.PublicKey, r Range) (verify.Bundle, error) {
	b := verify.Bundle{Format: verify.BundleFormat, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Tenant: verify.BundleTenant{ID: t.ID, Name: t.Name, RetentionDays: t.RetentionDays, LegalHold: t.LegalHold},
		Events: []ledger.Record{}, Checkpoints: []ledger.Checkpoint{}}
	for _, k := range pubs {
		pk := verify.PublicKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey, CreatedAt: k.CreatedAt.UTC().Format(time.RFC3339)}
		if k.RetiredAt != nil {
			s := k.RetiredAt.UTC().Format(time.RFC3339)
			pk.RetiredAt = &s
		}
		b.PublicKeys = append(b.PublicKeys, pk)
	}

	lo, hi := r.FromSeq, r.ToSeq
	if r.From != nil || r.To != nil {
		var mn, mx *int64
		if err := pool.QueryRow(ctx, `SELECT min(seq), max(seq) FROM agent_events WHERE tenant_id=$1
			AND ($2::timestamptz IS NULL OR timestamp >= $2) AND ($3::timestamptz IS NULL OR timestamp <= $3)`,
			t.ID, r.From, r.To).Scan(&mn, &mx); err != nil {
			return b, err
		}
		if mn == nil {
			return b, nil // nothing in the window
		}
		// Rows are seq-ordered by insertion; a time window maps to a seq span.
		lo, hi = max(lo, *mn), *mx
		if r.ToSeq > 0 {
			hi = min(hi, r.ToSeq)
		}
	}
	if lo <= 0 {
		if err := pool.QueryRow(ctx, `SELECT COALESCE(min(seq),1) FROM agent_events WHERE tenant_id=$1`, t.ID).Scan(&lo); err != nil {
			return b, err
		}
	}
	if hi <= 0 {
		if err := pool.QueryRow(ctx, `SELECT last_seq FROM chain_state WHERE tenant_id=$1`, t.ID).Scan(&hi); err != nil {
			return b, err
		}
	}
	// Widen to checkpoint boundaries.
	if cp, err := ledger.CheckpointCovering(ctx, pool, t.ID, lo); err == nil {
		lo = cp.FirstSeq
	}
	if cp, err := ledger.CheckpointCovering(ctx, pool, t.ID, hi); err == nil {
		hi = cp.LastSeq
	}
	if hi-lo+1 > MaxBundleRows {
		lo = hi - MaxBundleRows + 1
		if cp, err := ledger.CheckpointCovering(ctx, pool, t.ID, lo); err == nil && cp.FirstSeq < lo {
			lo = cp.LastSeq + 1
		}
	}
	evs, err := ledger.ListEvents(ctx, pool, t.ID, ledger.Filter{FromSeq: lo, ToSeq: hi})
	if err != nil {
		return b, err
	}
	b.Events = evs
	from := max(lo-1, 1)
	cps, err := ledger.ListCheckpoints(ctx, pool, t.ID, from, hi, 0)
	if err != nil {
		return b, err
	}
	b.Checkpoints = cps
	return b, nil
}
