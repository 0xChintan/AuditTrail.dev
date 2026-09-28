package export

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"

	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
	"audittrail.dev/packages/ingestion-go/internal/tenant"
	"audittrail.dev/packages/ingestion-go/internal/tlog"
	"audittrail.dev/packages/ingestion-go/internal/verify2"
)

// LogKeys renders a tenant's signing keys as C2SP vkeys.
func LogKeys(tenantID string, pubs []tenant.PublicKey) []verify2.KeyInfo {
	out := []verify2.KeyInfo{}
	for _, k := range pubs {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			continue
		}
		ki := verify2.KeyInfo{KeyID: k.KeyID, PublicKey: k.PublicKey, Vkey: tlog.Vkey(tlog.Origin(tenantID), tlog.TypeEd25519, pub),
			CreatedAt: k.CreatedAt.UTC().Format(time.RFC3339)}
		if k.RetiredAt != nil {
			s := k.RetiredAt.UTC().Format(time.RFC3339)
			ki.RetiredAt = &s
		}
		out = append(out, ki)
	}
	return out
}

// BuildBundleV2 assembles an offline-verifiable evidence bundle: rows
// [from..to] (widened to end at a signed tree head when one exists), a
// compact-range commitment to all earlier leaves, the covering tree heads
// with their cosignatures and RFC 3161 tokens, and consistency proofs.
func BuildBundleV2(ctx context.Context, q ledger.Querier, t tenant.Tenant, pubs []tenant.PublicKey, r Range) (*verify2.Bundle, error) {
	b := &verify2.Bundle{Format: verify2.Format, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Tenant: map[string]any{"id": t.ID, "name": t.Name, "retention_days": t.RetentionDays, "legal_hold": t.LegalHold},
		Events: []ledger.Record{}, TreeHeads: []verify2.TreeHead{}, Consistency: []verify2.Consistency{}}
	b.Log.Origin = tlog.Origin(t.ID)
	b.Log.Keys = LogKeys(t.ID, pubs)
	b.Prefix.Hashes = []string{}

	var last int64
	if err := q.QueryRow(ctx, `SELECT last_seq FROM chain_state WHERE tenant_id=$1`, t.ID).Scan(&last); err != nil {
		return nil, err
	}
	if last == 0 {
		return b, nil
	}
	lo, hi := r.FromSeq, r.ToSeq
	if r.From != nil || r.To != nil {
		var mn, mx *int64
		if err := q.QueryRow(ctx, `SELECT min(seq), max(seq) FROM agent_events WHERE tenant_id=$1
			AND ($2::timestamptz IS NULL OR timestamp >= $2) AND ($3::timestamptz IS NULL OR timestamp <= $3)`, t.ID, r.From, r.To).Scan(&mn, &mx); err != nil {
			return nil, err
		}
		if mn == nil {
			return b, nil
		}
		lo, hi = max(lo, *mn), *mx
	}
	var firstLive int64
	_ = q.QueryRow(ctx, `SELECT COALESCE(min(seq), 1) FROM agent_events WHERE tenant_id=$1`, t.ID).Scan(&firstLive)
	if lo < firstLive {
		lo = firstLive
	}
	if hi <= 0 || hi > last {
		hi = last
	}
	// Widen the end to the next signed head so the rows reproduce a signed root.
	var next *int64
	_ = q.QueryRow(ctx, `SELECT min(tree_size) FROM tree_heads WHERE tenant_id=$1 AND tree_size >= $2`, t.ID, hi).Scan(&next)
	if next != nil {
		hi = *next
	}
	if hi-lo+1 > MaxBundleRows {
		lo = hi - MaxBundleRows + 1
	}

	// A tampered log (a row deleted outside retention) must still export:
	// the bundle carries what exists and the verifier names the gap. The
	// range is widened back to the first missing seq so the prefix
	// commitment covers only leaves that are present.
	leaves, missing, err := gapTolerantLeaves(ctx, q, t.ID, hi)
	if err != nil {
		return nil, err
	}
	if missing > 0 && missing < lo {
		lo = missing
	}
	// Compact range over leaves [0, lo-1): O(log n) hashes commit to the prefix.
	rf := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	cr := rf.NewEmptyRange(0)
	for i := int64(0); i < lo-1; i++ {
		if err := cr.Append(rfc6962.DefaultHasher.HashLeaf(leaves[i]), nil); err != nil {
			return nil, err
		}
	}
	b.Prefix.Size = uint64(lo - 1) // #nosec G115 -- lo >= 1
	for _, h := range cr.Hashes() {
		b.Prefix.Hashes = append(b.Prefix.Hashes, hex.EncodeToString(h))
	}

	evs, err := ledger.ListEvents(ctx, q, t.ID, ledger.Filter{FromSeq: lo, ToSeq: hi})
	if err != nil {
		return nil, err
	}
	b.Events = evs

	rows, err := q.Query(ctx, `SELECT tree_size, note, tsa_token, tsa_status FROM tree_heads
		WHERE tenant_id=$1 AND tree_size BETWEEN $2 AND $3 ORDER BY tree_size DESC LIMIT 50`, t.ID, lo, hi)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var th verify2.TreeHead
		if err := rows.Scan(&th.TreeSize, &th.Note, &th.TSAToken, &th.TSAStatus); err != nil {
			rows.Close()
			return nil, err
		}
		b.TreeHeads = append([]verify2.TreeHead{th}, b.TreeHeads...)
	}
	rows.Close()
	for i := 1; i < len(b.TreeHeads); i++ {
		from, to := b.TreeHeads[i-1].TreeSize, b.TreeHeads[i].TreeSize
		if missing > 0 && uint64(missing) <= to { // #nosec G115 -- missing > 0
			continue // no honest proof exists over a hole; verification reports it
		}
		p, err := merkle.ConsistencyProof(leaves[:to], int(from)) // #nosec G115 -- bounded by leaves
		if err != nil {
			return nil, err
		}
		c := verify2.Consistency{From: from, To: to, Proof: []string{}}
		for _, h := range p {
			c.Proof = append(c.Proof, hex.EncodeToString(h))
		}
		b.Consistency = append(b.Consistency, c)
	}
	return b, nil
}

// gapTolerantLeaves returns leaf hashes 1..size (nil where a row is missing)
// and the first missing seq (0 if none).
func gapTolerantLeaves(ctx context.Context, q ledger.Querier, tenantID string, size int64) ([][]byte, int64, error) {
	rows, err := q.Query(ctx, `SELECT seq, hash FROM agent_events WHERE tenant_id=$1 AND seq <= $2
		UNION ALL SELECT seq, hash FROM purged_leaves WHERE tenant_id=$1 AND seq <= $2`, tenantID, size)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([][]byte, size)
	for rows.Next() {
		var seq int64
		var h string
		if err := rows.Scan(&seq, &h); err != nil {
			return nil, 0, err
		}
		if b, err := hex.DecodeString(h); err == nil && len(b) == 32 && seq >= 1 && seq <= size {
			out[seq-1] = b
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	for i, l := range out {
		if l == nil {
			return out, int64(i) + 1, nil
		}
	}
	return out, 0, nil
}
