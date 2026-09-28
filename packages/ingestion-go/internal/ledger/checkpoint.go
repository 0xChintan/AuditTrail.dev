package ledger

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Checkpoint is a signed Merkle checkpoint over a contiguous seq range.
type Checkpoint struct {
	ID                  string  `json:"id"`
	TenantID            string  `json:"tenant_id"`
	FirstSeq            int64   `json:"first_seq"`
	LastSeq             int64   `json:"last_seq"`
	RowCount            int64   `json:"row_count"`
	MerkleRoot          string  `json:"merkle_root"`
	HeadHash            string  `json:"head_hash"`
	PrevCheckpointHead  string  `json:"prev_checkpoint_head"`
	Statement           string  `json:"statement"`
	Signature           string  `json:"signature"`
	KeyID               string  `json:"key_id"`
	ExternalAnchorProof *string `json:"external_anchor_proof"`
	AnchorStatus        string  `json:"anchor_status"`
	AnchorAuthority     *string `json:"anchor_authority"`
	AnchoredAt          *string `json:"anchored_at"`
	AnchorError         *string `json:"anchor_error,omitempty"`
	CreatedAt           string  `json:"created_at"`
}

const CheckpointColumns = `id, tenant_id, first_seq, last_seq, row_count, merkle_root, head_hash,
	prev_checkpoint_head, statement, signature, key_id, external_anchor_proof, anchor_status,
	anchor_authority, anchored_at, anchor_error, created_at`

func ScanCheckpoint(row pgx.Row) (Checkpoint, error) {
	var c Checkpoint
	var anchoredAt *time.Time
	var created time.Time
	err := row.Scan(&c.ID, &c.TenantID, &c.FirstSeq, &c.LastSeq, &c.RowCount, &c.MerkleRoot, &c.HeadHash,
		&c.PrevCheckpointHead, &c.Statement, &c.Signature, &c.KeyID, &c.ExternalAnchorProof, &c.AnchorStatus,
		&c.AnchorAuthority, &anchoredAt, &c.AnchorError, &created)
	if err != nil {
		return c, err
	}
	if anchoredAt != nil {
		s := anchoredAt.UTC().Format(time.RFC3339Nano)
		c.AnchoredAt = &s
	}
	c.CreatedAt = created.UTC().Format(time.RFC3339Nano)
	return c, nil
}

func ListCheckpoints(ctx context.Context, q Querier, tenantID string, fromSeq, toSeq int64, limit int) ([]Checkpoint, error) {
	sql := `SELECT ` + CheckpointColumns + ` FROM checkpoints WHERE tenant_id=$1
		AND ($2 = 0 OR last_seq >= $2) AND ($3 = 0 OR first_seq <= $3) ORDER BY first_seq`
	args := []any{tenantID, fromSeq, toSeq}
	if limit > 0 {
		sql += ` DESC LIMIT $4`
		args = append(args, limit)
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Checkpoint{}
	for rows.Next() {
		c, err := ScanCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func GetCheckpoint(ctx context.Context, q Querier, tenantID, id string) (Checkpoint, error) {
	c, err := ScanCheckpoint(q.QueryRow(ctx, `SELECT `+CheckpointColumns+` FROM checkpoints WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

// CheckpointCovering returns the checkpoint whose range contains seq.
func CheckpointCovering(ctx context.Context, q Querier, tenantID string, seq int64) (Checkpoint, error) {
	c, err := ScanCheckpoint(q.QueryRow(ctx, `SELECT `+CheckpointColumns+` FROM checkpoints WHERE tenant_id=$1 AND first_seq <= $2 AND last_seq >= $2`, tenantID, seq))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}
