// Package tenant manages tenants, API keys and signing keys.
package tenant

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"audittrail.dev/packages/ingestion-go/internal/keys"
)

type Tenant struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	RetentionDays   int        `json:"retention_days"`
	LegalHold       bool       `json:"legal_hold"`
	LegalHoldReason *string    `json:"legal_hold_reason"`
	LegalHoldSetAt  *time.Time `json:"legal_hold_set_at"`
	RateLimitRPS    int        `json:"rate_limit_rps"`
	RateLimitBurst  int        `json:"rate_limit_burst"`
	CreatedAt       time.Time  `json:"created_at"`
}

type APIKey struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

type PublicKey struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm"`
	PublicKey string     `json:"public_key"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at"`
}

var ErrNotFound = errors.New("not found")
var ErrUnauthorized = errors.New("invalid or revoked API key")

type Store struct {
	Pool   *pgxpool.Pool
	Master *keys.MasterKey
}

const tenantCols = `id, name, retention_days, legal_hold, legal_hold_reason, legal_hold_set_at,
	rate_limit_rps, rate_limit_burst, created_at`

func scanTenant(r pgx.Row) (Tenant, error) {
	var t Tenant
	err := r.Scan(&t.ID, &t.Name, &t.RetentionDays, &t.LegalHold, &t.LegalHoldReason, &t.LegalHoldSetAt,
		&t.RateLimitRPS, &t.RateLimitBurst, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

// CreateOptions tunes a new tenant; zero values take DB defaults.
type CreateOptions struct {
	Name           string
	RetentionDays  int
	RateLimitRPS   int
	RateLimitBurst int
}

// Create onboards a tenant: tenant row, genesis chain_state, Ed25519
// signing key and a first API key — atomically. The plaintext API key is
// returned exactly once.
func (s *Store) Create(ctx context.Context, o CreateOptions) (Tenant, string, APIKey, PublicKey, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Tenant{}, "", APIKey{}, PublicKey{}, err
	}
	defer tx.Rollback(ctx)
	t, err := scanTenant(tx.QueryRow(ctx, `INSERT INTO tenants (name, retention_days, rate_limit_rps, rate_limit_burst)
		VALUES ($1, COALESCE(NULLIF($2,0),183), COALESCE(NULLIF($3,0),100), COALESCE(NULLIF($4,0),200))
		RETURNING `+tenantCols, o.Name, o.RetentionDays, o.RateLimitRPS, o.RateLimitBurst))
	if err != nil {
		return Tenant{}, "", APIKey{}, PublicKey{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO chain_state (tenant_id) VALUES ($1)`, t.ID); err != nil {
		return Tenant{}, "", APIKey{}, PublicKey{}, err
	}
	pk, err := s.insertSigningKey(ctx, tx, t.ID)
	if err != nil {
		return Tenant{}, "", APIKey{}, PublicKey{}, err
	}
	full, ak, err := s.insertAPIKey(ctx, tx, t.ID, "default")
	if err != nil {
		return Tenant{}, "", APIKey{}, PublicKey{}, err
	}
	return t, full, ak, pk, tx.Commit(ctx)
}

func (s *Store) insertSigningKey(ctx context.Context, tx pgx.Tx, tenantID string) (PublicKey, error) {
	sk, err := keys.NewSigningKey(s.Master, tenantID)
	if err != nil {
		return PublicKey{}, err
	}
	var pk PublicKey
	err = tx.QueryRow(ctx, `INSERT INTO signing_keys (key_id, tenant_id, public_key, private_key_enc)
		VALUES ($1,$2,$3,$4) RETURNING key_id, algorithm, public_key, created_at, retired_at`,
		sk.KeyID, tenantID, sk.PublicB64, sk.SealedPriv).Scan(&pk.KeyID, &pk.Algorithm, &pk.PublicKey, &pk.CreatedAt, &pk.RetiredAt)
	return pk, err
}

func (s *Store) insertAPIKey(ctx context.Context, tx pgx.Tx, tenantID, name string) (string, APIKey, error) {
	full, prefix, hash := keys.NewAPIKey()
	var k APIKey
	err := tx.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, name, prefix, key_hash) VALUES ($1,$2,$3,$4)
		RETURNING id, tenant_id, name, prefix, created_at, last_used_at, revoked_at`,
		tenantID, name, prefix, hash).Scan(&k.ID, &k.TenantID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
	return full, k, err
}

func (s *Store) Get(ctx context.Context, id string) (Tenant, error) {
	return scanTenant(s.Pool.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id=$1`, id))
}

func (s *Store) List(ctx context.Context) ([]Tenant, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Authenticate resolves an API key to its tenant. Keys are looked up by
// prefix and compared by constant-time hash comparison.
func (s *Store) Authenticate(ctx context.Context, full string) (Tenant, string, error) {
	prefix, ok := keys.ParseAPIKey(full)
	if !ok {
		return Tenant{}, "", ErrUnauthorized
	}
	var keyID, hash, tenantID string
	var revoked *time.Time
	var lastUsed *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT id, key_hash, tenant_id, revoked_at, last_used_at FROM api_keys WHERE prefix=$1`, prefix).
		Scan(&keyID, &hash, &tenantID, &revoked, &lastUsed)
	if err != nil || revoked != nil || !keys.HashesEqual(hash, keys.HashAPIKey(full)) {
		return Tenant{}, "", ErrUnauthorized
	}
	if lastUsed == nil || time.Since(*lastUsed) > time.Minute {
		_, _ = s.Pool.Exec(ctx, `UPDATE api_keys SET last_used_at=NOW() WHERE id=$1`, keyID)
	}
	t, err := s.Get(ctx, tenantID)
	return t, keyID, err
}

func (s *Store) CreateAPIKey(ctx context.Context, tenantID, name string) (string, APIKey, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", APIKey{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := s.Get(ctx, tenantID); err != nil {
		return "", APIKey{}, err
	}
	full, k, err := s.insertAPIKey(ctx, tx, tenantID, name)
	if err != nil {
		return "", APIKey{}, err
	}
	return full, k, tx.Commit(ctx)
}

func (s *Store) ListAPIKeys(ctx context.Context, tenantID string) ([]APIKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, tenant_id, name, prefix, created_at, last_used_at, revoked_at
		FROM api_keys WHERE tenant_id=$1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, tenantID, keyID string) error {
	ct, err := s.Pool.Exec(ctx, `UPDATE api_keys SET revoked_at=NOW() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenantID, keyID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Settings is a partial update; nil fields are left unchanged.
type Settings struct {
	Name            *string `json:"name"`
	RetentionDays   *int    `json:"retention_days"`
	LegalHold       *bool   `json:"legal_hold"`
	LegalHoldReason *string `json:"legal_hold_reason"`
	RateLimitRPS    *int    `json:"rate_limit_rps"`
	RateLimitBurst  *int    `json:"rate_limit_burst"`
}

func (s *Store) Update(ctx context.Context, id string, p Settings) (Tenant, error) {
	return scanTenant(s.Pool.QueryRow(ctx, `UPDATE tenants SET
		name = COALESCE($2, name),
		retention_days = COALESCE($3, retention_days),
		legal_hold = COALESCE($4, legal_hold),
		legal_hold_reason = CASE WHEN $4::bool IS NULL THEN legal_hold_reason
		                         WHEN $4::bool THEN $5 ELSE NULL END,
		legal_hold_set_at = CASE WHEN $4::bool IS NULL THEN legal_hold_set_at
		                         WHEN $4::bool AND NOT legal_hold THEN NOW()
		                         WHEN $4::bool THEN legal_hold_set_at ELSE NULL END,
		rate_limit_rps = COALESCE($6, rate_limit_rps),
		rate_limit_burst = COALESCE($7, rate_limit_burst)
		WHERE id=$1 RETURNING `+tenantCols,
		id, p.Name, p.RetentionDays, p.LegalHold, p.LegalHoldReason, p.RateLimitRPS, p.RateLimitBurst))
}

// RotateSigningKey retires the active key and creates a new one. Old rows
// remain verifiable: each row records its key_id and retired public keys
// stay published.
func (s *Store) RotateSigningKey(ctx context.Context, tenantID string) (PublicKey, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return PublicKey{}, err
	}
	defer tx.Rollback(ctx)
	// Serialize against in-flight appends for this tenant.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM chain_state WHERE tenant_id=$1 FOR UPDATE`, tenantID); err != nil {
		return PublicKey{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE signing_keys SET retired_at=NOW() WHERE tenant_id=$1 AND retired_at IS NULL`, tenantID); err != nil {
		return PublicKey{}, err
	}
	pk, err := s.insertSigningKey(ctx, tx, tenantID)
	if err != nil {
		return PublicKey{}, err
	}
	return pk, tx.Commit(ctx)
}

func (s *Store) PublicKeys(ctx context.Context, tenantID string) ([]PublicKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT key_id, algorithm, public_key, created_at, retired_at
		FROM signing_keys WHERE tenant_id=$1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PublicKey{}
	for rows.Next() {
		var k PublicKey
		if err := rows.Scan(&k.KeyID, &k.Algorithm, &k.PublicKey, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
