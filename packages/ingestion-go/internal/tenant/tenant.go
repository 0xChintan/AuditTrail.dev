// Package tenant manages tenants, API keys and signing keys.
package tenant

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
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
	Version    int        `json:"version"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

const apiKeyCols = `id, tenant_id, name, prefix, key_version, scopes, expires_at, created_at, last_used_at, revoked_at`

func scanKey(r pgx.Row) (APIKey, error) {
	var k APIKey
	var v int16
	err := r.Scan(&k.ID, &k.TenantID, &k.Name, &k.Prefix, &v, &k.Scopes, &k.ExpiresAt, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
	k.Version = int(v)
	return k, err
}

// DefaultScopes for new keys.
var DefaultScopes = []string{"events:write", "events:read", "export:read"}

// AllScopes that may be granted.
var AllScopes = map[string]bool{"events:write": true, "events:read": true, "export:read": true, "subjects:erase": true, "pii:read": true, "otlp:write": true}

type PublicKey struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm"`
	PublicKey string     `json:"public_key"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at"`
}

var ErrNotFound = errors.New("not found")
var ErrUnauthorized = errors.New("invalid or revoked API key")

// Store: control-plane operations (onboarding, keys, settings) run on the
// Control pool (audittrail_control); tenant-scoped reads run on the App pool
// under row-level security.
type Store struct {
	Pool    *pgxpool.Pool // app role, RLS-scoped
	Control *pgxpool.Pool // control-plane role
	Master  *keys.MasterKey
	Pepper  keys.Pepper
}

func (s *Store) ctl() *pgxpool.Pool {
	if s.Control != nil {
		return s.Control
	}
	return s.Pool
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
	tx, err := s.ctl().Begin(ctx)
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
	full, ak, err := s.insertAPIKey(ctx, tx, t.ID, "default", DefaultScopes, nil)
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

func (s *Store) insertAPIKey(ctx context.Context, tx pgx.Tx, tenantID, name string, scopes []string, expires *time.Time) (string, APIKey, error) {
	if len(s.Pepper) == 0 {
		return "", APIKey{}, errors.New("AUDITTRAIL_KEY_PEPPER not configured")
	}
	full, prefix, mac, pub := keys.NewAPIKeyV2(s.Pepper)
	k, err := scanKey(tx.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, name, prefix, key_version, key_hmac, sign_pub, scopes, expires_at)
		VALUES ($1,$2,$3,2,$4,$5,$6,$7) RETURNING `+apiKeyCols, tenantID, name, prefix, mac, pub, scopes, expires))
	return full, k, err
}

// Get is a control-plane read (any tenant).
func (s *Store) Get(ctx context.Context, id string) (Tenant, error) {
	return scanTenant(s.ctl().QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id=$1`, id))
}

// GetTx reads the tenant inside a tenant-scoped (RLS) transaction.
func GetTx(ctx context.Context, tx pgx.Tx, id string) (Tenant, error) {
	return scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id=$1`, id))
}

func (s *Store) List(ctx context.Context) ([]Tenant, error) {
	rows, err := s.ctl().Query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY created_at`)
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

// Credential is an authenticated API key.
type Credential struct {
	KeyID    string
	TenantID string
	Version  int
	Scopes   []string
	SignPub  ed25519.PublicKey // v2 keys only
}

func (c Credential) Has(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Authenticate resolves an API key (v1 at_… or v2 at2_…). Stored values are
// compared in constant time; revoked and expired keys fail identically.
func (s *Store) Authenticate(ctx context.Context, full string) (Credential, error) {
	ver, prefix, ok := keys.ParseAnyAPIKey(full)
	if !ok {
		return Credential{}, ErrUnauthorized
	}
	var c Credential
	var kv int16
	var hash, mac, pub *string
	var expires, revoked *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT id, tenant_id, key_version, key_hash, key_hmac, scopes, expires_at, revoked_at, sign_pub FROM auth_lookup_key($1)`, prefix).
		Scan(&c.KeyID, &c.TenantID, &kv, &hash, &mac, &c.Scopes, &expires, &revoked, &pub)
	if err != nil || int(kv) != ver {
		return Credential{}, ErrUnauthorized
	}
	c.Version = int(kv)
	switch c.Version {
	case 1:
		if hash == nil || !keys.HashesEqual(*hash, keys.HashAPIKey(full)) {
			return Credential{}, ErrUnauthorized
		}
	case 2:
		if mac == nil || len(s.Pepper) == 0 || !keys.HashesEqual(*mac, s.Pepper.HMAC(full)) {
			return Credential{}, ErrUnauthorized
		}
		if pub != nil {
			if b, err := base64.StdEncoding.DecodeString(*pub); err == nil && len(b) == ed25519.PublicKeySize {
				c.SignPub = b
			}
		}
	}
	if revoked != nil || (expires != nil && time.Now().After(*expires)) {
		return Credential{}, ErrUnauthorized
	}
	return c, nil
}

// Touch records key usage (throttled by the caller's cadence).
func Touch(ctx context.Context, tx pgx.Tx, keyID string) {
	_, _ = tx.Exec(ctx, `UPDATE api_keys SET last_used_at=NOW() WHERE id=$1 AND (last_used_at IS NULL OR last_used_at < NOW() - interval '1 minute')`, keyID)
}

func (s *Store) CreateAPIKey(ctx context.Context, tenantID, name string, scopes []string, expires *time.Time) (string, APIKey, error) {
	for _, sc := range scopes {
		if !AllScopes[sc] {
			return "", APIKey{}, fmt.Errorf("unknown scope %q", sc)
		}
	}
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	tx, err := s.ctl().Begin(ctx)
	if err != nil {
		return "", APIKey{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := s.Get(ctx, tenantID); err != nil {
		return "", APIKey{}, err
	}
	full, k, err := s.insertAPIKey(ctx, tx, tenantID, name, scopes, expires)
	if err != nil {
		return "", APIKey{}, err
	}
	return full, k, tx.Commit(ctx)
}

func (s *Store) ListAPIKeys(ctx context.Context, tenantID string) ([]APIKey, error) {
	rows, err := s.ctl().Query(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE tenant_id=$1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, tenantID, keyID string) error {
	ct, err := s.ctl().Exec(ctx, `UPDATE api_keys SET revoked_at=NOW() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenantID, keyID)
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
	return scanTenant(s.ctl().QueryRow(ctx, `UPDATE tenants SET
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
	tx, err := s.ctl().Begin(ctx)
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
	rows, err := s.ctl().Query(ctx, `SELECT key_id, algorithm, public_key, created_at, retired_at
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
