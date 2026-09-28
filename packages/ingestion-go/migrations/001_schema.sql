-- AuditTrail ledger schema (Appendix A + the columns later phases need).
-- Runs as audittrail_owner, which owns every object. Application roles never
-- own tables; that is what makes the grants in 002 enforceable.

CREATE TABLE tenants (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT NOT NULL,
    -- EU AI Act Art. 26(6) / Art. 19: logs kept at least six months.
    retention_days    INT NOT NULL DEFAULT 183 CHECK (retention_days >= 183),
    legal_hold        BOOLEAN NOT NULL DEFAULT FALSE,
    legal_hold_reason TEXT,
    legal_hold_set_at TIMESTAMPTZ,
    rate_limit_rps    INT NOT NULL DEFAULT 100 CHECK (rate_limit_rps > 0),
    rate_limit_burst  INT NOT NULL DEFAULT 200 CHECK (rate_limit_burst > 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id),
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL UNIQUE,
    key_hash     TEXT NOT NULL,            -- SHA-256 of the full key; plaintext never stored
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

-- One Ed25519 keypair per tenant (rotatable). Private seed is AES-GCM sealed
-- under AUDITTRAIL_MASTER_KEY, bound to tenant_id|key_id.
CREATE TABLE signing_keys (
    key_id          TEXT PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    algorithm       TEXT NOT NULL DEFAULT 'ed25519',
    public_key      TEXT NOT NULL,          -- base64, 32 bytes
    private_key_enc TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at      TIMESTAMPTZ
);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys(tenant_id) WHERE retired_at IS NULL;

-- Server-side genesis anchor / chain head, one row per tenant.
CREATE TABLE chain_state (
    tenant_id     UUID PRIMARY KEY REFERENCES tenants(id),
    previous_hash TEXT NOT NULL DEFAULT repeat('0', 64),
    last_seq      BIGINT NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE agent_events (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES chain_state(tenant_id),
    seq                BIGINT NOT NULL,        -- per-tenant, gapless
    timestamp          TIMESTAMPTZ NOT NULL,
    human_principal_id TEXT,                   -- nullable: fully autonomous actions
    agent_id           TEXT NOT NULL,
    model_id           TEXT,
    model_version      TEXT,
    delegation_chain   JSONB,                  -- nested tool-call ancestry
    action             TEXT NOT NULL,
    target_resource    TEXT NOT NULL,
    outcome            TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'error')),
    metadata           JSONB,
    previous_hash      TEXT NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
    hash               TEXT NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$'),
    signature          TEXT NOT NULL,          -- Ed25519 over "audittrail.event.v1\n" || hash
    key_id             TEXT NOT NULL REFERENCES signing_keys(key_id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, seq),
    CHECK (seq > 0)
);

CREATE INDEX idx_agent_events_tenant_time ON agent_events(tenant_id, timestamp DESC);
CREATE INDEX idx_agent_events_tenant_agent ON agent_events(tenant_id, agent_id, timestamp DESC);
CREATE INDEX idx_agent_events_tenant_outcome ON agent_events(tenant_id, outcome, timestamp DESC);
CREATE INDEX idx_agent_events_tenant_created ON agent_events(tenant_id, created_at);

CREATE TABLE checkpoints (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id),
    first_seq             BIGINT NOT NULL,
    last_seq              BIGINT NOT NULL,
    head_hash             TEXT NOT NULL,       -- hash of row last_seq
    prev_checkpoint_head  TEXT NOT NULL,       -- head_hash of prior checkpoint, or genesis
    merkle_root           TEXT NOT NULL,
    statement             TEXT NOT NULL,       -- exact JCS bytes that were signed + anchored
    signature             TEXT NOT NULL,       -- Ed25519 over statement
    key_id                TEXT NOT NULL REFERENCES signing_keys(key_id),
    external_anchor_proof TEXT,                -- base64 RFC 3161 TimeStampToken
    anchor_status         TEXT NOT NULL DEFAULT 'pending'
                          CHECK (anchor_status IN ('pending', 'anchored', 'failed', 'disabled')),
    anchor_authority      TEXT,
    anchored_at           TIMESTAMPTZ,
    anchor_attempts       INT NOT NULL DEFAULT 0,
    anchor_error          TEXT,
    row_count             INT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, first_seq),
    UNIQUE (tenant_id, last_seq),
    CHECK (first_seq <= last_seq AND row_count = last_seq - first_seq + 1)
);
CREATE INDEX idx_checkpoints_anchor_pending ON checkpoints(anchor_status) WHERE anchor_status = 'pending';

CREATE TABLE purge_log (
    id                 BIGSERIAL PRIMARY KEY,
    tenant_id          UUID NOT NULL REFERENCES tenants(id),
    checkpoint_id      UUID NOT NULL REFERENCES checkpoints(id),
    purged_through_seq BIGINT NOT NULL,
    rows_deleted       BIGINT NOT NULL,
    performed_by       TEXT NOT NULL DEFAULT session_user,
    purged_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
