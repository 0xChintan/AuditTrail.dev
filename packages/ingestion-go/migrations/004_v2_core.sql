-- v2 server core (v2 tasks 1.1–1.3): v2 record columns, row-level security,
-- API key v2 (HMAC + scopes + expiry + request-signing key), nonce cache.

-- ---- v2 records share the ledger table (and chain) with v1 rows ---------------
ALTER TABLE agent_events
    ADD COLUMN spec_version   SMALLINT NOT NULL DEFAULT 1 CHECK (spec_version IN (1, 2)),
    ADD COLUMN received_at    TIMESTAMPTZ,
    ADD COLUMN agent          JSONB,
    ADD COLUMN principal      JSONB,
    ADD COLUMN model          JSONB,
    ADD COLUMN payload_hash   TEXT CHECK (payload_hash IS NULL OR payload_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN pii_ct         JSONB,
    ADD COLUMN request_digest TEXT,
    ADD CONSTRAINT agent_events_v2_complete CHECK (
        spec_version = 1 OR (received_at IS NOT NULL AND agent IS NOT NULL AND payload_hash IS NOT NULL
                             AND request_digest IS NOT NULL AND delegation_chain IS NOT NULL));

GRANT INSERT (spec_version, received_at, agent, principal, model, payload_hash, pii_ct, request_digest)
      ON agent_events TO audittrail_app;

-- ---- API keys v2 ----------------------------------------------------------------
ALTER TABLE api_keys
    ADD COLUMN key_version SMALLINT NOT NULL DEFAULT 1 CHECK (key_version IN (1, 2)),
    ADD COLUMN key_hmac    TEXT,          -- HMAC-SHA256(pepper, key), v2 keys only
    ADD COLUMN scopes      TEXT[] NOT NULL DEFAULT '{events:write,events:read,export:read}',
    ADD COLUMN expires_at  TIMESTAMPTZ,
    ADD COLUMN sign_pub    TEXT;          -- Ed25519 request-signing public key (base64)
ALTER TABLE api_keys ALTER COLUMN key_hash DROP NOT NULL;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_v2_complete
    CHECK (key_version = 1 OR (key_hmac IS NOT NULL AND sign_pub IS NOT NULL));

-- Replay protection: a (key, nonce) pair is accepted once within its window.
CREATE TABLE request_nonces (
    key_id     UUID NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (key_id, nonce)
);
CREATE INDEX request_nonces_expiry ON request_nonces (expires_at);
GRANT SELECT, INSERT, DELETE ON request_nonces TO audittrail_app;

-- Credential lookup happens before the tenant is known, so it can't run under
-- the tenant RLS policy. This definer function exposes exactly one row by
-- prefix and nothing else.
CREATE FUNCTION auth_lookup_key(p_prefix TEXT)
RETURNS TABLE (id UUID, tenant_id UUID, key_version SMALLINT, key_hash TEXT, key_hmac TEXT,
               scopes TEXT[], expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, sign_pub TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT id, tenant_id, key_version, key_hash, key_hmac, scopes, expires_at, revoked_at, sign_pub
      FROM api_keys WHERE prefix = p_prefix
$$;
REVOKE ALL ON FUNCTION auth_lookup_key(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_lookup_key(TEXT) TO audittrail_app;

-- ---- control-plane role (tenant onboarding, key management) ---------------------
-- audittrail_control is created by the migrator. It manages tenants and keys
-- across tenants but has NO write access to the ledger itself.
GRANT USAGE ON SCHEMA public TO audittrail_control;
GRANT SELECT, INSERT ON tenants, api_keys, signing_keys, chain_state TO audittrail_control;
GRANT UPDATE (name, retention_days, legal_hold, legal_hold_reason, legal_hold_set_at,
              rate_limit_rps, rate_limit_burst) ON tenants TO audittrail_control;
GRANT UPDATE (last_used_at, revoked_at) ON api_keys TO audittrail_control;
GRANT UPDATE (retired_at) ON signing_keys TO audittrail_control;
GRANT SELECT ON agent_events, checkpoints, purge_log TO audittrail_control;

-- ---- row-level security (T6) -------------------------------------------------------
-- The API sets `SET LOCAL app.tenant_id` in every transaction. An unset or
-- empty setting matches nothing (fail closed).
CREATE FUNCTION app_tenant() RETURNS UUID LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

ALTER TABLE tenants      ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys     ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE chain_state  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE checkpoints  ENABLE ROW LEVEL SECURITY;
ALTER TABLE purge_log    ENABLE ROW LEVEL SECURITY;

CREATE POLICY app_tenant ON tenants      TO audittrail_app USING (id = app_tenant()) WITH CHECK (id = app_tenant());
CREATE POLICY app_tenant ON api_keys     TO audittrail_app USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY app_tenant ON signing_keys TO audittrail_app USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY app_tenant ON chain_state  TO audittrail_app USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY app_tenant ON agent_events TO audittrail_app USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY app_tenant ON checkpoints  TO audittrail_app USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY app_tenant ON purge_log    TO audittrail_app USING (tenant_id = app_tenant());

-- Cross-tenant roles: their grants (above and in 002) already limit *what*
-- they may do; RLS gives them all rows.
CREATE POLICY control_all ON tenants      TO audittrail_control USING (true) WITH CHECK (true);
CREATE POLICY control_all ON api_keys     TO audittrail_control USING (true) WITH CHECK (true);
CREATE POLICY control_all ON signing_keys TO audittrail_control USING (true) WITH CHECK (true);
CREATE POLICY control_all ON chain_state  TO audittrail_control USING (true) WITH CHECK (true);
CREATE POLICY control_all ON agent_events TO audittrail_control USING (true);
CREATE POLICY control_all ON checkpoints  TO audittrail_control USING (true);
CREATE POLICY control_all ON purge_log    TO audittrail_control USING (true);

CREATE POLICY worker_all ON tenants      TO audittrail_worker USING (true);
CREATE POLICY worker_all ON signing_keys TO audittrail_worker USING (true);
CREATE POLICY worker_all ON chain_state  TO audittrail_worker USING (true);
CREATE POLICY worker_all ON agent_events TO audittrail_worker USING (true);
CREATE POLICY worker_all ON checkpoints  TO audittrail_worker USING (true) WITH CHECK (true);

CREATE POLICY purge_read ON tenants TO audittrail_purge USING (true);
