-- v2 phase 5: crypto-shredding. One DEK per (tenant, subject) generation,
-- wrapped by the KEK (AUDITTRAIL_MASTER_KEY; a KMS in production). PII
-- fields are encrypted under it BEFORE the record hash is computed, so
-- destroying the DEK erases the plaintext while every hash, proof and
-- signature stays valid.
CREATE TABLE subject_keys (
    dek_id           TEXT PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES tenants(id),
    subject          TEXT NOT NULL,
    wrapped_dek      TEXT,                 -- NULL once destroyed
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    destroyed_at     TIMESTAMPTZ,
    destroyed_reason TEXT,
    CHECK ((wrapped_dek IS NULL) = (destroyed_at IS NOT NULL))
);
-- At most one live key per subject; a destroyed subject can get a fresh key
-- for events recorded after the erasure.
CREATE UNIQUE INDEX subject_keys_live ON subject_keys (tenant_id, subject) WHERE destroyed_at IS NULL;

GRANT SELECT, INSERT ON subject_keys TO audittrail_app;
GRANT UPDATE (wrapped_dek, destroyed_at, destroyed_reason) ON subject_keys TO audittrail_app;
GRANT SELECT ON subject_keys TO audittrail_control;

ALTER TABLE subject_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_tenant  ON subject_keys TO audittrail_app USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY control_all ON subject_keys TO audittrail_control USING (true);
