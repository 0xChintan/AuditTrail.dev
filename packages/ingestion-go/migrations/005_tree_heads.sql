-- v2 trust layer (v2 tasks 3.1–3.2): C2SP checkpoints over the whole tenant
-- log (RFC 9162 tree heads), witness cosignatures, RFC 3161 anchors.

-- Signed tree heads. `note` is the full C2SP signed note (checkpoint body +
-- log signature + any witness cosignatures collected so far).
CREATE TABLE tree_heads (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id),
    tree_size     BIGINT NOT NULL CHECK (tree_size > 0),
    root_hash     TEXT NOT NULL CHECK (root_hash ~ '^[0-9a-f]{64}$'),
    head_hash     TEXT NOT NULL,          -- record hash of leaf tree_size (seq = tree_size)
    note          TEXT NOT NULL,
    key_id        TEXT NOT NULL REFERENCES signing_keys(key_id),
    witnesses     TEXT[] NOT NULL DEFAULT '{}',
    tsa_token     TEXT,
    tsa_status    TEXT NOT NULL DEFAULT 'pending' CHECK (tsa_status IN ('pending', 'anchored', 'failed', 'disabled')),
    tsa_authority TEXT,
    tsa_time      TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, tree_size)
);
CREATE INDEX tree_heads_latest ON tree_heads (tenant_id, tree_size DESC);

-- Latest size each witness cosigned for each tenant log (so the log can
-- send the right consistency proof).
CREATE TABLE witness_state (
    tenant_id  UUID NOT NULL REFERENCES tenants(id),
    witness    TEXT NOT NULL,
    tree_size  BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, witness)
);

-- Leaf hashes of purged rows: retention may delete event content, never the
-- log structure, so inclusion/consistency proofs keep working forever.
CREATE TABLE purged_leaves (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    seq       BIGINT NOT NULL,
    hash      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);

GRANT SELECT ON tree_heads, purged_leaves TO audittrail_app, audittrail_control;
GRANT SELECT, INSERT ON tree_heads TO audittrail_worker;
GRANT UPDATE (note, witnesses, tsa_token, tsa_status, tsa_authority, tsa_time) ON tree_heads TO audittrail_worker;
GRANT SELECT, INSERT, UPDATE ON witness_state TO audittrail_worker;
GRANT SELECT ON purged_leaves TO audittrail_worker;

ALTER TABLE tree_heads    ENABLE ROW LEVEL SECURITY;
ALTER TABLE purged_leaves ENABLE ROW LEVEL SECURITY;
ALTER TABLE witness_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_tenant  ON tree_heads    TO audittrail_app USING (tenant_id = app_tenant());
CREATE POLICY app_tenant  ON purged_leaves TO audittrail_app USING (tenant_id = app_tenant());
CREATE POLICY control_all ON tree_heads    TO audittrail_control USING (true);
CREATE POLICY control_all ON purged_leaves TO audittrail_control USING (true);
CREATE POLICY worker_all  ON tree_heads    TO audittrail_worker USING (true) WITH CHECK (true);
CREATE POLICY worker_all  ON purged_leaves TO audittrail_worker USING (true);
CREATE POLICY worker_all  ON witness_state TO audittrail_worker USING (true) WITH CHECK (true);

-- Purge now preserves leaf hashes and requires a witnessed/anchored tree
-- head covering the purged range.
CREATE OR REPLACE FUNCTION purge_expired_events(p_tenant UUID)
RETURNS TABLE (purged_through_seq BIGINT, rows_deleted BIGINT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    t  tenants%ROWTYPE;
    cp checkpoints%ROWTYPE;
    through BIGINT;
    n  BIGINT;
BEGIN
    SELECT * INTO t FROM tenants WHERE id = p_tenant FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'tenant % not found', p_tenant;
    END IF;
    IF t.legal_hold THEN
        RAISE EXCEPTION 'legal hold active for tenant % (%): purge blocked',
            p_tenant, coalesce(t.legal_hold_reason, 'no reason given')
            USING ERRCODE = 'P0001';
    END IF;

    -- Oldest-first: purge through the last v1 range checkpoint or v2 tree
    -- head that is older than retention and externally anchored/witnessed.
    SELECT max(x.s) INTO through FROM (
        SELECT c.last_seq AS s FROM checkpoints c
         WHERE c.tenant_id = p_tenant AND c.anchor_status IN ('anchored', 'disabled')
           AND c.created_at < NOW() - make_interval(days => t.retention_days)
        UNION ALL
        SELECT h.tree_size FROM tree_heads h
         WHERE h.tenant_id = p_tenant AND (h.tsa_status IN ('anchored', 'disabled') OR cardinality(h.witnesses) > 0)
           AND h.created_at < NOW() - make_interval(days => t.retention_days)
    ) x;
    IF through IS NULL THEN
        RETURN QUERY SELECT 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    INSERT INTO purged_leaves (tenant_id, seq, hash)
         SELECT e.tenant_id, e.seq, e.hash FROM agent_events e
          WHERE e.tenant_id = p_tenant AND e.seq <= through
    ON CONFLICT DO NOTHING;
    DELETE FROM agent_events e WHERE e.tenant_id = p_tenant AND e.seq <= through;
    GET DIAGNOSTICS n = ROW_COUNT;

    IF n > 0 THEN
        SELECT * INTO cp FROM checkpoints c WHERE c.tenant_id = p_tenant AND c.last_seq <= through ORDER BY c.last_seq DESC LIMIT 1;
        INSERT INTO purge_log (tenant_id, checkpoint_id, purged_through_seq, rows_deleted)
        VALUES (p_tenant, cp.id, through, n);
    END IF;
    RETURN QUERY SELECT through, n;
END;
$$;

-- purge_log.checkpoint_id may be NULL now (purge covered by a v2 tree head).
ALTER TABLE purge_log ALTER COLUMN checkpoint_id DROP NOT NULL;
