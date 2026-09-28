-- Retention + legal hold (Task 6.3).
--
-- The only DELETE path on agent_events. It runs as its owner (SECURITY
-- DEFINER); only audittrail_purge may EXECUTE it. It:
--   * refuses outright while the tenant has legal_hold set, whatever the
--     retention setting;
--   * deletes only whole checkpoint ranges, and only checkpoints created
--     longer ago than the tenant's retention window (which is never less
--     than 183 days, see the CHECK on tenants.retention_days);
--   * requires that checkpoint to be externally anchored (or anchoring
--     explicitly disabled), so the surviving chain can still be verified
--     from the checkpoint's signed head_hash.

CREATE FUNCTION purge_expired_events(p_tenant UUID)
RETURNS TABLE (purged_through_seq BIGINT, rows_deleted BIGINT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    t  tenants%ROWTYPE;
    cp checkpoints%ROWTYPE;
    n  BIGINT;
BEGIN
    -- Row lock: a legal hold set concurrently either commits before us (and
    -- we see it) or waits for us.
    SELECT * INTO t FROM tenants WHERE id = p_tenant FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'tenant % not found', p_tenant;
    END IF;
    IF t.legal_hold THEN
        RAISE EXCEPTION 'legal hold active for tenant % (%): purge blocked',
            p_tenant, coalesce(t.legal_hold_reason, 'no reason given')
            USING ERRCODE = 'P0001';
    END IF;

    SELECT * INTO cp FROM checkpoints c
     WHERE c.tenant_id = p_tenant
       AND c.created_at < NOW() - make_interval(days => t.retention_days)
       AND c.anchor_status IN ('anchored', 'disabled')
     ORDER BY c.last_seq DESC
     LIMIT 1;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    DELETE FROM agent_events e WHERE e.tenant_id = p_tenant AND e.seq <= cp.last_seq;
    GET DIAGNOSTICS n = ROW_COUNT;

    IF n > 0 THEN
        INSERT INTO purge_log (tenant_id, checkpoint_id, purged_through_seq, rows_deleted)
        VALUES (p_tenant, cp.id, cp.last_seq, n);
    END IF;
    RETURN QUERY SELECT cp.last_seq, n;
END;
$$;

REVOKE ALL ON FUNCTION purge_expired_events(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_expired_events(UUID) TO audittrail_purge;
GRANT SELECT (id, legal_hold) ON tenants TO audittrail_purge;
