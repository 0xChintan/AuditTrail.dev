-- Shared per-tenant rate limits (ASVS V11). The token bucket lives here, so
-- the limit holds across any number of API instances. Instances lease small
-- batches of tokens with rate_take() and spend them locally; unused tokens
-- expire instead of being returned, so the combined rate never exceeds the
-- tenant's limit. Time comes from the database clock (one clock for all).
CREATE TABLE rate_buckets (
    tenant_id  UUID PRIMARY KEY REFERENCES tenants(id),
    tokens     DOUBLE PRECISION NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE FUNCTION rate_take(p_tenant UUID, p_rps DOUBLE PRECISION, p_burst DOUBLE PRECISION, p_want INT)
RETURNS TABLE (granted INT, wait_ms INT)
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    now_ts TIMESTAMPTZ := clock_timestamp();
    avail  DOUBLE PRECISION;
    g      INT;
BEGIN
    INSERT INTO rate_buckets (tenant_id, tokens, updated_at)
    VALUES (p_tenant, p_burst, now_ts)
    ON CONFLICT (tenant_id) DO NOTHING;

    SELECT least(p_burst, b.tokens + p_rps * extract(epoch FROM now_ts - b.updated_at))
      INTO avail FROM rate_buckets b WHERE b.tenant_id = p_tenant FOR UPDATE;

    g := greatest(0, least(p_want, floor(avail)::INT));
    UPDATE rate_buckets SET tokens = avail - g, updated_at = now_ts WHERE tenant_id = p_tenant;

    RETURN QUERY SELECT g,
        CASE WHEN g > 0 OR p_rps <= 0 THEN 0
             ELSE ceil((1 - avail) / p_rps * 1000)::INT END;
END;
$$;

GRANT SELECT, INSERT, UPDATE ON rate_buckets TO audittrail_control;
GRANT EXECUTE ON FUNCTION rate_take(UUID, DOUBLE PRECISION, DOUBLE PRECISION, INT) TO audittrail_control;
REVOKE EXECUTE ON FUNCTION rate_take(UUID, DOUBLE PRECISION, DOUBLE PRECISION, INT) FROM PUBLIC;
