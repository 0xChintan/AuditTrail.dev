-- Ledger lockdown (Task 1.2). Enforced with role grants, not app logic and
-- not triggers. Roles (created by `audittrail-migrate` before this runs):
--   audittrail_owner   NOLOGIN; owns all objects. Only migrations use it.
--   audittrail_app     the ingestion API: INSERT + SELECT on the ledger, nothing more
--   audittrail_worker  checkpoint worker: reads the ledger, writes checkpoints
--   audittrail_purge   retention job: may only EXECUTE purge_expired_events()

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO audittrail_app, audittrail_worker, audittrail_purge;

-- The ledger: append-only for the app. Explicit REVOKE per the blueprint,
-- plus TRUNCATE. INSERT is granted per column: created_at is left out so the
-- app cannot backdate a row to get it purged early.
REVOKE UPDATE, DELETE, TRUNCATE ON agent_events FROM audittrail_app;
GRANT SELECT ON agent_events TO audittrail_app;
GRANT INSERT (id, tenant_id, seq, timestamp, human_principal_id, agent_id, model_id,
              model_version, delegation_chain, action, target_resource, outcome,
              metadata, previous_hash, hash, signature, key_id)
      ON agent_events TO audittrail_app;

GRANT SELECT, INSERT ON chain_state TO audittrail_app;
GRANT UPDATE (previous_hash, last_seq, updated_at) ON chain_state TO audittrail_app;

GRANT SELECT, INSERT ON tenants TO audittrail_app;
GRANT UPDATE (name, retention_days, legal_hold, legal_hold_reason, legal_hold_set_at,
              rate_limit_rps, rate_limit_burst) ON tenants TO audittrail_app;

GRANT SELECT, INSERT ON api_keys TO audittrail_app;
GRANT UPDATE (last_used_at, revoked_at) ON api_keys TO audittrail_app;

GRANT SELECT, INSERT ON signing_keys TO audittrail_app;
GRANT UPDATE (retired_at) ON signing_keys TO audittrail_app;

GRANT SELECT ON checkpoints, purge_log TO audittrail_app;

-- Worker: read-only on the ledger; creates checkpoints; may only fill in
-- anchor columns afterwards (never merkle_root / statement / signature).
GRANT SELECT ON agent_events, chain_state, tenants, signing_keys TO audittrail_worker;
GRANT SELECT ON checkpoints TO audittrail_worker;
GRANT INSERT (tenant_id, first_seq, last_seq, head_hash, prev_checkpoint_head, merkle_root,
              statement, signature, key_id, anchor_status, row_count)
      ON checkpoints TO audittrail_worker;
GRANT UPDATE (external_anchor_proof, anchor_status, anchor_authority, anchored_at,
              anchor_attempts, anchor_error) ON checkpoints TO audittrail_worker;
