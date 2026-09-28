# Secrets and key management

This covers every secret AuditTrail uses: what it protects, where it lives, and how to rotate it. Every secret is read from the environment, and each variable also accepts a `*_FILE` form (Docker/Kubernetes secrets): `X_FILE=/run/secrets/x` loads `X` from that file. Local development uses `.env`. The production stack in `deploy/compose` uses secret files, with the master key in a KMS ([docs/DEPLOYING.md](docs/DEPLOYING.md)).

| Secret | Scope | Protects | Storage | Stronger target |
|---|---|---|---|---|
| Master key | global | Seals every tenant's Ed25519 private seed and every per-subject PII key (AES-256-GCM, AAD-bound) | **Production:** only KMS-wrapped (`AUDITTRAIL_MASTER_KEY_WRAPPED` + `AUDITTRAIL_KMS_KEY_URL`: AWS KMS, Google Cloud KMS, Azure Key Vault or Vault transit), unwrapped in memory at startup; `AUDITTRAIL_REQUIRE_KMS=true` refuses a plaintext key. Dev: `AUDITTRAIL_MASTER_KEY` in `.env` | Per-tenant signing inside the KMS/HSM |
| `AUDITTRAIL_KEY_PEPPER` | global | HMAC key for stored API-key digests: a DB dump alone can't be used to test guesses | Secret file | KMS-backed HMAC |
| Tenant signing key (Ed25519) | **per tenant** | Row signatures + checkpoint signatures | `signing_keys.private_key_enc`, sealed by master key | Per-tenant KMS asymmetric key (Ed25519 signing inside the KMS/HSM) |
| Tenant API keys (`at2_…`) | per tenant, many | Scoped access to one tenant's log; also derive the request-signing key (HKDF) | Only `HMAC-SHA256(pepper, key)` + a lookup prefix in `api_keys`, plus the derived Ed25519 *public* key | unchanged |
| `AUDITTRAIL_ADMIN_TOKEN` | global | `/v1/admin/*`, dashboard's server-side calls | Secret file | Per-operator credentials |
| DB role passwords | global | `audittrail_app` / `_worker` / `_control` / `_purge` logins | Secret files, inside `verify-full` TLS connection strings | IAM database auth |
| `DASHBOARD_PASSWORD` | global | Basic-auth gate on the dashboard | Secret file | OIDC SSO |

## Design rules

1. **Signing keys are per tenant.** A compromised key affects one tenant only, and each tenant's public keys are published at `GET /v1/tenants/{id}/public-keys`.
2. **API keys are never stored in plaintext.** v2 keys (`at2_…`) carry 256 bits of entropy. Lookup uses a prefix, and `HMAC-SHA256(pepper, key)` is compared in constant time. The pepper lives outside the database, so a stolen DB dump can't even confirm a guessed key. A slow hash isn't needed at this entropy.
3. **The plaintext API key is shown once.** It appears only in the create response (API and dashboard) and can't be retrieved later.
4. **Private seeds are sealed with AAD `tenant_id|key_id`.** A ciphertext moved to another tenant's row won't decrypt.
5. **Admin changes are logged in the ledger.** Tenant creation, settings and legal-hold changes, API key create/revoke and signing-key rotation are all recorded in that tenant's own ledger (`agent_id = "audittrail-admin"`).

## Rotation policy

| Secret | Routine rotation | On suspected compromise |
|---|---|---|
| Tenant API key | Every 90 days. Create the new key, deploy it, then revoke the old one (`POST` / `DELETE /v1/admin/tenants/{id}/api-keys`). Revocation takes effect on the next request. | Revoke immediately. |
| Tenant signing key | Yearly: `POST /v1/admin/tenants/{id}/signing-keys/rotate`. The old key is marked `retired_at`, stays published and still verifies old rows, since each row records its `key_id`. | Rotate immediately. Checkpoints signed and **RFC 3161-anchored** before the compromise stay trustworthy, because the TSA proves they existed before the attacker had the key. Treat anything after the last anchored checkpoint as suspect. |
| KMS key (wrapping the master key) | Per your KMS policy. Automatic KMS key rotation (AWS, GCP) needs no action. To move to a new key, run `audittrail-admin kms-rewrap -to <new URL>` and deploy the new `AUDITTRAIL_MASTER_KEY_WRAPPED`; no data is re-encrypted. | Revoke the old KMS key's decrypt grant after rewrapping. The wrapped blob is useless without KMS access. |
| Master key | When staff with plaintext access leave (with a KMS, nobody should have it). Re-sealing all `private_key_enc` values under a new key is in the backlog; until then, rotate tenant signing keys after swapping the master key. | Treat all tenant signing keys as compromised: swap the master key, then rotate every tenant key. |
| Admin token | 90 days. | Replace, and restart the API and dashboard. |
| DB passwords | 90 days. With `deploy/compose`: delete `secrets/<role>_db_password`, rerun `./init-secrets.sh` (it rewrites the connection strings) and `docker compose up -d`; `migrate` applies the new password first. | Same, immediately. |

## Generating secrets

```sh
deploy/compose/init-secrets.sh             # everything for the production stack
audittrail-admin kms-wrap -key "$URL" -generate   # new master key, wrapped; the plaintext is never shown
audittrail-admin gen-master-key            # dev only: plaintext AUDITTRAIL_MASTER_KEY
```

## What the database roles can do

| Role | agent_events | chain_state | checkpoints | Notes |
|---|---|---|---|---|
| `audittrail_app` | SELECT, INSERT (not `created_at`) | SELECT, INSERT, UPDATE(head) | SELECT | **No UPDATE / DELETE / TRUNCATE on the ledger** |
| `audittrail_worker` | SELECT | SELECT | SELECT, INSERT, UPDATE(anchor columns only) | Can't change a root or signature after writing it |
| `audittrail_purge` | — | — | — | May only `EXECUTE purge_expired_events()`, which refuses while a legal hold is set |
| `audittrail_owner` | owner | owner | owner | NOLOGIN; used only by the migrator |

A database superuser can still edit anything. That's why the design doesn't rely on the database alone: hash chaining, Ed25519 signatures and the external RFC 3161 anchors make any such edit **detectable** by `audittrail-verify`, even when whoever edited the data controls the database.
