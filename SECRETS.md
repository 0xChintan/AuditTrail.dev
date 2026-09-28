# Secrets and key management

This covers every secret AuditTrail uses: what it protects, where it lives in the MVP, and how to rotate it. The MVP keeps secrets in `.env`. The **KMS** column shows where each secret should live in production. Nothing in the code assumes `.env`: every secret is read from the environment.

| Secret | Scope | Protects | MVP storage | KMS target |
|---|---|---|---|---|
| `AUDITTRAIL_MASTER_KEY` | global | Encrypts every tenant's Ed25519 private seed (AES-256-GCM, bound to `tenant_id\|key_id`) | `.env` | KMS key; wrap/unwrap seeds through the KMS API instead of AES in-process |
| Tenant signing key (Ed25519) | **per tenant** | Row signatures + checkpoint signatures | `signing_keys.private_key_enc`, sealed by master key | Per-tenant KMS asymmetric key (Ed25519 signing inside the KMS/HSM) |
| Tenant API keys | per tenant, many | Write/read access to one tenant's ledger | Only `SHA-256(key)` + a 12-hex lookup prefix in `api_keys` | unchanged (hashes are not secrets) |
| `AUDITTRAIL_ADMIN_TOKEN` | global | `/v1/admin/*`, dashboard's server-side calls | `.env` | Secret manager; better, replace with SSO/OIDC |
| DB role passwords | global | `audittrail_app` / `_worker` / `_purge` logins | `.env` | Secret manager, or IAM database auth |
| `DASHBOARD_PASSWORD` | global | Basic-auth gate on the dashboard | `.env` | SSO |

## Design rules

1. **Signing keys are per tenant.** A compromised key affects one tenant only, and each tenant's public keys are published at `GET /v1/tenants/{id}/public-keys`.
2. **API keys are never stored in plaintext.** The key format is `at_<12-hex prefix>_<256-bit secret>`. Lookup uses the prefix, and the SHA-256 of the full key is compared in constant time. A salted slow hash isn't needed because the keys carry 256 bits of entropy.
3. **The plaintext API key is shown once.** It appears only in the create response (API and dashboard) and can't be retrieved later.
4. **Private seeds are sealed with AAD `tenant_id|key_id`.** A ciphertext moved to another tenant's row won't decrypt.
5. **Admin changes are logged in the ledger.** Tenant creation, settings and legal-hold changes, API key create/revoke and signing-key rotation are all recorded in that tenant's own ledger (`agent_id = "audittrail-admin"`).

## Rotation policy

| Secret | Routine rotation | On suspected compromise |
|---|---|---|
| Tenant API key | Every 90 days. Create the new key, deploy it, then revoke the old one (`POST` / `DELETE /v1/admin/tenants/{id}/api-keys`). Revocation takes effect on the next request. | Revoke immediately. |
| Tenant signing key | Yearly: `POST /v1/admin/tenants/{id}/signing-keys/rotate`. The old key is marked `retired_at`, stays published and still verifies old rows, since each row records its `key_id`. | Rotate immediately. Checkpoints signed and **RFC 3161-anchored** before the compromise stay trustworthy, because the TSA proves they existed before the attacker had the key. Treat anything after the last anchored checkpoint as suspect. |
| Master key | Yearly, or when staff with access leave. Re-seal all `private_key_enc` values under the new key (the job is in the backlog; for the MVP, rotate tenant signing keys after swapping the master key). | Treat all tenant signing keys as compromised: swap the master key, then rotate every tenant key. |
| Admin token | 90 days. | Replace, and restart the API and dashboard. |
| DB passwords | 90 days: change `AUDITTRAIL_*_DB_PASSWORD`, rerun `audittrail-migrate` (it resets role passwords), then update the connection URLs. | Same, immediately. |

## Generating secrets

```sh
head -c 32 /dev/urandom | base64          # AUDITTRAIL_MASTER_KEY
head -c 24 /dev/urandom | base64          # AUDITTRAIL_ADMIN_TOKEN
# or: go run ./packages/ingestion-go/cmd/admin gen-master-key
```

## What the database roles can do

| Role | agent_events | chain_state | checkpoints | Notes |
|---|---|---|---|---|
| `audittrail_app` | SELECT, INSERT (not `created_at`) | SELECT, INSERT, UPDATE(head) | SELECT | **No UPDATE / DELETE / TRUNCATE on the ledger** |
| `audittrail_worker` | SELECT | SELECT | SELECT, INSERT, UPDATE(anchor columns only) | Can't change a root or signature after writing it |
| `audittrail_purge` | — | — | — | May only `EXECUTE purge_expired_events()`, which refuses while a legal hold is set |
| `audittrail_owner` | owner | owner | owner | NOLOGIN; used only by the migrator |

A database superuser can still edit anything. That's why the design doesn't rely on the database alone: hash chaining, Ed25519 signatures and the external RFC 3161 anchors make any such edit **detectable** by `audittrail-verify`, even when whoever edited the data controls the database.
