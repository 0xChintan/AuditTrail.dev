# OWASP ASVS 4.0.3 Level 2: self-assessment

**Scope:** ingestion API (`packages/ingestion-go`), witness, verifier/WASM, dashboard (`apps/dashboard`), SDK and MCP sidecar. **Date:** 2026-09-28. **Method:** chapter-by-chapter review against the code, backed by the automated tests named in [THREAT_MODEL.md](../THREAT_MODEL.md).

This is **not** a substitute for the external penetration test (v2 task 7.1). Book that before the first paying customer. Status legend: ✅ meets L2 · 🟡 partial / deployment-dependent · ⛔ gap · n/a not applicable.

## Findings fixed during this assessment

| Severity | Finding | Fix |
|---|---|---|
| **High** | The dashboard served admin pages with no authentication when `DASHBOARD_PASSWORD` was unset | Now fails closed in production (503 unless `DASHBOARD_ALLOW_NO_AUTH=true`); the password is compared in constant time |
| High | A third-party toast library injected `<style>` without a nonce, forcing a CSP choice between breakage and `unsafe-inline` | Replaced with an in-house component; the strict CSP has no `unsafe-inline` |
| **High** | The tree-head worker kept a witness's cosignature only if the witness's key name equaled its *configured* name, but still marked the head as witnessed. With short config names (`w1=…`), heads claimed 3 witnesses while carrying none, and the purge function (which trusts that column) could purge under an unwitnessed head | Every cosignature line the witness returns is kept; a witness counts only if one arrived; regression test `TestTreeHeadCarriesWitnessCosignatures` (fails on the old code) |
| Medium | `/v2/export` returned 500 for a log with a row deleted behind the API, so the evidence of the tampering couldn't be exported | Gap-tolerant export; the verifier reports `seq-continuity` for the missing row (`TestExportSurvivesDeletedRow`) |
| Medium | A `.env` file in the working directory could override an explicitly configured `*_FILE` secret, silently connecting a service to the wrong database | Found by the deployment smoke test. An explicit `X_FILE` now always wins (`TestFileSecretBeatsDotEnv`) |
| Low | The root layout fetched the tenant list with the admin token on every page, including the public `/verify`; it didn't leak only because that page happened to be static | The tenant list and operator identity are rendered only for requests the proxy has authenticated, and client-sent auth headers are stripped |
| Medium | The API server had only a header timeout (slow-body clients could hold connections) | Read 30 s / write 120 s / idle 120 s timeouts, 64 KiB header cap; the witness server too |
| Medium | Floats above 2^53 re-canonicalized to a form the strict parser rejects, causing false tamper alarms after the jsonb round-trip | Found by fuzzing; rejected at ingest in Go + TS + spec (`unsafe_integer`) |
| Medium | `golang.org/x/text` infinite loop (GO-2026-5970) reachable via pgx | Upgraded; `govulncheck` clean |
| Low | SDK `flush()` could return before events passed to `track()` were spooled; concurrent `record()` calls could be spooled out of order | Fixed, with regression tests |

## Chapter status

| Chapter | Status | Evidence / notes |
|---|---|---|
| **V1 Architecture, threat modeling** | ✅ | THREAT_MODEL.md: every threat has an owner and a CI test ID; trust boundaries; least-privilege DB roles (app / worker / control / purge / owner) |
| **V2 Authentication** | ✅ | API keys: 256-bit, stored as HMAC-SHA256 with a pepper, constant-time compare, expiry, revocation, scopes (S1–S4 tests); writes require Ed25519 request signatures with a ±5 min skew and a nonce cache. Operators sign in through OIDC SSO (authorization code + PKCE, verified email, allowlist, optional MFA via `amr`), and admin actions are attributed to the operator (`scripts/oidc-e2e.mjs`, 23 checks). The shared password remains as a fallback when SSO isn't configured. The dashboard still reaches the API with one service token |
| **V3 Session management** | ✅ | The API is stateless (bearer + signature). Dashboard SSO sessions are encrypted JWE cookies (`__Host-`, HttpOnly, Secure, SameSite=Lax) with an absolute lifetime (8 h default), rejected when tampered with, and cleared on logout together with the IdP session. The one-time PKCE/state/nonce cookie expires after 10 minutes |
| **V4 Access control** | ✅ | Postgres RLS on every tenant table, fail-closed without `app.tenant_id` (S5 incl. raw-SQL checks); per-key scopes (403); the ledger is append-only at the grant level; admin routes need the admin token; the dashboard proxy exposes only an allowlist of read endpoints |
| **V5 Validation, sanitization, encoding** | ✅ | Strict parser (duplicate keys, invalid UTF-8, lone surrogates, depth, size, unsafe numbers, NUL) with 126 hostile vectors over HTTP (S6) and 2×30 min fuzzing; output encoding by React, no raw-HTML sinks, CSV formula-injection guard; XSS corpus test (D1) |
| **V6 Stored cryptography** | ✅ | Ed25519 (receipts, checkpoints, request signing), SHA-256/RFC 9162 Merkle, AES-256-GCM (keys + PII) with AAD binding, HKDF, crypto/rand only (gosec G404 clean). The master key (KEK) is deployed only KMS-wrapped (AWS KMS, GCP KMS, Azure Key Vault, Vault transit) and unwrapped in memory at startup; `AUDITTRAIL_REQUIRE_KMS=true` refuses a plaintext key (`internal/masterkey`, tested against an AWS KMS protocol fake). Per-tenant signing inside an HSM is a future step |
| **V7 Errors and logging** | ✅ | Generic error bodies (401 never reveals the reason), panics recovered to a generic 500; logs record auth-failure reasons without secrets; admin actions are themselves sealed into the tenant ledger |
| **V8 Data protection** | ✅ | PII encrypted per subject and crypto-shreddable; SDK and sidecar redact secrets before hashing (C4, M2); `Cache-Control: no-store` on API responses; the dashboard never sends the admin token to the browser |
| **V9 Communications** | ✅ | The production stack (`deploy/compose`) terminates TLS at Caddy (automatic certificates, TLS 1.2+, HTTP→HTTPS, HSTS). Postgres accepts TLS 1.3 only (`hostssl`-only `pg_hba`), and every client uses `sslmode=verify-full` against a private CA. Verified: plaintext, TLS 1.2, wrong CA and hostname mismatch are all refused. Hops inside the private `edge` network (Caddy → API/dashboard) are plain HTTP |
| **V10 Malicious code** | ✅ | gosec, govulncheck, semgrep, osv-scanner, gitleaks (with canary) in CI; SBOMs (CycloneDX) for Go + JS; pinned lockfile; no dynamic code execution (only `wasm-unsafe-eval` for the verifier) |
| **V11 Business logic** | ✅ | Per-tenant token buckets shared across API instances through Postgres (leased batches, database clock). Two instances together admitted 119 of an allowed 120 (`TestSharedRateLimitAcrossInstances`); the old per-instance limiter admitted twice the burst. 429 + Retry-After; idempotency blocks double-processing |
| **V12 Files and resources** | ✅ / n/a | No server-side file uploads; bundle uploads in `/verify` are parsed only in the browser; body size limits (256 KiB events, 4 MiB OTLP) |
| **V13 API and web service** | ✅ | Strict JSON contracts with unknown fields rejected, per-route scopes, a CORS allowlist, correct status codes, signed state-changing requests (except OTLP: exporters can't sign, so it gets a dedicated `otlp:write` scope) |
| **V14 Configuration** | 🟡 | Strict nonce-based CSP, `nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, Referrer-Policy, Permissions-Policy, COOP. Secrets come from files (`*_FILE`). Containers are distroless or minimal, non-root, read-only, with all capabilities dropped and base images pinned by digest. **Gap:** the ZAP baseline and the compose smoke test run in CI (`dast.yml`, `deploy-smoke.yml`) but haven't run yet (no Docker here) |

## Open items before launch

1. **External penetration test** (owner: you). Scope: the API, dashboard, witness, the deployment in `deploy/compose`, and the SDK/sidecar supply chain.
2. First green runs of `deploy-smoke.yml` and `dast.yml` on GitHub (V14).
3. Choose the production KMS and IdP, then enable `compose.kms.yaml` and `compose.sso.yaml` (V2, V6).
4. Later: per-tenant signing keys inside an HSM, and per-operator API credentials in place of the dashboard's service token.
