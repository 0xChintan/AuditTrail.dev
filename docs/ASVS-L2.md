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
| Medium | The API server had only a header timeout (slow-body clients could hold connections) | Read 30 s / write 120 s / idle 120 s timeouts, 64 KiB header cap; the witness server too |
| Medium | Floats above 2^53 re-canonicalized to a form the strict parser rejects, causing false tamper alarms after the jsonb round-trip | Found by fuzzing; rejected at ingest in Go + TS + spec (`unsafe_integer`) |
| Medium | `golang.org/x/text` infinite loop (GO-2026-5970) reachable via pgx | Upgraded; `govulncheck` clean |
| Low | SDK `flush()` could return before events passed to `track()` were spooled; concurrent `record()` calls could be spooled out of order | Fixed, with regression tests |

## Chapter status

| Chapter | Status | Evidence / notes |
|---|---|---|
| **V1 Architecture, threat modeling** | ✅ | THREAT_MODEL.md: every threat has an owner and a CI test ID; trust boundaries; least-privilege DB roles (app / worker / control / purge / owner) |
| **V2 Authentication** | 🟡 | API keys: 256-bit, stored as HMAC-SHA256 with a pepper, constant-time compare, expiry, revocation, scopes (S1–S4 tests); writes require Ed25519 request signatures with a ±5 min skew and a nonce cache. **Gap:** dashboard/admin uses one static admin token + basic-auth password; no MFA or SSO. Recommended: OIDC SSO in front of the dashboard and per-operator admin credentials |
| **V3 Session management** | n/a / 🟡 | The API is stateless (bearer + signature). The dashboard uses HTTP basic auth, which has no session to fixate; logout requires closing the browser. SSO (V2 gap) would add proper sessions |
| **V4 Access control** | ✅ | Postgres RLS on every tenant table, fail-closed without `app.tenant_id` (S5 incl. raw-SQL checks); per-key scopes (403); the ledger is append-only at the grant level; admin routes need the admin token; the dashboard proxy exposes only an allowlist of read endpoints |
| **V5 Validation, sanitization, encoding** | ✅ | Strict parser (duplicate keys, invalid UTF-8, lone surrogates, depth, size, unsafe numbers, NUL) with 126 hostile vectors over HTTP (S6) and 2×30 min fuzzing; output encoding by React, no raw-HTML sinks, CSV formula-injection guard; XSS corpus test (D1) |
| **V6 Stored cryptography** | 🟡 | Ed25519 (receipts, checkpoints, request signing), SHA-256/RFC 9162 Merkle, AES-256-GCM (keys + PII) with AAD binding, HKDF, crypto/rand only (gosec G404 clean). **Gap:** the KEK/master key is an environment variable; move it to a KMS/HSM before production (SECRETS.md) |
| **V7 Errors and logging** | ✅ | Generic error bodies (401 never reveals the reason), panics recovered to a generic 500; logs record auth-failure reasons without secrets; admin actions are themselves sealed into the tenant ledger |
| **V8 Data protection** | ✅ | PII encrypted per subject and crypto-shreddable; SDK and sidecar redact secrets before hashing (C4, M2); `Cache-Control: no-store` on API responses; the dashboard never sends the admin token to the browser |
| **V9 Communications** | 🟡 | The app speaks plain HTTP and expects TLS termination in front (ingress / load balancer); the DB DSNs in `.env.example` use `sslmode=disable` for local dev. **Deployment requirement:** TLS 1.2+ at the edge, `sslmode=verify-full` to Postgres, HSTS at the edge |
| **V10 Malicious code** | ✅ | gosec, govulncheck, semgrep, osv-scanner, gitleaks (with canary) in CI; SBOMs (CycloneDX) for Go + JS; pinned lockfile; no dynamic code execution (only `wasm-unsafe-eval` for the verifier) |
| **V11 Business logic** | 🟡 | Per-tenant token-bucket rate limits (429 + Retry-After); idempotency blocks double-processing. **Gap:** limits are per API instance; use a shared limiter for multi-instance deployments |
| **V12 Files and resources** | ✅ / n/a | No server-side file uploads; bundle uploads in `/verify` are parsed only in the browser; body size limits (256 KiB events, 4 MiB OTLP) |
| **V13 API and web service** | ✅ | Strict JSON contracts with unknown fields rejected, per-route scopes, a CORS allowlist, correct status codes, signed state-changing requests (except OTLP: exporters can't sign, so it gets a dedicated `otlp:write` scope) |
| **V14 Configuration** | 🟡 | Strict nonce-based CSP, `nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, Referrer-Policy, Permissions-Policy, COOP; secrets only in the environment. **Gap:** a ZAP baseline runs in CI (`.github/workflows/dast.yml`) but has not run locally (no Docker here) |

## Open items before launch

1. **External penetration test** (owner: you): scope the API, dashboard, witness, and the SDK/sidecar supply chain.
2. KMS for the KEK/master key; SSO + MFA for operators (V2, V6).
3. TLS everywhere in the deployment manifests (V9).
4. A shared rate limiter for multi-instance deployments (V11).
5. First green run of the ZAP workflow on GitHub (V14).
