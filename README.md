# AuditTrail.dev

**A tamper-evident audit ledger for AI agents and the humans they act for.**

AuditTrail records every action, including every tool call an MCP agent makes, in a per-tenant append-only log: a SHA-256 hash chain plus an RFC 9162 Merkle tree. Signed C2SP tree heads are cosigned by independent witnesses and time-stamped by an RFC 3161 authority. The result is evidence a reviewer can check offline *without trusting you or us*, exportable as reports mapped clause by clause to the **EU AI Act (Art. 12 / 19 / 26)**, **SOC 2 CC7.2** and **NIST SP 800-53 AU-3**.

```
 your app ── @audittrail/sdk ──┐  signed POST /v2/events   ┌──────────────────────────┐
 agent host ─▶ audittrail-mcp-proxy ─▶ any MCP server       │  Go ingestion API        │
            (zero code changes) └── mirror ────────────────▶│  auth + RLS + strict JSON │──▶ Postgres (append-only,
 OTel gen_ai spans ──────────── POST /v1/traces ───────────▶│  group-commit sequencer  │    row-level security)
                                                            └──────────────────────────┘
   tree-head worker ── C2SP signed note ──▶ witnesses (cosign, N-of-M) ── RFC 3161 TSA
   exports (PDF / CSV / v2 bundle) ──▶ audittrail-verify (CLI, or WASM in the browser, fully offline)
```

## Why it's different

- **Nobody has to trust the operator.** Witnesses cosign each tree head only if it is consistent with every head they saw before, so the log can't fork or rewrite history, even by someone holding the database and the signing key. The verifier checks 14 named invariants and names the exact rows that fail.
- **Secure by design.** Scoped `at2_` API keys stored as peppered HMACs; Ed25519-signed requests with replay protection; Postgres row-level security that fails closed; a strict JSON parser tested with 126 hostile vectors and fuzzing; secrets redacted before hashing; per-subject encryption so personal data can be crypto-shredded without breaking the log. See [THREAT_MODEL.md](THREAT_MODEL.md).
- **It captures agent identity.** The MCP proxy records the human principal, agent, model and version, and the delegation chain, including sampling and elicitation requests nested inside a tool call. A missing field is recorded as `"unknown"` with its provenance, never silently dropped. Tool definitions are pinned, so a server that changes a tool after approval (a "rug pull") is caught.
- **Denials and gaps are evidence too.** Policy-blocked calls, errors, calls that never got a response and declined elicitations are all recorded. Sidecars send heartbeats and number their events, so a silenced or bypassed proxy raises an alert.
- **Reports are what gets bought.** Exports label every column with the clause it evidences, and include the witnessed tree heads and anchors.

## Repository

| Path | What |
|---|---|
| `packages/ingestion-go` | Go API, tree-head/anchor worker, `audittrail-witness`, `audittrail-verify` (CLI + WASM), OTLP receiver, purge job, migrator, stress + load generators |
| `packages/core` | `@audittrail/core`: the v2 message contract in TypeScript (strict JSON, JCS, record hashing, UUIDv7), byte-identical to Go |
| `packages/sdk` | `@audittrail/sdk`: signed requests, redaction before hashing, fail-open durable spool, Express/Next.js helpers |
| `packages/mcp-sidecar` | `audittrail-mcp-proxy`: MCP audit sidecar (stdio and Streamable HTTP), tool pinning, heartbeats |
| `apps/dashboard` | Next.js dashboard (strict CSP, password-protected): onboarding, keys, activity timeline, tree heads, exports, retention/legal hold, in-browser verification |
| `schemas/` | `v2/SPEC.md` (the exact bytes that are hashed and signed), 318 cross-language test vectors, pinned TSA roots |
| `deploy/` | Container images and the production compose stack (TLS edge, TLS-only Postgres, KMS and SSO overlays) |
| `docs/` | Quickstart, deploying, ASVS L2 self-assessment, performance, releasing, validation kit, testing backlog, launch post draft |

## Quickstart (local)

Requirements: Go ≥ 1.26, Node ≥ 20 with pnpm, and Postgres ≥ 15 running locally.

```sh
scripts/setup.sh     # .env with fresh secrets, install, build, migrate
scripts/dev.sh       # API :8080, 3 local witnesses, worker, dashboard :3000
```

Then follow **[docs/QUICKSTART.md](docs/QUICKSTART.md)**: onboard a tenant, wrap an agent's MCP server, and produce a verifiable compliance export.

## Proofs that it works

| Claim | Run |
|---|---|
| Go and TS agree byte for byte on 318 vectors | `go test ./packages/ingestion-go/internal/contract` + `pnpm --filter @audittrail/core test` |
| Keys, signatures, replay, cross-tenant access and hostile input are rejected (S1–S6) | `go test ./packages/ingestion-go/internal/api` |
| 10k concurrent writers + `kill -9` of the API: 0 gaps, 0 duplicates | `bin/stress -n 10000 -c 128 -spawn ./bin/api -kill-at 0.4` |
| Network cut mid-`record()` and a reply lost after commit: in order, exactly once | `node scripts/e2e-sdk-network.mjs` |
| A superuser edit or delete is detected and localized to the row | `scripts/tamper-demo.sh` |
| Legal hold blocks purge; the log still verifies after purge | `scripts/retention-demo.sh` |
| Tampered bundles fail with a named invariant (A1–A7) | `go test ./packages/ingestion-go/internal/verify2` |
| Stored XSS payloads render inert under the CSP | `node scripts/xss-corpus.mjs` |
| Load: 4,783 req/s, p99 24.8 ms; Postgres restart loses nothing | [docs/PERFORMANCE.md](docs/PERFORMANCE.md) |
| Rate limits hold across API instances (119 of 120 allowed) | `go test ./packages/ingestion-go/internal/api -run RateLimit` |
| Dashboard SSO: allowlist, MFA, CSRF, tampered cookies, operator attribution (23 checks, real OpenID provider) | `node scripts/oidc-e2e.mjs` |
| Production stack through the TLS edge: TLS-only Postgres, signed ingest, witnessed tree head, offline verify | `deploy/compose/smoke.sh` (CI: `deploy-smoke.yml`) |

Security: [THREAT_MODEL.md](THREAT_MODEL.md), [SECURITY.md](SECURITY.md), [docs/ASVS-L2.md](docs/ASVS-L2.md), [SECRETS.md](SECRETS.md). Build log: [PROGRESS.md](PROGRESS.md).

## Scope notes

Production deployment: [docs/DEPLOYING.md](docs/DEPLOYING.md). It covers the TLS edge, TLS-only Postgres, the master key in a KMS, operator SSO and shared rate limits. Not yet done: per-region data residency, independent third-party witnesses, and the external penetration test ([docs/ASVS-L2.md](docs/ASVS-L2.md)).
