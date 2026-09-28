# AuditTrail.dev

**A tamper-evident audit ledger for AI agents and the humans they act for.**

AuditTrail records every action, including every tool call an MCP agent makes, as a SHA-256 hash-chained, Ed25519-signed record. Records are grouped into Merkle checkpoints, and each checkpoint is time-stamped by an independent RFC 3161 authority. The result is evidence a reviewer can check *without trusting you or us*, exportable as reports mapped clause by clause to the **EU AI Act (Art. 12 / 19 / 26)**, **SOC 2 CC7.2** and **NIST SP 800-53 AU-3**.

```
            ┌─────────────────────┐   POST /v1/events    ┌──────────────────────────┐
 your app ──│ @audittrail/sdk      │─────────────────────▶│                          │
            └─────────────────────┘                       │  Go ingestion API        │
 agent host ─▶ audittrail-mcp-proxy ─▶ any MCP server      │  per-tenant chain head   │──▶ Postgres (append-only
            (zero code changes)  └───── mirror ──────────▶│  SERIALIZABLE + FOR UPDATE│    by role grants)
                                                          └──────────────────────────┘
                                   checkpoint worker ── Merkle root ── Ed25519 ── RFC 3161 TSA
                                   exports (PDF/CSV/bundle) ── audittrail-verify / browser portal
```

## Why it's different

- **The server holds the chain.** The chain head lives in Postgres, one row per tenant. Appends run in a `SERIALIZABLE` transaction with `SELECT … FOR UPDATE`, and the server recomputes the hash. Tested with 1,000 concurrent writes across two API instances: 0 broken links, 0 gaps.
- **It captures agent identity.** The MCP proxy records the human principal, agent, model and version, and the delegation chain, including sampling and elicitation requests nested inside a tool call. A missing field is recorded as `"unknown"` with its provenance, never silently dropped.
- **Denials are evidence too.** Policy-blocked calls, errors, calls that never got a response, and human-declined elicitations are all recorded.
- **Verification doesn't depend on trusting the operator.** The external RFC 3161 anchors mean that even a database superuser holding the signing key can't rewrite history undetected. See `scripts/tamper-demo.sh` and `internal/verify/verify_test.go`.
- **Reports are what gets bought.** Exports label every column with the clause it evidences, and include the covering checkpoints and anchor proofs.

## Repository

| Path | What |
|---|---|
| `packages/ingestion-go` | Go API, checkpoint/anchor worker, `audittrail-verify`, purge job, migrator, stress test |
| `packages/core` | `@audittrail/core`: the ledger spec in TypeScript (JCS, hashing, Merkle, verification) for Node and the browser |
| `packages/sdk` | `@audittrail/sdk`: server-sealed events, ordered durable retry queue, Express/Next.js helpers |
| `packages/mcp-sidecar` | `audittrail-mcp-proxy`: MCP audit sidecar (stdio and Streamable HTTP) |
| `apps/dashboard` | Next.js dashboard: onboarding, keys, activity timeline, exports, retention/legal hold, verification portal |
| `schemas/` | Event JSON Schema, `SPEC.md` (the bytes that get hashed and signed), cross-language test vectors, pinned TSA roots |
| `docs/` | Quickstart, dogfood log, launch post draft |

## Quickstart (local)

Requirements: Go ≥ 1.26, Node ≥ 20 with pnpm, and Postgres ≥ 15 running locally.

```sh
scripts/setup.sh     # .env with fresh secrets, install, build, migrate
scripts/dev.sh       # API :8080, checkpoint worker, dashboard :3000
```

Then follow **[docs/QUICKSTART.md](docs/QUICKSTART.md)**: onboard a tenant, wrap an agent's MCP server, and produce a verifiable compliance export.

## Proofs that it works

| Blueprint DoD | Run |
|---|---|
| 1.2 App role can't UPDATE/DELETE the ledger | `cd packages/ingestion-go && go test ./internal/db` |
| 2.4 1,000 concurrent appends, 0 broken links | `bin/stress -api http://localhost:8080,http://localhost:8081 -n 1000` |
| 3.1 Network killed mid-`record()`: events still arrive, in order, once | `node scripts/e2e-sdk-network.mjs` |
| 4 Real agent → proxy → MCP server → correct identity chain | `node packages/mcp-sidecar/test/e2e.mjs`, [docs/DOGFOOD.md](docs/DOGFOOD.md) |
| 5.3 Direct DB edit is detected and localized | `scripts/tamper-demo.sh` |
| 6.3 Legal hold blocks purge; chain verifies after purge | `scripts/retention-demo.sh` |
| Go/TS byte-for-byte agreement | `go test ./internal/canon` + `pnpm --filter @audittrail/core test` |

Security model and key rotation: [SECRETS.md](SECRETS.md). Build log: [PROGRESS.md](PROGRESS.md).

## Scope notes

Out of scope for the MVP, as in the blueprint: full KMS integration (the master key currently lives in `.env`), per-region data residency, and SLA/pricing. The rate limiter works per API instance; use Redis for a global limit.
# AuditTrail.dev
