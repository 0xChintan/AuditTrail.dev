# Build progress

Status of each blueprint phase and its Definition of Done (DoD), with the command that proves it. Newest notes are at the bottom of each phase.

| Phase | Status | DoD evidence |
|---|---|---|
| 0 Foundation | ✅ | `pnpm install` + `go build ./...` from the repo root |
| 1 Data model | ✅ | `go test ./internal/db` — UPDATE/DELETE/TRUNCATE as `audittrail_app` → permission denied |
| 2 Ingestion API | ✅ | `bin/stress -api :8080,:8081 -n 1000` — 0 broken links across 2 instances |
| 3 SDK | ✅ | `node scripts/e2e-sdk-network.mjs` — network killed mid-record(), events arrive in order, once |
| 4 MCP sidecar | ✅ | `node packages/mcp-sidecar/test/e2e.mjs` (stdio + HTTP, sampling/elicitation nesting) and a real Claude Code run (`docs/DOGFOOD.md`) |
| 5 Checkpoints + anchor + verifier | ✅ | `scripts/tamper-demo.sh`: superuser edits and deletes are detected and localized; the worker refuses to checkpoint a tampered chain. `go test ./internal/verify` covers the adversary cases (rehash without key, stolen key, forged checkpoint, deleted row, untrusted TSA, purged prefix) |
| 6 Compliance export | ✅ | `GET /v1/export?template=eu-ai-act-art12\|soc2-cc7.2\|nist-800-53-au3&format=pdf\|csv\|bundle`; `scripts/retention-demo.sh` (legal hold blocks purge; the chain verifies after purge) |
| 7.1 Dashboard | ✅ | `apps/dashboard`: onboarding (key shown once plus setup snippets), API key management, signing-key rotation, live activity timeline with denied/error filters, identity-chain view, checkpoints, exports, legal hold/retention/rate limit |
| 7.2 Verification portal | ✅ | `/verify`: single record, inclusion proof or whole bundle, all computed in the browser (WebCrypto). The same logic was checked against a real proof: hash, signature, Merkle inclusion and checkpoint signature pass; a tampered copy fails |
| 7.3 Dogfood | 🟡 started | One real Claude Code session through the proxy, with findings fixed (`docs/DOGFOOD.md`). The one-week run needs you |
| 7.4 Publish + launch | 🟡 ready, not published | `pnpm pack` tarballs install cleanly and `npx audittrail-mcp-proxy --help` works; CI workflow, LICENSE, `docs/LAUNCH_POST.md` drafted. Publishing to npm/GitHub needs your accounts |

## What needs you

| # | Item | Status | Owner |
|---|---|---|---|
| 1 | Create the GitHub repo and push | ⏳ next | you |
| 2 | Set the real repo URL in the package.json `repository` fields (placeholder: `github.com/audittrail-dev/audittrail`) | ⏳ after 1 | Claude, once you give the URL |
| 3 | npm publish (`@audittrail` scope, 2FA, provenance) | ⏳ | you (moved to v2 7.3) |
| 4 | One week of daily Claude Code use through the proxy | ⏳ | you, see `docs/TESTING_BACKLOG.md` |
| 5 | Production hardening: KMS master key, shared rate limiter, SSO | ⏳ | v2 plan (1.2 / 5.1 / roadmap) |
| 6 | Legal review of clause text in `internal/export/templates.go` | ⏳ | you + counsel |
| 7 | Update the launch post and exports to the Digital Omnibus timeline (Annex III: 2 Dec 2027) | ⏳ | v2 6.2 |
| 8 | Remaining v1 tests (dashboard browser tests, TSA outage, more MCP hosts, …) | ⏳ | `docs/TESTING_BACKLOG.md` |

## Next: v2 secure-by-design build (phases 0–7)

Starts after the repo is pushed and you say **go**. Each phase finishes only when its Gate passes. Proposed decisions (confirm or change before starting):

1. Evolve this repo; add `spec_version`, so v1 rows keep verifying under v1 rules and new rows use the v2 length-prefixed hash.
2. Run 3 local C2SP witnesses with a 2-of-3 quorum. Public witnesses are a roadmap item.
3. Keep the replay-nonce cache in Postgres (no Redis).
4. Install gosec, govulncheck, gitleaks, osv-scanner, semgrep and k6 locally. OWASP ZAP runs only in GitHub CI.

Can't be done by Claude: the external pentest (7.1), the 15 validation calls (7.4) and npm/GitHub publishing (7.3).

## Deviations from the blueprint (and why)

- **Hash submission modes.** 2.2 had the client claim `hash`/`previousHash`, but 3.1 says the SDK doesn't compute hashes. Both are supported: *server-sealed* (default, used by the SDK and proxy) and *optimistic* (if a client sends `previous_hash`/`hash`, a mismatch returns 409). The stress test covers both.
- **Schema additions** to Appendix A (names kept): `seq`, per-row `signature`/`key_id`, checkpoint `first_seq`/`last_seq`/`head_hash`/`statement`/anchor columns, plus `tenants`, `api_keys`, `signing_keys` and `purge_log` tables.
- **SERIALIZABLE plus a per-tenant in-process queue.** The blueprint's SERIALIZABLE + FOR UPDATE is kept (with retries on 40001). The in-process queue stops requests within one instance from wasting retries on each other. Correctness across instances still comes from Postgres, as the two-instance stress test shows.
- **Checkpoints sign a statement, not just the root.** The signed, time-stamped object is a canonical statement: root + seq range + head hash + previous checkpoint head. A bare root doesn't say which rows it covers.
