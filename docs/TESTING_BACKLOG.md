# Testing backlog (v1 follow-ups, finish after the v2 build)

Tests the v1 build didn't cover, or covered only with scripts. Items the v2 plan already contains are marked **→ v2 x.y** and will be done there.

## Dashboard (v1 Phase 7.1 / 7.2)
- [ ] Browser click-through tests (Playwright): onboard a tenant → key shown once → create and revoke an API key → rotate the signing key → set and release a legal hold → download PDF/CSV/bundle.
- [ ] Event sheet: "Verify in this browser" button in a real browser: all green for a genuine record, red for a tampered one.
- [ ] /verify portal in a real browser: record, proof and bundle tabs, including drag-and-drop of a large bundle (100k rows) and progress display.
- [ ] Error states: API down, tenant not found, expired admin token.
- [ ] `DASHBOARD_PASSWORD` gate: pages blocked, /verify still public.
- [ ] Dark mode and narrow screens (the sidebar is hidden below `md` and there's no mobile nav yet).
- [ ] XSS payloads in event fields render inert → v2 6.1 (D1)

## Ingestion API
- [ ] Signing-key rotation during a concurrent write burst: every row verifies under the right `key_id`.
- [ ] Rate limiter across multiple instances (currently per instance) → decide whether to use a Postgres or Redis limiter.
- [ ] Export of a very large tenant (250k-row cap): response time and memory; PDF capped at 2,000 rows.
- [ ] Stress at 10k writers + kill -9 mid-transaction → v2 1.3
- [ ] Fuzz the ingest parser → v2 1.4

## Checkpoint worker / anchoring
- [ ] TSA outage: checkpoints stay `pending`, retry, then reach `failed` after 48 attempts; verifier warns and doesn't fail.
- [ ] Two workers running at once: the advisory lock prevents duplicate or overlapping checkpoints.
- [ ] Verify with `--system-roots` against DigiCert/Sectigo tokens (the FreeTSA root is pinned in the repo).
- [ ] Split view / witnesses → v2 3.2 (A6)

## SDK
- [ ] Offline for hours, then restore → v2 2.2
- [ ] Browser build of the SDK (memory queue): behavior on page unload.
- [ ] Express/Next.js helpers in real apps (only unit-level coverage today).

## MCP sidecar
- [ ] **One week of daily use in real Claude Code sessions (v1 7.3)**: record identity-mapping errors in `docs/DOGFOOD.md`.
- [ ] More hosts: Claude Desktop, Cursor, VS Code, and a remote HTTPS MCP server with OAuth.
- [ ] stdio→HTTP mode (`--upstream` without `--listen`) against a remote server (only HTTP↔HTTP and stdio↔stdio were tested).
- [ ] Long-running and cancelled calls (`notifications/cancelled`), progress notifications, large results (>1 MB).
- [ ] Proxy crash mid-call: the event is in the journal and delivered on restart.
- [ ] Conformance / zero behavior change → v2 4.1; rug-pull → v2 4.2; heartbeats → v2 4.4

## Release (v1 7.4)
- [ ] `npm publish` dry run from CI with provenance → v2 7.3
- [ ] Fresh-machine quickstart run by someone other than us (the "outside person" DoD).
- [ ] CI workflow actually green on GitHub (only its steps were run locally).
