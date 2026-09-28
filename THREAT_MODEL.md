# Threat model

AuditTrail is a **neutral evidence layer**: it records what systems and agents report, and lets anyone verify those records offline without trusting the operator.

## What we guarantee, and what we don't

**Guaranteed**, given a correct verifier and honest witnesses or anchors:

- **Tamper-evidence** of every recorded event: any edit, deletion, reorder or truncation is detectable.
- **Ordering**: a gap-free per-tenant sequence, fixed by the hash chain and the Merkle log.
- **Time bounds**: an event existed no later than its checkpoint's external anchor (RFC 3161 token or witness cosignature time).
- **Erasure of PII** by crypto-shredding, without breaking integrity: hashes cover ciphertext.

**Not guaranteed:**

- **That events are truthful.** A compromised client can log lies. We prove what was *recorded*, not what *happened*.
- **That unsent events exist.** An event that never reached us can't be proven. Sidecar heartbeats (T11) make silent gaps *detectable*, not impossible.
- **That crypto-shredding is legally sufficient erasure.** This is unsettled and varies by jurisdiction; get legal advice. Plaintext that existed before shredding in backups, client spools or downstream exports isn't covered.
- **`occurred_at` accuracy.** It's client-supplied and untrusted. `received_at` and the anchors are the trusted time.

## Assets and trust boundaries

| Asset | Where |
|---|---|
| Ledger rows (events, hashes, seq) | Postgres (`agent_events`) |
| Tenant log signing keys (Ed25519) | `signing_keys`, sealed under the master key/KEK |
| Per-subject DEKs (PII) | `subject_keys`, wrapped by the KEK |
| API keys | HMAC(pepper) only, in `api_keys` |
| Checkpoints / cosignatures / anchors | `checkpoints`, witnesses, TSA |

The trust boundaries are: client → API (TLS, signed requests), API → DB (least-privilege roles + RLS), log → witnesses/TSA (independent parties), and bundle → verifier (offline, no trust in us).

## Threats, controls and tests

Every row has an owner and at least one test ID; CI runs every test ID. **Status** is updated as the v2 phases land.

| ID | Threat | Control | Test IDs | Owner | Status |
|---|---|---|---|---|---|
| T1 | Edit, delete or reorder a row | Length-prefixed record hash chain, gapless `seq`, Merkle inclusion | A1, A2, A3 | `internal/verify2` | ✅ tested |
| T2 | Truncate the tail or rewrite the whole chain | Checkpoints anchored externally (RFC 3161 + witness cosignatures), consistency proofs | A4, A5 | `internal/treehead`, `internal/verify2` | ✅ tested |
| T3 | Split view (two histories shown to different parties) | C2SP signed-note checkpoints, witness quorum N-of-M, cross-bundle fork detection | A6 | `cmd/witness`, `internal/verify2` | ✅ tested |
| T4 | Log signing-key compromise | Key IDs, rotation, key validity windows; anchors and witnesses expose forged history | A7 | `internal/keys`, `internal/verify2` | ✅ tested |
| T5 | Replay or duplicate submission | Ed25519 request signature over method, path, timestamp, nonce and body hash; ±5 min skew; nonce cache; `event_id` idempotency | S3, S4 | `internal/api` | ✅ tested |
| T6 | Cross-tenant access (IDOR) | Postgres RLS with `SET LOCAL app.tenant_id` on every transaction; tenant in every query | S5 | `migrations`, `internal/db` | ✅ tested |
| T7 | Malformed or hostile payloads | Strict parser (duplicate keys, invalid UTF-8, lone surrogates, unsafe integers, depth ≤ 16, body ≤ 256 KB, unknown fields), JCS | S6, fuzz | `internal/contract` | ✅ tested (126 vectors over HTTP, 2×30 min fuzz) |
| T8 | Secrets or PII leaking into logs | SDK redaction before hashing; sidecar secret scanning; PII encrypted per subject | C4, M2 | `packages/sdk`, `packages/mcp-sidecar` | ✅ tested (C4, M2) |
| T9 | Malicious MCP tool text (prompt injection) | All tool text treated as inert data: never interpreted, forwarded byte-for-byte, escaped on display | M1, D2 | `packages/mcp-sidecar`, `apps/dashboard` | M1 ✅; D2 ✅ (6.1: tool names/results/resources in the XSS corpus render as escaped text; CSV formula guard + text-only PDF in exports) |
| T10 | Tool "rug pull" (a definition changes after approval) | Hash and pin tool definitions; drift is logged as an event, optionally blocked | M3 | `packages/mcp-sidecar` | ✅ tested |
| T11 | Sidecar bypass or silent gaps | Heartbeats with the sidecar's own sequence counter; server-side gap and silence alerts | M4 | `packages/mcp-sidecar`, `internal/api/monitor.go` | ✅ tested |
| T12 | Stored XSS via log content | React escaping, no `dangerouslySetInnerHTML`, strict nonce-based CSP | D1 | `apps/dashboard` | ✅ (6.1: 0 canary hits, strict nonce CSP) |
| T13 | Supply-chain compromise of the SDK or proxy | npm provenance, pinned lockfiles, 2FA publish, signed binaries, SBOM, OSV scanning | R3 | release workflow | scanning + SBOM ✅ (0.3); provenance + cosign + attestations in `release.yml` ✅ (7.3); first real release + 2FA need you |

## Test ID index

| Test | Asserts |
|---|---|
| A1 | Editing any field of a row → verifier names *content-hash* broken at that seq |
| A2 | Deleting a row → *seq-continuity* and *inclusion* broken, missing seq named |
| A3 | Reordering two rows → *chain-link* broken |
| A4 | Truncating the tail → *consistency* with the anchored/cosigned checkpoint fails |
| A5 | Replaying an old checkpoint as current → *freshness* / *consistency* failure |
| A6 | Two histories served → witnesses refuse the second; verifier rejects it for lack of *witness-quorum*, and flags *fork* when both are seen |
| A7 | History signed by a forged or unauthorized key → *checkpoint-signature* / *key-authorization* failure |
| S1 | Bad request signature → 401 |
| S2 | Revoked key → 401 |
| S3 | Expired key or timestamp outside ±5 min → 401 |
| S4 | Replayed nonce → 401 |
| S5 | Tenant A reading or writing tenant B (API and direct DB with RLS) → blocked |
| S6 | Hostile input corpus → correct 400/413/422, never 500, never a panic |
| C4 | Planted secrets never reach the wire from the SDK |
| M1 | Injection payloads in tool text change nothing (bytes forwarded identically, stored as data) |
| M2 | Secrets in tool args/results are never stored in plaintext |
| M3 | Changing a tool definition produces a drift event |
| M4 | Killing the sidecar is detected as a gap |
| D1 | XSS corpus renders inert in the dashboard |
| D2 | Tool text shown escaped in the dashboard and exports |
| R3 | Release artifacts have provenance, signatures and an SBOM; the lockfile is frozen |
