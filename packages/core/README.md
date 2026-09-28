# @audittrail/core

The AuditTrail ledger spec ([SPEC.md](../../schemas/SPEC.md)) in TypeScript, with zero dependencies. It runs in Node ≥ 20 and modern browsers, using WebCrypto for SHA-256 and Ed25519.

- `canonicalize(value)`: RFC 8785 JSON Canonicalization Scheme
- `canonicalPayload(event)`, `computeEventHash(prev, event)`: the exact bytes that are hashed
- `verifyRecord(record, publicKeys, previous?)`: recomputes the hash and checks the signature and chain link
- `verifyBundle(bundle)`: verifies an exported evidence bundle (hashes, links, seq gaps, signatures, Merkle roots, checkpoint signatures)
- `merkleRoot(hashes)`, `verifyInclusion(...)`: RFC 6962 / RFC 9162

The output matches the Go implementation byte for byte; both are tested against `schemas/test-vectors.json`. RFC 3161 time-stamp tokens are validated by the Go `audittrail-verify` CLI.
