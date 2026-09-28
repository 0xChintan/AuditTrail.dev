# AuditTrail ledger specification (v1)

This spec defines the bytes that get hashed and signed. The Go ingestion API, the TypeScript `@audittrail/core` package, the verifier CLI and the in-browser verification portal all implement it. `schemas/test-vectors.json` holds known-good test cases, and every implementation's tests run against it.

## 1. Canonical event payload

For each sealed row, build this JSON object. All keys are always present; missing optional values are `null`.

| key | value |
|---|---|
| `v` | `1` |
| `id` | event UUID, lowercase |
| `tenant_id` | tenant UUID, lowercase |
| `timestamp` | UTC, millisecond precision, `YYYY-MM-DDTHH:MM:SS.sssZ` (the output of JS `Date#toISOString()`) |
| `human_principal_id` | string or `null` |
| `agent_id` | string |
| `model_id` | string or `null` |
| `model_version` | string or `null` |
| `delegation_chain` | JSON array or `null` |
| `action` | string |
| `target_resource` | string |
| `outcome` | `"allowed"`, `"denied"` or `"error"` |
| `metadata` | JSON object or `null` |

Serialize it with **RFC 8785 JSON Canonicalization Scheme (JCS)**: object keys sorted by UTF-16 code units, no whitespace, ECMAScript number formatting and minimal string escaping. Call the resulting UTF-8 bytes `canonical_payload`.

`seq` is deliberately **not** part of the payload. Order is fixed by the hash links, so a renumbered `seq` shows up as a broken link.

## 2. Chain hash

```
hash = lowercase_hex( SHA-256( ascii(previous_hash) || canonical_payload ) )
```

`previous_hash` is the 64-character lowercase hex hash of the tenant's previous row. For a tenant's first row it is the genesis value: 64 × `"0"`.

## 3. Row signature

Each sealed row is signed with the tenant's Ed25519 signing key (identified by `key_id`):

```
signature = base64( Ed25519.sign( "audittrail.event.v1\n" || ascii(hash) ) )
```

## 4. Merkle checkpoints

A checkpoint covers the contiguous run of rows `first_seq..last_seq` for one tenant. The tree is built the way RFC 6962 (Certificate Transparency) builds it:

```
leaf(i)   = SHA-256( 0x00 || raw32(hash_i) )
node(l,r) = SHA-256( 0x01 || l || r )
MTH(D[n]) : for n > 1, k = largest power of two < n,
            MTH = node( MTH(D[0:k]), MTH(D[k:n]) )
```

The checkpoint **statement** is this JCS-canonicalized object:

```json
{"created_at":"…Z","first_seq":1,"head_hash":"<hash of row last_seq>","last_seq":42,
 "merkle_root":"<hex>","prev_checkpoint_head":"<head_hash of prior checkpoint or genesis>",
 "row_count":42,"tenant_id":"…","type":"audittrail.checkpoint.v1"}
```

```
checkpoint.signature = base64( Ed25519.sign( statement_bytes ) )
```

## 5. External anchor

`SHA-256(statement_bytes)` is submitted to an RFC 3161 Time-Stamp Authority. The DER-encoded TimeStampToken (base64) is stored in `checkpoints.external_anchor_proof`. A verifier checks three things: the token's message imprint equals `SHA-256(statement_bytes)`, the token's CMS signature is valid, and the TSA certificate is trusted.

## 6. What a verifier checks

1. For every row, recompute `canonical_payload` from the stored columns, then recompute `hash` → it must match.
2. Each row's `previous_hash` equals the prior row's `hash`. The first row links to genesis, or to the `head_hash` of the checkpoint that ends just before it, if earlier rows were purged under retention.
3. `seq` has no gaps.
4. Every row signature verifies under the tenant public key named by its `key_id`.
5. For every checkpoint, recompute the Merkle root over its rows, check that `head_hash` matches row `last_seq`, check the statement signature, and check the external anchor.
