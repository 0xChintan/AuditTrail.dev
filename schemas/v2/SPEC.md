# AuditTrail message contract, spec_version 2

This spec is normative. The Go server and verifier, the TypeScript SDK and core, and the WASM verifier all implement it, and all must reproduce `schemas/v2/vectors.json` byte for byte. v1 rows (`spec_version` 1, `schemas/SPEC.md`) stay verifiable under v1 rules. A tenant's chain may contain both.

## 1. Envelope (client → `POST /v2/events`)

A JSON object with exactly these members. Any other member is rejected (`unknown_field`).

| member | type | rules |
|---|---|---|
| `spec_version` | string | required, `"2"` |
| `event_id` | string | required. UUIDv7, lowercase canonical form. It is the **idempotency key**. |
| `occurred_at` | string | required. RFC 3339 with `Z` or an offset. Normalized to UTC with **millisecond** precision, truncating extra digits. **Untrusted.** |
| `agent` | object | required: `{ "id": string 1..256, "version"?: string ≤128 }` |
| `principal` | object\|null | `{ "id": string 1..512, "type": "human"\|"service" }`. `null` means autonomous. |
| `model` | object\|null | `{ "id": string 1..256, "version"?: string\|null, "provider"?: string\|null }` |
| `delegation` | array | ≤ 32 frames `{ "type": string 1..64, "id": string 1..512, … }`, outermost first. Extra frame members must be strings, numbers, booleans or null. |
| `action` | string | 1..256 chars, `[A-Za-z0-9._:/-]+` |
| `resource` | string | 1..2048 chars |
| `outcome` | string | `allowed` \| `denied` \| `error` |
| `payload` | object\|null | Any JSON (see §2). Stored, but **not** hashed directly (see `payload_hash`). |
| `payload_hash` | string | required. Lowercase hex `SHA-256(JCS(payload))`, where a `null`/absent payload hashes `null`. The server recomputes it and rejects a mismatch (`payload_hash_mismatch`). |
| `pii` | object\|null | `{ "subject": string 1..256, "fields": { name: string } }`. Plaintext over TLS. The **server** encrypts each field with the subject's DEK *before* sealing (§4). |

Optional members may be absent; absent is treated exactly like `null` (or `[]` for `delegation`).

## 2. Parsing and canonicalization

Input is processed by a strict parser, in this order. The first failure wins.

| check | status | code |
|---|---|---|
| body > 262,144 bytes | 413 | `body_too_large` |
| not valid UTF-8 | 400 | `invalid_utf8` |
| JSON syntax error (including `NaN` or `Infinity`) | 400 | `invalid_json` |
| `\uD800`–`\uDFFF` escape not forming a valid pair | 400 | `invalid_surrogate` |
| duplicate object key (at any depth) | 400 | `duplicate_key` |
| nesting depth > 16 (top-level object = depth 1) | 400 | `depth_exceeded` |
| any number with \|value\| > 2^53, integer literal or not (send it as a string) | 400 | `unsafe_integer` |
| number not finite as an IEEE-754 double | 400 | `non_finite_number` |
| U+0000 in any string or key | 422 | `invalid_value` |
| schema rules in §1 | 422 | `missing_field` / `unknown_field` / `wrong_type` / `invalid_value` / `unsupported_spec_version` |
| `payload_hash` ≠ recomputed | 422 | `payload_hash_mismatch` |

Integer literals are checked exactly (big-integer comparison). Any other literal is checked after conversion to a double. Every double above 2^53 is integral, and its canonical form would otherwise not re-parse.

**Canonical JSON** is RFC 8785 (JCS) over the parsed value. Keys are sorted by UTF-16 code units; numbers use ECMAScript `Number.prototype.toString`.

## 3. Sealed record and record hash

The server assigns `tenant_id`, `seq` (starting at 1, gap-free per tenant), `received_at` (UTC ms), `prev_hash` (the previous record's hash, or 64 × `0` for the first record) and `pii_ct` (§4).

```
LP(x)   = uint32_be(len(x)) || x          (x = UTF-8 bytes)
LP(nil) = 0xFFFFFFFF                       (null; distinct from empty)

hash = hex( SHA-256(
  "AuditTrail/v2/record\x00"
  || LP(spec_version) || LP(tenant_id) || LP(decimal(seq)) || LP(event_id)
  || LP(occurred_at)  || LP(received_at)
  || LP(JCS(agent))   || LP(JCS(principal) | nil) || LP(JCS(model) | nil)
  || LP(JCS(delegation))
  || LP(action) || LP(resource) || LP(outcome) || LP(payload_hash)
  || LP(JCS(pii_ct) | nil) || LP(prev_hash) ))
```

Every field is length-prefixed, so shifting bytes across a field boundary can't produce the same hash.

The **receipt signature** is `Ed25519(tenant log key, "AuditTrail/v2/receipt\n" || hash)`.

The **request digest** is `hex(SHA-256(JCS(envelope)))`, used for idempotency. A repeated `event_id` with the same digest returns 200 with the original receipt; with a different digest it returns 409 `idempotency_conflict`.

## 4. PII encryption (crypto-shredding)

Each `(tenant, subject)` has a 256-bit DEK, wrapped by the KEK. Each field is encrypted with AES-256-GCM (random 96-bit nonce, AAD = `tenant_id|subject|field|event_id`).

```
pii_ct = { "subject": s, "kid": dek_id, "fields": { name: { "n": b64(nonce), "c": b64(ciphertext||tag) } } }
```

The hash covers `pii_ct`, not the plaintext. Destroying the DEK makes the plaintext unrecoverable, while every hash, proof and signature stays valid.

## 5. Merkle log (RFC 9162)

Leaf *i* (for seq *i+1*) is `SHA-256(0x00 || raw32(hash))`, and nodes are `SHA-256(0x01 || L || R)`. Inclusion and consistency proofs follow RFC 9162 §2.1.3 and §2.1.4. v1 rows join the same log; their leaf is their v1 hash.

## 6. Checkpoints (C2SP tlog-checkpoint + signed-note)

```
audittrail.dev/log/<tenant_id>\n
<tree size>\n
<base64 root>\n
\n
— audittrail.dev/log/<tenant_id> base64(keyID || Ed25519 sig)\n     (log, type 0x01)
— <witness name> base64(keyID || u64 time || Ed25519 sig)\n          (cosignature/v1, type 0x04)
```

- The log key ID is `SHA-256(name || 0x0A || 0x01 || pub)[:4]`.
- A witness cosigns `"cosignature/v1\ntime <t>\n" || note body`, with key ID `SHA-256(name || 0x0A || 0x04 || pub)[:4]`.
- Witnesses implement C2SP `tlog-witness` `add-checkpoint`: they check consistency from the last size they cosigned, refuse rollbacks and forks, and persist before responding.
- A checkpoint is **trusted** when its log signature verifies and at least `quorum` of the verifier's configured witnesses (N-of-M) cosigned it. An RFC 3161 token over the note body is an additional time anchor.

## 7. Request authentication

- `Authorization: Bearer at2_<prefix12hex>_<secret43>`. The server stores `HMAC-SHA256(pepper, key)`, compared in constant time. Each key also carries scopes, an expiry and a revocation flag.
- The request signing key is `Ed25519 seed = HKDF-SHA256(ikm = key, salt = "AuditTrail/v2", info = "request-signing", 32)`. The server stores only the public key, recorded when the API key is created.
- Headers are `X-AT-Timestamp` (unix ms), `X-AT-Nonce` (16–64 chars `[A-Za-z0-9_-]`) and `X-AT-Signature` (base64 Ed25519) over:

```
"AuditTrail/v2/request\n" + METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + hex(SHA-256(body))
```

- A timestamp outside ±5 minutes, a reused `(key, nonce)`, or a bad signature returns 401. Responses never reveal which check failed.

## 8. Status codes

| status | meaning |
|---|---|
| 202 | Newly sealed; the body is the receipt |
| 200 | Idempotent replay; the body is the original receipt |
| 400 / 413 / 422 | See §2 |
| 401 / 403 | Authentication / scope |
| 409 | `idempotency_conflict` |
| 429 | Rate limited; `Retry-After` is set |

Error bodies are `{"error":{"code","message"}}` and never include internals.
