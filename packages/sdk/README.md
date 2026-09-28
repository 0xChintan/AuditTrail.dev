# @audittrail/sdk

Record tamper-evident audit events to [AuditTrail.dev](https://audittrail.dev). Each event is signed on the way out, sealed on the server into your tenant's append-only log (SHA-256 hash chain + RFC 9162 Merkle tree), and covered by tree heads that independent witnesses cosign. A reviewer can verify the evidence offline without trusting you or us.

```sh
npm install @audittrail/sdk
```

This is the v2 SDK (`spec_version: "2"`). It needs an `at2_…` API key. v1 `at_…` keys are rejected: create a new key in the dashboard.

## Quick start

```ts
import { AuditTrail } from "@audittrail/sdk";

const audit = new AuditTrail({
  apiKey: process.env.AUDITTRAIL_API_KEY!,      // at2_…
  baseUrl: "https://api.audittrail.dev",        // or your self-hosted ingestion API
  agent: { id: "billing-service", version: "1.4.2" },
});

const receipt = await audit.record({
  principal: { id: "user_123", type: "human" }, // null = autonomous
  action: "invoice.refund",
  resource: "invoice/INV-2041",
  outcome: "allowed",                // allowed | denied | error — record denials too
  payload: { amount: 120.5, currency: "EUR" },
});

receipt?.seq;                // position in your tenant's log
receipt?.hash;               // record hash (hex)
receipt?.receipt_signature;  // Ed25519 signature over the hash (key: receipt.key_id)
```

`audit.track(event)` does the same without waiting and returns the `event_id` immediately. `await audit.flush()` waits until everything queued has been delivered. `await audit.close()` flushes and stops.

## Guarantees

- **Fail-open by default.** Auditing never throws into your request path: `record()` resolves `null` if the event can't be delivered right now, and the event stays spooled and is retried. Use `failMode: "closed"` where a missing audit record must stop the operation.
- **Nothing dropped, nothing reordered, nothing duplicated.** Each event gets a UUIDv7 `event_id` (the idempotency key) the moment you call `record()`. A single sender delivers the spool in call order and retries the head with exponential backoff on network errors, 5xx, 429 and auth failures. If a request committed but its response was lost, the retry returns the original receipt, not a second row.
- **Signed requests.** Every write carries an Ed25519 signature over the method, path, timestamp, nonce and body hash, using a key derived from your API key. A stolen bearer token alone can't forge writes, and replays are rejected.
- **Secrets are redacted before hashing.** Built-in patterns (cloud keys, GitHub/OpenAI/Anthropic/Stripe tokens, JWTs, PEM blocks, URL passwords, …) are replaced before the event is hashed, so a secret never enters the immutable log. Pass `redact: { patterns, secretKeys, piiKeys }` to extend it, or `redact: false` to turn it off.
- **Personal data is crypto-shreddable.** Put personal data in `pii: { subject, fields }`, not in `payload`. The server encrypts it under a per-subject key; `POST /v2/subjects/{subject}/erase` destroys that key. The log keeps verifying because the hash covers the ciphertext.
- **Survives restarts and long outages (Node).** Use the file-backed spool:

```ts
import { AuditTrail, FileSpool } from "@audittrail/sdk/node";

const audit = new AuditTrail({
  apiKey: process.env.AUDITTRAIL_API_KEY!,
  agent: { id: "billing-service" },
  spool: new FileSpool("/var/lib/myapp/audittrail.spool"),
  onError: (err) => console.error("audit delivery issue", err.code),
  onMetric: (m) => m.name === "spool_size" && gauge.set(m.value),
});
```

Tested with 60 minutes offline plus delayed, duplicated and dropped-after-commit responses: every event arrives exactly once, in order.

## Express

```ts
import express from "express";
import { AuditTrail } from "@audittrail/sdk";
import { auditTrailMiddleware } from "@audittrail/sdk/express";

const audit = new AuditTrail({ apiKey: process.env.AUDITTRAIL_API_KEY!, agent: { id: "orders-api" } });
const app = express();

// Records every POST/PUT/PATCH/DELETE after the response is sent.
// 401/403 -> "denied", other 4xx/5xx -> "error", everything else -> "allowed".
app.use(auditTrailMiddleware(audit, {
  principal: (req) => (req as any).user?.id,
  action: (req) => `orders.${req.method.toLowerCase()}`,
}));
```

## Next.js (App Router)

```ts
// app/api/invoices/[id]/route.ts
import { AuditTrail } from "@audittrail/sdk";
import { withAuditTrail } from "@audittrail/sdk/next";
import { auth } from "@/auth";

const audit = new AuditTrail({ apiKey: process.env.AUDITTRAIL_API_KEY!, agent: { id: "web-app" } });

export const DELETE = withAuditTrail(audit, {
  action: "invoice.delete",
  principal: async () => (await auth())?.user?.id,
}, async (req) => {
  // … your handler …
  return Response.json({ ok: true });
});
```

## Event fields

| field | required | notes |
|---|---|---|
| `action` | yes | e.g. `invoice.refund` |
| `resource` | yes | e.g. `invoice/INV-2041` |
| `outcome` | yes | `allowed`, `denied` or `error` |
| `principal` | no | `{ id, type: "human" \| "service" }` on whose behalf this ran; `null` = autonomous |
| `agent` | no | Overrides `options.agent` for this event |
| `model` | no | `{ id, version?, provider? }` for AI agents |
| `delegation` | no | `[{ type: "human", id }, { type: "agent", id }, …]`, outermost first |
| `payload` | no | Any JSON object (covered by the hash via `payload_hash`). Numbers must be within ±2^53; no `\u0000` |
| `pii` | no | `{ subject, fields }`: encrypted server-side, erasable per subject |
| `occurredAt` | no | Defaults to now; the server also records `received_at` |
| `eventId` | no | Your own UUIDv7, to make an event idempotent across processes |

The exact bytes that are hashed and signed are specified in [`schemas/v2/SPEC.md`](https://github.com/0xChintan/AuditTrail.dev/blob/main/schemas/v2/SPEC.md).

## Verifying

Export an evidence bundle (dashboard, or `GET /v2/export`) and check it offline with `audittrail-verify`. Pin the tenant's log key and the witnesses you trust:

```sh
audittrail-verify --log-key "$(cat log.vkey)" --witness "$(cat w1.vkey)" --witness "$(cat w2.vkey)" --quorum 2 bundle.json
```

The same verifier, compiled to WebAssembly, runs in the dashboard's **/verify** page with no network access.
