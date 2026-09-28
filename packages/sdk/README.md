# @audittrail/sdk

Record tamper-evident audit events to [AuditTrail.dev](https://audittrail.dev). Each event is sealed on the server into your tenant's SHA-256 hash chain and signed with your tenant's Ed25519 key. The chain is periodically checkpointed into Merkle trees, and each checkpoint is time-stamped by an external RFC 3161 authority.

```sh
npm install @audittrail/sdk
```

## Quick start

```ts
import { AuditTrail } from "@audittrail/sdk";

const audit = new AuditTrail({
  apiKey: process.env.AUDITTRAIL_API_KEY!,      // at_…
  baseUrl: "https://api.audittrail.dev",        // or your self-hosted ingestion API
  agentId: "billing-service",
});

const sealed = await audit.record({
  human_principal_id: "user_123",
  action: "invoice.refund",
  target_resource: "invoice/INV-2041",
  outcome: "allowed",               // allowed | denied | error — log denials too
  metadata: { amount: 120.5, currency: "EUR" },
});

sealed.hash;          // SHA-256 chain hash
sealed.previous_hash; // previous row's hash in your tenant's chain
sealed.signature;     // Ed25519 signature (key: sealed.key_id)
sealed.seq;           // position in the chain
```

`audit.track(event)` does the same without waiting and returns the event id immediately. `await audit.flush()` waits until everything queued has been delivered.

## Delivery guarantees

- **The SDK never computes or stores chain hashes.** The server holds the chain head per tenant, so any number of app instances can write to the same chain safely.
- **Nothing is dropped if the network fails.** `record()` assigns each event its `id` and `timestamp` immediately and puts it in a local queue. A single sender delivers the queue in order. Network errors, 5xx and 429 responses retry the *head* of the queue with exponential backoff, so events are delayed but never skipped or reordered.
- **No duplicates.** The `id` is an idempotency key. If a request committed but its response was lost, the retry returns the original sealed record instead of writing a second row.
- **Rejected events don't block the queue.** An event the server permanently rejects (a 4xx validation error) rejects its promise, is reported through `onError`, and is removed so later events keep flowing.
- **Crash-safe (optional).** In Node, a file-backed queue sends events that were recorded but not yet acknowledged when the process restarts:

```ts
import { AuditTrail, FileQueueStore } from "@audittrail/sdk/node";

const audit = new AuditTrail({
  apiKey: process.env.AUDITTRAIL_API_KEY!,
  agentId: "billing-service",
  store: new FileQueueStore("/var/lib/myapp/audittrail-queue.jsonl"),
  onError: (err, event) => console.error("audit delivery issue", err.code, event?.id),
});
```

## Express

```ts
import express from "express";
import { AuditTrail } from "@audittrail/sdk";
import { auditTrailMiddleware } from "@audittrail/sdk/express";

const audit = new AuditTrail({ apiKey: process.env.AUDITTRAIL_API_KEY!, agentId: "orders-api" });
const app = express();

// Records every POST/PUT/PATCH/DELETE after the response is sent.
// 401/403 -> outcome "denied", other 4xx/5xx -> "error", everything else -> "allowed".
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

const audit = new AuditTrail({ apiKey: process.env.AUDITTRAIL_API_KEY!, agentId: "web-app" });

export const DELETE = withAuditTrail(audit, {
  action: "invoice.delete",
  principal: async () => (await auth())?.user?.id,
}, async (req) => {
  // … your handler …
  return Response.json({ ok: true });
});
```

## Verifying records yourself

```ts
import { verifyRecord } from "@audittrail/sdk";

const keys = await (await fetch(`${baseUrl}/v1/tenants/${tenantId}/public-keys`)).json();
const check = await verifyRecord(sealed, keys.keys);
check.ok; // hash recomputed from content + Ed25519 signature valid
```

For whole-ledger verification, including Merkle checkpoints and the RFC 3161 anchors, use the `audittrail-verify` CLI on an exported bundle.

## Event fields

| field | required | notes |
|---|---|---|
| `agent_id` | yes (or `options.agentId`) | Acting service or agent. Use `"unknown"` rather than leaving it out. |
| `action` | yes | e.g. `invoice.refund` |
| `target_resource` | yes | e.g. `invoice/INV-2041` |
| `outcome` | yes | `allowed`, `denied` or `error` |
| `human_principal_id` | no | The human on whose behalf this ran. `null` means autonomous. |
| `model_id`, `model_version` | no | For AI agents. |
| `delegation_chain` | no | `[{ type: "human", id }, { type: "agent", id }, …]`, outermost first |
| `metadata` | no | Any JSON object; it's covered by the hash. |
| `id`, `timestamp` | no | Set automatically. Timestamps are stored at millisecond precision. |
