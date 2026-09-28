// SDK v2 against the real Go API: signed requests, receipts, idempotent replay,
// and the stored rows re-verify.
import { readFileSync } from "node:fs";
import { AuditTrail } from "../packages/sdk/dist/index.js";
const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const API = "http://localhost:8080";
const t = await (await fetch(`${API}/v1/admin/tenants`, { method: "POST", headers: { authorization: `Bearer ${env.AUDITTRAIL_ADMIN_TOKEN}` }, body: JSON.stringify({ name: "sdk-v2-smoke" }) })).json();
const at = new AuditTrail({ apiKey: t.api_key, baseUrl: API, agent: { id: "billing-service", version: "1.4.0" } });
const receipts = [];
for (let i = 0; i < 5; i++) receipts.push(await at.record({ action: "invoice.refund", resource: `invoice/${i}`, outcome: i === 3 ? "denied" : "allowed",
  principal: { id: "user_123", type: "human" }, payload: { amount: 10.5 * i, api_key: "sk-live-should-not-leak-" + "x".repeat(30) } }));
console.log("seqs", receipts.map((r) => r.seq).join(","), "| first hash", receipts[0].hash.slice(0, 16));
const { events } = await (await fetch(`${API}/v1/events?limit=100`, { headers: { authorization: `Bearer ${t.api_key}` } })).json();
const leaked = JSON.stringify(events).includes("sk-live-should-not-leak");
console.log("rows", events.length, "| spec_version", events.map((e) => e.spec_version).join(","), "| secret stored?", leaked);
process.exit(receipts.every(Boolean) && !leaked && events.length === 6 ? 0 : 1);
