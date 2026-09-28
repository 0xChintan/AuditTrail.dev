// Phase 3 DoD: kill the network mid-record() and restore it; the events must
// still arrive, in order, exactly once. Runs against a real ingestion API
// through a TCP proxy we can unplug.
//
//   node scripts/e2e-sdk-network.mjs   (API on :8080, .env with admin token)
import net from "node:net";
import { readFileSync } from "node:fs";
import { AuditTrail } from "../packages/sdk/dist/index.js";
import { verifyBundle } from "../packages/core/dist/index.js";

const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
  .filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const API = process.env.API ?? "http://localhost:8080";
const ADMIN = env.AUDITTRAIL_ADMIN_TOKEN;
const PROXY_PORT = 18080;

// ---- unpluggable TCP proxy --------------------------------------------------
let server = null;
const sockets = new Set();
let swallowNextResponse = false; // forward the request, then cut the line before the reply
function plugIn() {
  server = net.createServer((client) => {
    const up = net.connect(new URL(API).port || 80, new URL(API).hostname);
    sockets.add(client); sockets.add(up);
    client.on("data", (d) => up.write(d));
    up.on("data", (d) => {
      if (swallowNextResponse) { swallowNextResponse = false; log("  proxy: request reached server, cutting the line before the response"); client.destroy(); up.destroy(); return; }
      client.write(d);
    });
    for (const s of [client, up]) { s.on("error", () => {}); s.on("close", () => { client.destroy(); up.destroy(); sockets.delete(s); }); }
  });
  return new Promise((r) => server.listen(PROXY_PORT, r));
}
function unplug() {
  for (const s of sockets) s.destroy();
  return new Promise((r) => server.close(() => r()));
}
const t0 = Date.now();
const log = (m) => console.log(`[${((Date.now() - t0) / 1000).toFixed(2)}s] ${m}`);

// ---- run --------------------------------------------------------------------
const created = await (await fetch(`${API}/v1/admin/tenants`, { method: "POST", headers: { authorization: `Bearer ${ADMIN}` },
  body: JSON.stringify({ name: "sdk-network-e2e" }) })).json();
const tenantId = created.tenant.id;
await plugIn();
const errors = [];
const at = new AuditTrail({ apiKey: created.api_key, baseUrl: `http://127.0.0.1:${PROXY_PORT}`, agentId: "sdk-e2e",
  retry: { baseDelayMs: 100, maxDelayMs: 500 }, timeoutMs: 2000, onError: (e) => errors.push(e.code) });

log("record #1 with network up");
await at.record({ action: "step.1", target_resource: "doc/1", outcome: "allowed" });

log("unplugging network; recording #2..#6 while it is down");
await unplug();
const inflight = [2, 3, 4, 5, 6].map((i) => at.record({ action: `step.${i}`, target_resource: `doc/${i}`, outcome: i === 4 ? "denied" : "allowed" }));
await new Promise((r) => setTimeout(r, 1500));
log(`  still pending locally: ${await at.pending()} (errors so far: ${errors.length})`);

log("restoring network, but the first reply will be lost after the server commits");
swallowNextResponse = true;
await plugIn();
const recs = await Promise.all(inflight);
log(`all record() promises resolved: seqs ${recs.map((r) => r.seq).join(",")}`);
await unplug();

// ---- check the ledger directly ------------------------------------------------
const h = { authorization: `Bearer ${created.api_key}` };
const { events } = await (await fetch(`${API}/v1/events?limit=1000`, { headers: h })).json();
const { keys } = await (await fetch(`${API}/v1/tenants/${tenantId}/public-keys`)).json();
const actions = events.filter((e) => e.agent_id === "sdk-e2e").map((e) => e.action);
const report = await verifyBundle({ format: "audittrail.bundle.v1", generated_at: "", tenant: { id: tenantId, name: "" }, public_keys: keys, events, checkpoints: [] });
const expected = ["step.1", "step.2", "step.3", "step.4", "step.5", "step.6"];
const ok = JSON.stringify(actions) === JSON.stringify(expected) && report.ok;
log(`ledger order: ${actions.join(" -> ")}`);
log(`chain verified in-process: ok=${report.ok}, signatures=${report.signaturesVerified}, retries observed=${errors.length}`);
console.log(ok ? "PASS: events survived the outage, arrived in order, exactly once" : "FAIL");
process.exit(ok ? 0 : 1);
