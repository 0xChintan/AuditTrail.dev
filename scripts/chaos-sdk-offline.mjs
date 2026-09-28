// v2 task 2.2 gate: network chaos + a long offline window, then restore.
// Every event must arrive exactly once, in recording order.
//
//   OFFLINE_MINUTES=60 node scripts/chaos-sdk-offline.mjs
//
// Chaos proxy (HTTP level) between the SDK and the real API:
//   online:  random delay 0–400 ms, 10% responses dropped AFTER the server
//            committed, 10% requests duplicated upstream (server must reject
//            the duplicate nonce), 5% transient 503s
//   offline: connection refused for OFFLINE_MINUTES while the app keeps
//            recording to a disk spool
import http from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditTrail } from "../packages/sdk/dist/index.js";
import { FileSpool } from "../packages/sdk/dist/node.js";

const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const API = process.env.API ?? "http://localhost:8080";
const OFFLINE_MIN = Number(process.env.OFFLINE_MINUTES ?? 60);
const PORT = 18181;
const t0 = Date.now();
const log = (m) => console.log(`[${((Date.now() - t0) / 60000).toFixed(1)}m] ${m}`);
const stats = { forwarded: 0, dropped: 0, duplicated: 0, dupRejected: 0, s503: 0, refused: 0 };

let server = null;
const sockets = new Set();
function plugIn() {
  server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    await new Promise((r) => setTimeout(r, Math.random() * 400));
    if (Math.random() < 0.05) { stats.s503++; res.writeHead(503).end("{}"); return; }
    const headers = {};
    for (const h of ["authorization", "content-type", "x-at-timestamp", "x-at-nonce", "x-at-signature"]) if (req.headers[h]) headers[h] = req.headers[h];
    const fwd = () => fetch(API + req.url, { method: req.method, headers, body: req.method === "GET" ? undefined : body });
    const up = await fwd().catch(() => null);
    if (!up) { res.writeHead(502).end("{}"); return; }
    const text = await up.text();
    stats.forwarded++;
    if (Math.random() < 0.10) {
      stats.duplicated++;
      const dup = await fwd().catch(() => null);
      if (dup && dup.status === 401) stats.dupRejected++;
    }
    if (Math.random() < 0.10) { stats.dropped++; req.socket.destroy(); return; }
    res.writeHead(up.status, { "content-type": "application/json" }).end(text);
  });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  return new Promise((r) => server.listen(PORT, r));
}
function unplug() { for (const s of sockets) s.destroy(); return new Promise((r) => server.close(() => r())); }

const tenant = await (await fetch(`${API}/v1/admin/tenants`, { method: "POST", headers: { authorization: `Bearer ${env.AUDITTRAIL_ADMIN_TOKEN}` }, body: JSON.stringify({ name: `sdk-chaos-${OFFLINE_MIN}m` }) })).json();
const spoolPath = join(mkdtempSync(join(tmpdir(), "at-chaos-")), "spool.jsonl");
const errors = [];
let retries = 0;
const at = new AuditTrail({ apiKey: tenant.api_key, baseUrl: `http://127.0.0.1:${PORT}`, agent: { id: "chaos-agent" },
  spool: new FileSpool(spoolPath), retry: { baseDelayMs: 200, maxDelayMs: 10_000, authPauseMs: 2_000 },
  onError: (e) => errors.push(e.code), onMetric: (m) => { if (m.name === "retry") retries++; } });

const recorded = [];
let i = 0;
const rec = () => { const action = `chaos.step.${String(++i).padStart(5, "0")}`; recorded.push(action); at.track({ action, resource: `r/${i}`, outcome: i % 5 ? "allowed" : "denied", payload: { i } }); };

await plugIn();
log(`phase A: online with chaos for 60s (tenant ${tenant.tenant.id})`);
for (let s = 0; s < 60; s++) { rec(); await new Promise((r) => setTimeout(r, 1000)); }
await unplug();
log(`phase B: OFFLINE for ${OFFLINE_MIN} min; recording one event every 10s to the disk spool`);
const offEnd = Date.now() + OFFLINE_MIN * 60_000;
while (Date.now() < offEnd) {
  rec();
  await new Promise((r) => setTimeout(r, 10_000));
  if (i % 60 === 0) log(`  offline… ${recorded.length} recorded, ${await at.pending()} spooled`);
}
log(`phase C: network restored (with chaos); ${await at.pending()} events spooled`);
await plugIn();
for (let s = 0; s < 10; s++) rec();
const flushStart = Date.now();
await at.flush();
log(`flushed in ${((Date.now() - flushStart) / 1000).toFixed(1)}s; proxy stats ${JSON.stringify(stats)}; sdk retries ${retries}; errors ${JSON.stringify([...new Set(errors)])}`);
await unplug();

let all = [], after = 0;
for (;;) {
  const { events } = await (await fetch(`${API}/v1/events?after_seq=${after}&limit=1000`, { headers: { authorization: `Bearer ${tenant.api_key}` } })).json();
  if (!events.length) break;
  all = all.concat(events); after = events[events.length - 1].seq;
}
const got = all.filter((e) => e.action.startsWith("chaos.")).map((e) => e.action);
const once = new Set(got).size === got.length;
const inOrder = JSON.stringify(got) === JSON.stringify(recorded);
log(`ledger: ${got.length} chaos events (recorded ${recorded.length}); exactly once: ${once}; in recording order: ${inOrder}`);
console.log(once && inOrder ? "PASS: every event arrived once, in order, after chaos + offline window" : "FAIL");
process.exit(once && inOrder ? 0 : 1);
