// M4: killing the sidecar is detectable as a gap. A proxy with 2 s
// heartbeats is kill -9'd; the server-side monitor must seal a
// sidecar_silent alert. A second proxy that shuts down cleanly must not.
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const env = Object.fromEntries(readFileSync(join(here, "../../../.env"), "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const API = "http://localhost:8080";
const FS = require.resolve("@modelcontextprotocol/server-filesystem/dist/index.js");
const dir = mkdtempSync(join(tmpdir(), "m4-"));
const t = await (await fetch(`${API}/v1/admin/tenants`, { method: "POST", headers: { authorization: `Bearer ${env.AUDITTRAIL_ADMIN_TOKEN}` }, body: JSON.stringify({ name: "m4-sidecar-gap" }) })).json();
const start = () => {
  const p = spawn(process.execPath, [join(here, "../dist/cli.js"), "--quiet", "--heartbeat", "2", "--pins", join(dir, `pins-${Math.random()}.json`), "--queue", join(dir, `q-${Math.random()}.jsonl`), "--", process.execPath, FS, dir],
    { env: { ...process.env, AUDITTRAIL_API_KEY: t.api_key, AUDITTRAIL_API_URL: API }, stdio: ["pipe", "pipe", "ignore"] });
  p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "m4", version: "1" } } }) + "\n");
  p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_directory", arguments: { path: dir } } }) + "\n");
  return p;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const killed = start();
const clean = start();
await sleep(6000); // a few heartbeats reach the ledger
killed.kill("SIGKILL");
clean.stdin.end(); // graceful: emits sidecar/stopped
console.log("killed one sidecar with SIGKILL, stopped the other cleanly; waiting for the monitor…");
await sleep(12000);
const { events } = await (await fetch(`${API}/v1/events?limit=500`, { headers: { authorization: `Bearer ${t.api_key}` } })).json();
const sidecars = [...new Set(events.filter((e) => e.metadata?.sidecar).map((e) => e.metadata.sidecar.id))];
const alerts = events.filter((e) => e.action.startsWith("audittrail.monitor/"));
const hb = events.filter((e) => e.action === "audittrail.sidecar/heartbeat").length;
console.log(`sidecars seen: ${sidecars.length}; heartbeats: ${hb}; alerts: ${alerts.map((a) => `${a.action} ${a.target_resource} (silent ${a.metadata.silent_for_seconds}s)`).join("; ")}`);
const stoppedIds = new Set(events.filter((e) => e.action === "audittrail.sidecar/stopped").map((e) => e.metadata.sidecar.id));
const ok = alerts.length === 1 && alerts[0].action === "audittrail.monitor/sidecar_silent" && !stoppedIds.has(alerts[0].target_resource.slice(8)) && alerts[0].outcome === "error";
console.log(ok ? "PASS: the killed sidecar was detected as a gap; the cleanly stopped one was not" : "FAIL");
process.exit(ok ? 0 : 1);
