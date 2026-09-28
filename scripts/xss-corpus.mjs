// D1/D2 gate: an XSS payload corpus written into every attacker-controllable
// field (agent, principal, model, delegation, resource, payload, tenant name,
// tool text) must render inert in the dashboard. A canary server counts any
// payload that executes or loads a resource; a real headless Chrome renders
// the pages. Pass = 0 canary hits, payload text visible as text.
import http from "node:http";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditTrail } from "../packages/sdk/dist/index.js";

const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const API = "http://localhost:8080", DASH = "http://localhost:3000";
// The dashboard requires basic auth (DASHBOARD_PASSWORD); read it from the env or apps/dashboard/.env.local.
const dashPw = process.env.DASHBOARD_PASSWORD ?? (readFileSync(new URL("../apps/dashboard/.env.local", import.meta.url), "utf8").match(/^DASHBOARD_PASSWORD=(.*)$/m)?.[1] ?? "");
const DASH_AUTH = { Authorization: "Basic " + Buffer.from(`admin:${dashPw}`).toString("base64") };
const DASH_CRED = `http://admin:${encodeURIComponent(dashPw)}@localhost:3000`;
const CANARY = 9912;
let hits = [];
const canary = http.createServer((req, res) => { hits.push(req.url); res.writeHead(204).end(); }).listen(CANARY);
const c = `http://127.0.0.1:${CANARY}`;
const corpus = [
  `<script>fetch('${c}/script')</script>`,
  `<img src=x onerror="fetch('${c}/img-onerror')">`,
  `<img src="${c}/img-src">`,
  `<svg onload="fetch('${c}/svg')">`,
  `"><script>fetch('${c}/attr-break')</script>`,
  `javascript:fetch('${c}/js-url')`,
  `<iframe src="javascript:fetch('${c}/iframe')"></iframe>`,
  `<a href="javascript:fetch('${c}/href')">click</a>`,
  `{{constructor.constructor('fetch("${c}/template")')()}}`,
  `<style>@import '${c}/css';</style>`,
  `<link rel=stylesheet href="${c}/link">`,
  `</title><script>fetch('${c}/title')</script>`,
  `<script>fetch('${c}/unicode-escaped')</script>`,
  `<details open ontoggle="fetch('${c}/details')">`,
  `<math><mtext><table><mglyph><style><img src=x onerror="fetch('${c}/mxss')">`,
];
const H = { authorization: `Bearer ${env.AUDITTRAIL_ADMIN_TOKEN}` };
const t = await (await fetch(`${API}/v1/admin/tenants`, { method: "POST", headers: H, body: JSON.stringify({ name: `xss ${corpus[1]}` }) })).json();
const at = new AuditTrail({ apiKey: t.api_key, baseUrl: API, agent: { id: "xss-agent" }, redact: false });
for (const [i, p] of corpus.entries()) {
  await at.record({
    agent: { id: p.slice(0, 250), version: p.slice(0, 100) },
    principal: { id: p, type: "human" },
    model: { id: p.slice(0, 250), provider: p.slice(0, 100) },
    delegation: [{ type: "human", id: p }, { type: "tool_call", id: `c:${i}`, tool: p }],
    action: "mcp.tools/call",
    resource: `mcp://evil/tools/${p}`,
    outcome: ["allowed", "denied", "error"][i % 3],
    payload: { result: p, nested: { html: p }, list: [p] },
  });
}
const pages = ["/", `/t/${t.tenant.id}`, `/t/${t.tenant.id}/checkpoints`, `/t/${t.tenant.id}/exports`, `/t/${t.tenant.id}/keys`, `/t/${t.tenant.id}/settings`, "/verify"];
const CH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const prof = mkdtempSync(join(tmpdir(), "xss-chrome-"));
let rendered = 0, cspPresent = 0;
for (const p of pages) {
  const head = await fetch(DASH + p, { headers: DASH_AUTH });
  if (head.headers.get("content-security-policy")?.includes("'strict-dynamic'")) cspPresent++;
  const dom = await new Promise((resolve) => {
    const ch = spawn(CH, ["--headless=new", "--disable-gpu", "--no-first-run", `--user-data-dir=${prof}`, "--virtual-time-budget=4000", "--dump-dom", DASH_CRED + p], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    ch.stdout.on("data", (d) => (out += d));
    const timer = setTimeout(() => ch.kill("SIGKILL"), 20000);
    ch.on("exit", () => { clearTimeout(timer); resolve(out); });
  });
  if (dom.includes("fetch(") && (dom.includes("&lt;script") || dom.includes("&lt;img") || dom.includes("onerror"))) rendered++;
}
await new Promise((r) => setTimeout(r, 1500));
canary.close();
console.log(`pages rendered: ${pages.length}; pages with strict CSP: ${cspPresent}; pages showing the payloads as text: ${rendered}`);
console.log(`canary hits (executed/loaded payloads): ${hits.length} ${JSON.stringify(hits)}`);
const ok = hits.length === 0 && cspPresent === pages.length && rendered >= 2;
console.log(ok ? "PASS: XSS corpus renders inert" : "FAIL");
process.exit(ok ? 0 : 1);
