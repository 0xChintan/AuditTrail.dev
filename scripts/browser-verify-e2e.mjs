// Drives real Chrome (DevTools protocol, no extra deps): opens a tenant in
// the dashboard, clicks the first event, clicks "Verify in this browser",
// and reads the result. Proves the WASM verifier runs under the strict CSP.
//   node scripts/browser-verify-e2e.mjs <tenant-id>
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const tenant = process.argv[2];
const CH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const port = 9333;
// The dashboard requires basic auth (DASHBOARD_PASSWORD); read it from the env or apps/dashboard/.env.local.
const dashPw = process.env.DASHBOARD_PASSWORD ?? (readFileSync(new URL("../apps/dashboard/.env.local", import.meta.url), "utf8").match(/^DASHBOARD_PASSWORD=(.*)$/m)?.[1] ?? "");
const chrome = spawn(CH, ["--headless=new", "--disable-gpu", "--no-first-run", `--user-data-dir=${mkdtempSync(join(tmpdir(), "cdp-"))}`, `--remote-debugging-port=${port}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let targets;
for (let i = 0; i < 50; i++) {
  // Local Chrome DevTools endpoint on loopback; TLS doesn't apply.
  // nosemgrep: typescript.react.security.react-insecure-request.react-insecure-request
  try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); break; } catch { await sleep(200); }
}
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0;
const pending = new Map();
const consoleErrors = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
  if (d.method === "Runtime.exceptionThrown") consoleErrors.push(d.params.exceptionDetails.text);
  if (d.method === "Log.entryAdded" && /Content Security Policy|CSP/.test(d.params.entry.text)) consoleErrors.push(d.params.entry.text);
};
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async (expr) => (await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result?.result?.value;
await send("Runtime.enable");
await send("Log.enable");
await send("Page.enable");
await send("Network.enable");
await send("Network.setExtraHTTPHeaders", { headers: { Authorization: "Basic " + Buffer.from(`admin:${dashPw}`).toString("base64") } });
await send("Page.navigate", { url: `http://localhost:3000/t/${tenant}` });
await sleep(4000);
await evaluate(`document.querySelector("ul li")?.click()`);
await sleep(1200);
await evaluate(`[...document.querySelectorAll("button")].find(b => b.textContent.includes("Verify in this browser"))?.click()`);
let text = "";
for (let i = 0; i < 40; i++) {
  await sleep(500);
  text = await evaluate(`document.querySelector('[data-slot="sheet-content"]')?.innerText ?? ""`);
  if (/Reproduces the signed Merkle root|Verification failed/.test(text)) break;
}
const lines = text.split("\n").filter((l) => /Hash recomputed|signature|Links|Merkle|tree head|append-only|Covered|Cosigned|anchor|failed/i.test(l));
console.log(lines.slice(0, 14).join("\n"));
console.log(`CSP/console errors: ${consoleErrors.length} ${JSON.stringify(consoleErrors.slice(0, 3))}`);
chrome.kill();
const ok = /Reproduces the signed Merkle root/.test(text) && !/Verification failed/.test(text) && consoleErrors.length === 0;
console.log(ok ? "PASS: WASM verifier ran in real Chrome under the strict CSP" : "FAIL");
process.exit(ok ? 0 : 1);
