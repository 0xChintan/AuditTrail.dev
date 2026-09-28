// v2 task 3.3 gate: the WASM verifier checks a bundle with NO network.
// Every network API is replaced by a trap before the verifier loads; the
// script fails if any of them is touched.
//   node scripts/wasm-verify-offline.mjs bundle.json '{"log_keys":[...],...}' [tampered]
import { readFileSync } from "node:fs";
const touched = [];
for (const api of ["fetch", "WebSocket", "XMLHttpRequest", "EventSource"]) {
  globalThis[api] = function () { touched.push(api); throw new Error(`network API ${api} used by the verifier`); };
}
await import("../apps/dashboard/public/verifier/wasm_exec.js");
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(readFileSync(new URL("../apps/dashboard/public/verifier/verify.wasm", import.meta.url)), go.importObject);
go.run(instance);
while (!globalThis.auditTrailVerifierReady) await new Promise((r) => setTimeout(r, 5));
let bundle = readFileSync(process.argv[2], "utf8");
if (process.argv[4] === "tampered") {
  const b = JSON.parse(bundle);
  b.events[3].outcome = b.events[3].outcome === "denied" ? "allowed" : "denied";
  bundle = JSON.stringify(b);
}
const rep = JSON.parse(globalThis.auditTrailVerify(bundle, process.argv[3] ?? ""));
console.log(JSON.stringify({ ok: rep.ok, trust: rep.trust, rows: rep.events, heads: rep.tree_heads, witnessed_by: rep.witnessed_by,
  failed: Object.entries(rep.checks).filter(([, c]) => c.status === "fail").map(([k]) => k), tampered: rep.tampered_seqs, network_apis_touched: touched }));
process.exit(touched.length ? 2 : rep.ok ? 0 : 1);
