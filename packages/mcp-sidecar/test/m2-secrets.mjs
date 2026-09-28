// M2: secrets in tool args/results are never stored in plaintext. They are
// scanned + redacted in the ledger; raw values survive only encrypted
// (per-principal DEK, crypto-shreddable) and readable with pii:read.
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const env = Object.fromEntries(readFileSync(join(here, "../../../.env"), "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const API = "http://localhost:8080", H = { authorization: `Bearer ${env.AUDITTRAIL_ADMIN_TOKEN}` };
const FS = require.resolve("@modelcontextprotocol/server-filesystem/dist/index.js");
const dir = mkdtempSync(join(tmpdir(), "m2-"));
const SECRETS = { aws: "AKIAIOSFODNN7EXAMPLE", gh: "ghp_" + "Q".repeat(36), anthropic: "sk-ant-api03-" + "Z".repeat(40), pem: "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----" };
writeFileSync(join(dir, ".env.prod"), `AWS_ACCESS_KEY_ID=${SECRETS.aws}\nGITHUB_TOKEN=${SECRETS.gh}\n`);
const t = await (await fetch(`${API}/v1/admin/tenants`, { method: "POST", headers: H, body: JSON.stringify({ name: "m2-secrets" }) })).json();
const reader = (await (await fetch(`${API}/v1/admin/tenants/${t.tenant.id}/api-keys`, { method: "POST", headers: H, body: JSON.stringify({ name: "auditor", scopes: ["events:read", "pii:read"] }) })).json()).api_key;
const p = spawn(process.execPath, [join(here, "../dist/cli.js"), "--quiet", "--principal", "alice@example.com", "--pins", join(dir, "pins.json"), "--queue", join(dir, "q.jsonl"), "--", process.execPath, FS, dir],
  { env: { ...process.env, AUDITTRAIL_API_KEY: t.api_key, AUDITTRAIL_API_URL: API }, stdio: ["pipe", "pipe", "ignore"] });
const send = (m) => p.stdin.write(JSON.stringify(m) + "\n");
send({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "m2", version: "1" } } });
send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read_text_file", arguments: { path: join(dir, ".env.prod") } } });
send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "write_file", arguments: { path: join(dir, "key.pem"), content: SECRETS.pem, note: `deploy with ${SECRETS.anthropic}` } } });
await new Promise((r) => setTimeout(r, 2500));
p.stdin.end();
await new Promise((r) => setTimeout(r, 4000));
// 1) nothing in the database, anywhere in the ledger rows, contains a planted secret
const dump = execSync(`psql -X -q -At audittrail -c "select agent_events::text from agent_events where tenant_id='${t.tenant.id}'"`).toString();
const leaked = Object.entries(SECRETS).filter(([, v]) => dump.includes(v.split("\n")[1] ?? v) || dump.includes(v));
// 2) the ledger shows the findings and redacted copies
const { events } = await (await fetch(`${API}/v1/events?limit=100`, { headers: { authorization: `Bearer ${reader}` } })).json();
const calls = events.filter((e) => e.action === "mcp.tools/call");
const findings = calls.map((e) => [e.target_resource.split("/").pop(), e.metadata.secrets_found?.kinds ?? [], e.metadata.result_secrets_found?.kinds ?? []]);
// 3) raw values are recoverable only by decrypting with pii:read
const raw = await (await fetch(`${API}/v2/events/${calls[0].id}/pii`, { headers: { authorization: `Bearer ${reader}` } })).json();
console.log("secrets found by the sidecar:", JSON.stringify(findings));
console.log("plaintext secrets in database rows:", leaked.map(([k]) => k));
console.log("raw result recoverable via pii:read (encrypted at rest):", JSON.stringify(raw.fields?.result ?? "").includes(SECRETS.aws));
const ok = leaked.length === 0 && calls.length === 2 && findings.every(([, a, b]) => a.length + b.length > 0) && JSON.stringify(raw.fields?.result ?? "").includes(SECRETS.aws);
console.log(ok ? "PASS: no secret stored in plaintext; findings recorded; raw data only under encryption" : "FAIL");
process.exit(ok ? 0 : 1);
