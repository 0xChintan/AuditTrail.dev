// Phase 4 DoD (scripted part): real MCP servers, real MCP client SDK, real
// ingestion API. Drives tool calls through the proxy in both transports and
// checks each ledger record's identity chain.
//
//   node test/e2e.mjs      (needs the API on :8080 and .env with admin token)
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CreateMessageRequestSchema, ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const root = join(here, "../../..");
const env = Object.fromEntries(readFileSync(join(root, ".env"), "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#"))
  .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const API = "http://localhost:8080";
const CLI = join(here, "../dist/cli.js");
const FS_SERVER = require.resolve("@modelcontextprotocol/server-filesystem/dist/index.js");
const EVERYTHING = require.resolve("@modelcontextprotocol/server-everything/dist/index.js");
let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? "  ✓" : "  ✗"} ${msg}`); if (!cond) failures++; };

const created = await (await fetch(`${API}/v1/admin/tenants`, { method: "POST", headers: { authorization: `Bearer ${env.AUDITTRAIL_ADMIN_TOKEN}` },
  body: JSON.stringify({ name: "mcp-sidecar-e2e" }) })).json();
const KEY = created.api_key, TENANT = created.tenant.id;
const qdir = mkdtempSync(join(tmpdir(), "atq-"));

// ---------------- stdio: wrap @modelcontextprotocol/server-filesystem ----------------
console.log("stdio mode: agent -> audittrail-mcp-proxy -> server-filesystem");
const dir = mkdtempSync(join(tmpdir(), "mcpfs-"));
writeFileSync(join(dir, "notes.txt"), "quarterly numbers: 42\n");
const stdioClient = new Client({ name: "e2e-agent", version: "1.0.0" });
await stdioClient.connect(new StdioClientTransport({
  command: process.execPath,
  args: [CLI, "--principal", "alice@example.com", "--model", "claude-opus-5-5", "--model-version", "20260901",
    "--deny", "write_file", "--queue", join(qdir, "stdio.jsonl"), "--quiet", "--", process.execPath, FS_SERVER, dir],
  env: { ...process.env, AUDITTRAIL_API_KEY: KEY, AUDITTRAIL_API_URL: API },
  stderr: "inherit",
}));
const tools = await stdioClient.listTools();
check(tools.tools.some((t) => t.name === "read_text_file"), `tools/list passes through unmodified (${tools.tools.length} tools)`);
const r1 = await stdioClient.callTool({ name: "read_text_file", arguments: { path: join(dir, "notes.txt") } });
check(r1.content[0].text.includes("42"), "read_text_file result passes through");
await stdioClient.callTool({ name: "list_directory", arguments: { path: dir } });
const r3 = await stdioClient.callTool({ name: "write_file", arguments: { path: join(dir, "x.txt"), content: "nope" } });
check(r3.isError === true && /Blocked by AuditTrail policy/.test(r3.content[0].text), "write_file blocked by --deny policy");
const r4 = await stdioClient.callTool({ name: "read_text_file", arguments: { path: "/etc/does-not-exist" } });
check(r4.isError === true, "failing tool call returns isError");
await stdioClient.close();

// ---------------- HTTP: wrap server-everything (Streamable HTTP) ----------------
console.log("http mode: agent -> audittrail-mcp-proxy --listen -> server-everything (streamableHttp)");
const upstream = spawn(process.execPath, [EVERYTHING, "streamableHttp"], { env: { ...process.env, PORT: "3901" }, stdio: ["ignore", "ignore", "inherit"] });
const proxy = spawn(process.execPath, [CLI, "--upstream", "http://127.0.0.1:3901/mcp", "--listen", "3902", "--agent-id", "research-agent",
  "--queue", join(qdir, "http.jsonl"), "--quiet"], { env: { ...process.env, AUDITTRAIL_API_KEY: KEY, AUDITTRAIL_API_URL: API }, stdio: ["ignore", "ignore", "inherit"] });
await new Promise((r) => setTimeout(r, 1500));
const httpClient = new Client({ name: "e2e-http-agent", version: "2.0.0" }, { capabilities: { sampling: {}, elicitation: {} } });
httpClient.setRequestHandler(CreateMessageRequestSchema, async () => ({ model: "claude-sonnet-5", role: "assistant", content: { type: "text", text: "sampled answer" } }));
httpClient.setRequestHandler(ElicitRequestSchema, async () => ({ action: "decline" }));
await httpClient.connect(new StreamableHTTPClientTransport(new URL("http://127.0.0.1:3902/mcp"), {
  requestInit: { headers: { "X-AuditTrail-Principal": "bob@example.com" } } }));
const e1 = await httpClient.callTool({ name: "echo", arguments: { message: "hello through the proxy" } });
check(JSON.stringify(e1).includes("hello through the proxy"), "echo over Streamable HTTP");
const s1 = await httpClient.callTool({ name: "get-sum", arguments: { a: 2, b: 40 } });
check(JSON.stringify(s1).includes("42"), "get-sum over Streamable HTTP");
const samp = await httpClient.callTool({ name: "trigger-sampling-request", arguments: { prompt: "summarize", maxTokens: 20 } });
check(JSON.stringify(samp).includes("sampled answer"), "server->agent sampling round-trips through the proxy");
await httpClient.callTool({ name: "trigger-elicitation-request", arguments: {} }).catch(() => undefined);
await httpClient.close();
await new Promise((r) => setTimeout(r, 1500)); // let the proxy deliver
proxy.kill("SIGTERM");
upstream.kill("SIGTERM");
await new Promise((r) => setTimeout(r, 1500));

// ---------------- inspect the ledger ----------------
const h = { authorization: `Bearer ${KEY}` };
const { events } = await (await fetch(`${API}/v1/events?limit=1000`, { headers: h })).json();
const { keys } = await (await fetch(`${API}/v1/tenants/${TENANT}/public-keys`)).json();
const mcp = events.filter((e) => e.action.startsWith("mcp."));
console.log(`\nledger now holds ${mcp.length} MCP records:`);
for (const e of mcp) {
  console.log(`  #${e.seq} ${e.outcome.padEnd(7)} ${e.action.padEnd(28)} ${e.target_resource}`);
  console.log(`       principal=${e.human_principal_id} (${e.metadata.identity_provenance.human_principal_id}) agent=${e.agent_id} (${e.metadata.identity_provenance.agent_id}) model=${e.model_id}@${e.model_version} (${e.metadata.identity_provenance.model_id})`);
  console.log(`       chain: ${e.delegation_chain.map((f) => `${f.type}:${String(f.id).split(":").slice(-2).join(":")}`).join(" > ")}`);
}
const find = (pred) => mcp.find(pred);
const read = find((e) => e.target_resource === "mcp://secure-filesystem-server/tools/read_text_file" && e.outcome === "allowed");
check(read && read.human_principal_id === "alice@example.com" && read.model_id === "claude-opus-5-5" && read.model_version === "20260901"
  && read.agent_id === "e2e-agent@1.0.0", "stdio read: principal/model from flags, agent from clientInfo, server from serverInfo");
check(read && read.metadata.arguments.path.endsWith("notes.txt") && read.metadata.result.is_error === false, "stdio read: arguments + result summary captured");
check(find((e) => e.target_resource.endsWith("/tools/write_file"))?.outcome === "denied", "blocked write_file recorded as denied");
check(find((e) => e.target_resource.endsWith("/tools/read_text_file") && e.outcome === "error") !== undefined, "failed read recorded as error");
const echo = find((e) => e.target_resource.endsWith("/tools/echo"));
check(echo && echo.human_principal_id === "bob@example.com" && echo.metadata.identity_provenance.human_principal_id === "header"
  && echo.agent_id === "research-agent" && echo.model_id === "unknown", "http echo: principal from header, agent from flag, model honestly 'unknown'");
const sampling = find((e) => e.action === "mcp.sampling/createMessage");
check(sampling && sampling.delegation_chain.some((f) => f.type === "tool_call" && f.tool === "trigger-sampling-request" && f.source === "nested_server_request"),
  "sampling request nested under its parent tool call in delegation_chain");
check(sampling?.metadata.sampling_model === "claude-sonnet-5", "model observed from sampling result");
check(find((e) => e.action === "mcp.elicitation/create")?.outcome === "denied", "declined elicitation recorded as human denial");
check(mcp.filter((e) => e.action === "mcp.session/initialize").length === 2, "one session/initialize record per session");
const bundlePath = join(qdir, "bundle.v2.json");
writeFileSync(bundlePath, await (await fetch(`${API}/v2/export`, { headers: { authorization: `Bearer ${env.AUDITTRAIL_ADMIN_TOKEN}`, "x-audittrail-tenant": TENANT } })).text());
const logKey = (await (await fetch(`${API}/v2/tenants/${TENANT}/log`)).json()).vkeys[0];
let verified = false;
try {
  execFileSync(join(root, "packages/ingestion-go/bin/verify"), ["--log-key", logKey, bundlePath], { stdio: "pipe" });
  verified = true;
} catch (e) {
  console.log(String(e.stdout));
}
check(verified, `whole chain verifies offline with the pinned log key (${events.length} rows)`);
console.log(failures ? `\nFAIL (${failures})` : "\nPASS: every MCP call produced a correct, verifiable identity-chain record");
process.exit(failures ? 1 : 0);
