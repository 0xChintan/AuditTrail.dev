#!/usr/bin/env node
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { AuditTrail } from "@audittrail/sdk";
import { FileQueueStore } from "@audittrail/sdk/node";
import type { CaptureMode, MirrorOptions } from "./mirror.js";
import { runHttpProxy, runStdioProxy, runStdioToHttp } from "./transports.js";

const HELP = `audittrail-mcp-proxy — hash-chain every MCP tool call into AuditTrail, with no
code changes to the agent or the MCP server.

Wrap a local (stdio) MCP server — use this as the "command" in your agent's MCP config:
  audittrail-mcp-proxy [options] -- <server command> [args...]

Wrap a remote (Streamable HTTP) MCP server, exposed to the agent as a stdio server:
  audittrail-mcp-proxy [options] --upstream https://mcp.example.com/mcp

...or exposed as an HTTP endpoint the agent connects to:
  audittrail-mcp-proxy [options] --upstream https://mcp.example.com/mcp --listen 7331

Options:
  --api-key <key>         AuditTrail API key            (env AUDITTRAIL_API_KEY, required)
  --api-url <url>         AuditTrail ingestion API       (env AUDITTRAIL_API_URL, default http://localhost:8080)
  --principal <id>        Human on whose behalf the agent acts (env AUDITTRAIL_PRINCIPAL)
  --agent-id <id>         Agent identity (default: MCP clientInfo name@version)
  --model <id>            Model id (env AUDITTRAIL_MODEL / ANTHROPIC_MODEL)
  --model-version <v>     Model version
  --server-name <name>    Name used in target_resource (default: MCP serverInfo.name)
  --deny <glob>           Block matching tools (repeatable), recorded as "denied"
  --allow <glob>          Allow only matching tools (repeatable)
  --capture-args <mode>   full | redacted (default) | hash | none
  --header "K: V"         Extra header sent to the HTTP upstream (repeatable)
  --audit-all             Record every request method, not only actions
  --queue <path>          Durable local queue file (default ~/.audittrail/…)
  --no-os-principal       Don't fall back to the OS user as (inferred) principal
  --quiet                 Only log errors (to stderr)
`;

function parseArgs(argv: string[]) {
  const o: Record<string, string | boolean | string[]> = { deny: [], allow: [], header: [] };
  let command: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") {
      command = argv.slice(i + 1);
      break;
    }
    if (a === "-h" || a === "--help") o.help = true;
    else if (a === "--audit-all" || a === "--quiet" || a === "--no-os-principal") o[a.slice(2)] = true;
    else if (a.startsWith("--")) {
      const [k, inline] = a.slice(2).split(/=(.*)/s, 2) as [string, string | undefined];
      const v = inline ?? argv[++i];
      if (v === undefined) throw new Error(`missing value for --${k}`);
      if (Array.isArray(o[k])) (o[k] as string[]).push(v);
      else o[k] = v;
    } else throw new Error(`unexpected argument ${a} (put the server command after --)`);
  }
  return { o, command };
}

async function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`audittrail-mcp-proxy: ${(e as Error).message}\n\n${HELP}`);
    process.exit(2);
  }
  const { o, command } = parsed;
  if (o.help || (!command.length && !o.upstream)) {
    process.stderr.write(HELP);
    process.exit(o.help ? 0 : 2);
  }
  const quiet = o.quiet === true;
  // stdout is the MCP channel in stdio modes: logs go to stderr only.
  const log = (m: string) => process.stderr.write(`[audittrail-mcp-proxy] ${m}\n`);
  const info = (m: string) => !quiet && log(m);

  const apiKey = (o["api-key"] as string) || process.env.AUDITTRAIL_API_KEY;
  if (!apiKey) {
    log("AUDITTRAIL_API_KEY (or --api-key) is required");
    process.exit(2);
  }
  const apiUrl = (o["api-url"] as string) || process.env.AUDITTRAIL_API_URL || "http://localhost:8080";
  const upstreamDesc = command.length ? command.join(" ") : String(o.upstream);
  const capture = ((o["capture-args"] as string) || "redacted") as CaptureMode;
  if (!["full", "redacted", "hash", "none"].includes(capture)) {
    log(`--capture-args must be full|redacted|hash|none`);
    process.exit(2);
  }
  const queuePath = (o.queue as string) || join(homedir(), ".audittrail",
    `mcp-proxy-${createHash("sha256").update(apiUrl + "|" + apiKey.slice(0, 15) + "|" + upstreamDesc).digest("hex").slice(0, 16)}.jsonl`);

  const audit = new AuditTrail({
    apiKey, baseUrl: apiUrl, agentId: "unknown",
    store: new FileQueueStore(queuePath),
    onError: (e) => (e.permanent ? log(`audit event rejected: ${e.code} ${e.message}`) : !quiet && log(`audit delivery retrying: ${e.message}`)),
  });
  const headers: Record<string, string> = {};
  for (const h of o.header as string[]) {
    const i = h.indexOf(":");
    if (i > 0) headers[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim();
  }
  const mirror: MirrorOptions = {
    recorder: audit,
    upstream: upstreamDesc,
    transport: o.listen || !command.length ? "http" : "stdio",
    serverName: o["server-name"] as string | undefined,
    identity: {
      principal: o.principal as string | undefined,
      agentId: o["agent-id"] as string | undefined,
      model: o.model as string | undefined,
      modelVersion: o["model-version"] as string | undefined,
      osUserFallback: o["no-os-principal"] !== true,
    },
    policy: { deny: o.deny as string[], allow: o.allow as string[] },
    captureArgs: capture,
    auditAll: o["audit-all"] === true,
    log,
  };

  let exiting = false;
  const exit = async (code: number) => {
    if (exiting) return;
    exiting = true;
    const pending = await audit.pending();
    if (pending > 0) info(`flushing ${pending} audit event(s)…`);
    const ok = await Promise.race([audit.flush().then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), 5000))]);
    if (!ok) log(`${await audit.pending()} audit event(s) not yet delivered; kept in ${queuePath} and sent on next start`);
    process.exit(code);
  };

  if (command.length) {
    info(`wrapping stdio MCP server: ${upstreamDesc} → ledger ${apiUrl}`);
    runStdioProxy({ command: command[0]!, args: command.slice(1), mirror, log, onExit: (c) => void exit(c) });
  } else if (o.listen) {
    const port = Number(o.listen);
    await runHttpProxy({ upstream: String(o.upstream), port, headers, mirror, log });
    info(`listening on http://127.0.0.1:${port}/mcp → ${o.upstream} → ledger ${apiUrl}`);
    for (const s of ["SIGINT", "SIGTERM"] as const) process.on(s, () => void exit(0));
  } else {
    info(`bridging stdio → ${o.upstream} → ledger ${apiUrl}`);
    runStdioToHttp({ upstream: String(o.upstream), headers, mirror, log, onExit: (c) => void exit(c) });
  }
}

main().catch((e) => {
  process.stderr.write(`[audittrail-mcp-proxy] fatal: ${(e as Error).stack ?? e}\n`);
  process.exit(1);
});
