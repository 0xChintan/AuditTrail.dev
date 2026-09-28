import { createHash, randomUUID } from "node:crypto";
import { canonicalize, type DelegationFrame } from "@audittrail/core";
import { redactValue, type AuditEvent, type Outcome } from "@audittrail/sdk";
import { META, envModel, first, metaString, osUser, type IdentityConfig, type Resolved } from "./identity.js";
import { evaluate, type Policy } from "./policy.js";

export type JsonRpcId = string | number;
export interface JsonRpcMessage {
  jsonrpc?: "2.0";
  id?: JsonRpcId | null;
  method?: string;
  params?: Record<string, any>;
  result?: any;
  error?: { code: number; message: string; data?: unknown };
}

export interface Recorder {
  track(event: AuditEvent): unknown;
}

/** Pinned tool definitions per server: tool name -> SHA-256(JCS(definition)). */
export interface PinStore {
  get(server: string): Record<string, string> | undefined;
  set(server: string, pins: Record<string, string>): void;
}

export class MemoryPinStore implements PinStore {
  private m = new Map<string, Record<string, string>>();
  get(server: string) {
    return this.m.get(server);
  }
  set(server: string, pins: Record<string, string>) {
    this.m.set(server, { ...pins });
  }
}

export type CaptureMode = "full" | "redacted" | "hash" | "none";

export interface MirrorOptions {
  recorder: Recorder;
  identity: IdentityConfig;
  /** Human-readable upstream (URL or command line). */
  upstream: string;
  transport: "stdio" | "http";
  serverName?: string;
  policy?: Policy;
  captureArgs?: CaptureMode;
  maxArgBytes?: number;
  /** Record every request method, not just the audited ones. */
  auditAll?: boolean;
  /** Gap with no in-flight calls that starts a new (inferred) turn. Default 2000ms. */
  turnGapMs?: number;
  /** Tool-definition pinning (rug-pull detection). */
  pins?: PinStore;
  /** "warn" (default): record drift; "block": also refuse calls to drifted tools until re-approved. */
  onDrift?: "warn" | "block";
  /** Raw (unredacted) arguments/results: "encrypted" (default) sends them as crypto-shreddable PII; "none" keeps only hashes + redacted copies. */
  storeRaw?: "encrypted" | "none";
  log?: (msg: string) => void;
}

/** Methods that constitute agent *actions* and are always recorded. */
const CLIENT_AUDITED = new Set(["tools/call", "resources/read", "prompts/get"]);
const SERVER_AUDITED = new Set(["sampling/createMessage", "elicitation/create"]);

interface Pending {
  dir: "client" | "server";
  id: JsonRpcId;
  method: string;
  params: Record<string, any>;
  started: number;
  timestamp: Date;
  callId: string;
  turnId: string;
  parent: Pending | null;
  concurrent: string[];
}

const SECRET_KEY = /pass(word|phrase)?|secret|token|api[_-]?key|authori[sz]ation|cookie|credential|private[_-]?key|session[_-]?id/i;

export function sha256Canon(v: unknown): string {
  let s: string;
  try {
    s = canonicalize(v ?? null);
  } catch {
    s = JSON.stringify(v ?? null);
  }
  return createHash("sha256").update(s).digest("hex");
}

export function redact(v: unknown, depth = 0): unknown {
  if (depth > 12) return "[depth limit]";
  if (typeof v === "string") return v.length > 2048 ? `${v.slice(0, 2048)}…[truncated ${v.length - 2048} chars]` : v;
  if (Array.isArray(v)) return v.slice(0, 200).map((x) => redact(x, depth + 1));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = SECRET_KEY.test(k) ? "[REDACTED]" : redact(x, depth + 1);
    return out;
  }
  if (typeof v === "number" && !Number.isFinite(v)) return String(v);
  return v;
}

/**
 * Observes one MCP session's JSON-RPC traffic (both directions) and records
 * an identity-chain audit event for every agent action. It never modifies
 * forwarded messages; the only message it ever originates is the reply to
 * a call blocked by policy.
 */
export class AuditMirror {
  readonly sessionId = randomUUID();
  mcpSessionId: string | null = null;
  headerPrincipal: string | null = null;
  private client: { name?: string; version?: string } = {};
  private server: { name?: string; version?: string } = {};
  private protocolVersion: string | null = null;
  private initMeta: Record<string, unknown> = {};
  private observedModel: string | null = null;
  private pending = new Map<string, Pending>();
  private drifted = new Set<string>();
  private turn = 0;
  private lastActivity = 0;
  private readonly o: Required<Pick<MirrorOptions, "captureArgs" | "maxArgBytes" | "turnGapMs">> & MirrorOptions;

  constructor(opts: MirrorOptions) {
    this.o = { captureArgs: "redacted", maxArgBytes: 16_384, turnGapMs: 2000, ...opts };
  }

  get serverName(): string {
    return this.o.serverName || this.server.name || deriveName(this.o.upstream);
  }

  // ---- identity -------------------------------------------------------------

  principal(reqMeta?: unknown): Resolved {
    const r = first(
      [metaString(reqMeta, META.principal), "request_meta"],
      [metaString(this.initMeta, META.principal), "session_meta"],
      [this.headerPrincipal, "header"],
      [this.o.identity.principal, "flag"],
      [process.env.AUDITTRAIL_PRINCIPAL, "env"],
    );
    if (r.value || this.o.identity.osUserFallback === false) return r;
    const os = osUser();
    return os ? { value: os, source: "inferred:os_user" } : r;
  }

  agent(reqMeta?: unknown): Resolved {
    const ci = this.client.name ? `${this.client.name}${this.client.version ? "@" + this.client.version : ""}` : undefined;
    return first(
      [metaString(reqMeta, META.agent), "request_meta"],
      [metaString(this.initMeta, META.agent), "session_meta"],
      [this.o.identity.agentId, "flag"],
      [process.env.AUDITTRAIL_AGENT_ID, "env"],
      [ci, "client_info"],
    );
  }

  model(reqMeta?: unknown): Resolved {
    return first(
      [metaString(reqMeta, META.model), "request_meta"],
      [metaString(this.initMeta, META.model), "session_meta"],
      [this.o.identity.model, "flag"],
      [envModel(), "env"],
      [this.observedModel, "observed_sampling"],
    );
  }

  modelVersion(reqMeta?: unknown): Resolved {
    return first(
      [metaString(reqMeta, META.modelVersion), "request_meta"],
      [metaString(this.initMeta, META.modelVersion), "session_meta"],
      [this.o.identity.modelVersion, "flag"],
      [process.env.AUDITTRAIL_MODEL_VERSION, "env"],
    );
  }

  // ---- traffic --------------------------------------------------------------

  /**
   * Inspect a message from the agent host. Returns replies to send back
   * instead of forwarding (policy denials); `forward=false` means the
   * message must not reach the server.
   */
  onClientMessage(msg: JsonRpcMessage): { forward: boolean; reply?: JsonRpcMessage } {
    try {
      if (msg.method && msg.id !== undefined && msg.id !== null) {
        if (msg.method === "initialize") {
          const p = msg.params ?? {};
          this.client = { name: p.clientInfo?.name, version: p.clientInfo?.version };
          this.protocolVersion = p.protocolVersion ?? null;
          this.initMeta = (p._meta as Record<string, unknown>) ?? {};
        }
        if (msg.method === "tools/call" && this.drifted.has(String(msg.params?.name ?? "")) && this.o.onDrift === "block") {
          const tool = String(msg.params?.name ?? "");
          const p = this.track("client", msg);
          const reply: JsonRpcMessage = { jsonrpc: "2.0", id: msg.id,
            result: { content: [{ type: "text", text: `Blocked by AuditTrail: the definition of tool "${tool}" changed since it was approved. Re-approve it before use.` }], isError: true } };
          if (p) this.finish(p, "denied", { policy: { rule: `drift:${tool}`, decision: "deny" } }, reply.result);
          return { forward: false, reply };
        }
        if (msg.method === "tools/call" && this.o.policy) {
          const tool = String(msg.params?.name ?? "");
          const d = evaluate(this.o.policy, this.serverName, tool);
          if (!d.allowed) {
            const p = this.track("client", msg);
            const reply: JsonRpcMessage = {
              jsonrpc: "2.0",
              id: msg.id,
              result: { content: [{ type: "text", text: `Blocked by AuditTrail policy (${d.rule}): tool "${tool}" is not permitted for this agent.` }], isError: true },
            };
            if (p) this.finish(p, "denied", { policy: { rule: d.rule, decision: "deny" } }, reply.result);
            return { forward: false, reply };
          }
        }
        this.track("client", msg);
      } else if (msg.method === "notifications/cancelled") {
        const id = msg.params?.requestId;
        const p = this.pending.get(`client:${id}`);
        if (p) this.finish(p, "error", { cancelled: true, cancel_reason: msg.params?.reason ?? null });
      } else if (!msg.method && msg.id !== undefined && msg.id !== null) {
        this.complete("server", msg); // client answering a server request
      }
    } catch (e) {
      this.o.log?.(`audit mirror error (client msg): ${(e as Error).message}`);
    }
    return { forward: true };
  }

  /** Inspect a message from the MCP server. relatedRequestId: the client request whose HTTP stream carried it. */
  onServerMessage(msg: JsonRpcMessage, relatedRequestId?: JsonRpcId): void {
    try {
      if (msg.method && msg.id !== undefined && msg.id !== null) {
        this.track("server", msg, relatedRequestId);
      } else if (!msg.method && msg.id !== undefined && msg.id !== null) {
        const p = this.pending.get(`client:${msg.id}`);
        if (p?.method === "initialize" && msg.result) {
          this.server = { name: msg.result.serverInfo?.name, version: msg.result.serverInfo?.version };
          this.protocolVersion = msg.result.protocolVersion ?? this.protocolVersion;
        }
        this.complete("client", msg);
      }
    } catch (e) {
      this.o.log?.(`audit mirror error (server msg): ${(e as Error).message}`);
    }
  }

  /** Record every still-open call (e.g. the server died). */
  close(reason: string): void {
    for (const p of [...this.pending.values()]) this.finish(p, "error", { no_response: true, reason });
  }

  // ---- internals ------------------------------------------------------------

  private audited(dir: "client" | "server", method: string): boolean {
    if (this.o.auditAll) return !method.startsWith("notifications/") && method !== "ping";
    return dir === "client" ? CLIENT_AUDITED.has(method) || method === "initialize" : SERVER_AUDITED.has(method);
  }

  private track(dir: "client" | "server", msg: JsonRpcMessage, relatedRequestId?: JsonRpcId): Pending | null {
    const method = msg.method!;
    const now = Date.now();
    if (this.inFlightCalls().length === 0 && now - this.lastActivity > this.o.turnGapMs) this.turn++;
    this.lastActivity = now;
    let parent: Pending | null = null;
    if (dir === "server") {
      // Server-initiated request nested inside a client call: precise on HTTP
      // (it arrived on that call's response stream), inferred on stdio.
      if (relatedRequestId !== undefined) parent = this.pending.get(`client:${relatedRequestId}`) ?? null;
      else {
        const open = this.inFlightCalls();
        if (open.length === 1) parent = open[0]!;
      }
    }
    const p: Pending = {
      dir, id: msg.id!, method, params: msg.params ?? {}, started: now, timestamp: new Date(now),
      callId: `${this.sessionId}:${dir === "server" ? "s" : "c"}:${msg.id}`,
      turnId: `${this.sessionId}:turn:${this.turn}`,
      parent,
      concurrent: this.inFlightCalls().map((x) => x.callId),
    };
    this.pending.set(`${dir}:${msg.id}`, p);
    return this.audited(dir, method) ? p : null;
  }

  private inFlightCalls(): Pending[] {
    return [...this.pending.values()].filter((p) => p.dir === "client" && p.method !== "initialize");
  }

  private complete(dir: "client" | "server", msg: JsonRpcMessage): void {
    const p = this.pending.get(`${dir}:${msg.id}`);
    if (!p) return;
    this.lastActivity = Date.now();
    if (dir === "client" && p.method === "tools/list" && Array.isArray(msg.result?.tools)) this.checkPins(msg.result.tools);
    if (!this.audited(dir, p.method)) {
      this.pending.delete(`${dir}:${msg.id}`);
      return;
    }
    let outcome: Outcome = "allowed";
    const extra: Record<string, unknown> = {};
    if (msg.error) {
      outcome = "error";
      extra.error = { code: msg.error.code, message: String(msg.error.message).slice(0, 1024) };
    } else if (msg.result?.isError === true) {
      outcome = "error";
      const text = (msg.result.content ?? []).filter((c: any) => c?.type === "text").map((c: any) => c.text).join("\n");
      extra.tool_error = String(text).slice(0, 1024);
    }
    if (p.method === "elicitation/create" && msg.result?.action && msg.result.action !== "accept") {
      outcome = "denied"; // the human declined or cancelled
      extra.elicitation_action = msg.result.action;
    }
    if (p.method === "sampling/createMessage" && typeof msg.result?.model === "string") {
      this.observedModel = msg.result.model;
      extra.sampling_model = msg.result.model;
    }
    this.finish(p, outcome, extra, msg.result);
  }

  private finish(p: Pending, outcome: Outcome, extra: Record<string, unknown>, result?: any): void {
    this.pending.delete(`${p.dir}:${p.id}`);
    const reqMeta = p.params._meta;
    const principal = this.principal(reqMeta);
    const agent = this.agent(reqMeta);
    const model = this.model(reqMeta);
    const modelVersion = this.modelVersion(reqMeta);
    const server = this.serverName;

    const chain: DelegationFrame[] = [
      { type: "human", id: principal.value ?? "unknown", source: principal.source },
      { type: "agent", id: agent.value ?? "unknown", source: agent.source, model: model.value ?? "unknown" },
    ];
    const supplied = (reqMeta as Record<string, unknown> | undefined)?.[META.delegation] ?? this.initMeta[META.delegation];
    if (Array.isArray(supplied)) {
      for (const f of supplied) if (f && typeof f === "object" && "type" in f && "id" in f) chain.push({ ...(f as DelegationFrame), source: "request_meta" });
    }
    chain.push({ type: "mcp_session", id: this.sessionId, server, transport: this.o.transport });
    chain.push({ type: "turn", id: p.turnId, source: "inferred:idle_gap" });
    const declaredParent = metaString(reqMeta, META.parentCall);
    if (declaredParent) chain.push({ type: "parent_call", id: declaredParent, source: "request_meta" });
    if (p.parent) chain.push({ type: "tool_call", id: p.parent.callId, tool: p.parent.params?.name ?? p.parent.method, source: p.dir === "server" ? "nested_server_request" : "inferred" });
    chain.push({ type: kindOf(p.method), id: p.callId, method: p.method });

    const { action, target } = describe(p, server, this.client.name);
    const payload = {
      mcp: {
        method: p.method,
        jsonrpc_id: p.id,
        direction: p.dir === "client" ? "agent_to_server" : "server_to_agent",
        session_id: this.sessionId,
        mcp_session_id: this.mcpSessionId,
        protocol_version: this.protocolVersion,
        transport: this.o.transport,
        server: { name: server, version: this.server.version ?? null, upstream: this.o.upstream },
        client: { name: this.client.name ?? null, version: this.client.version ?? null },
      },
      ...this.captureParams(p),
      result: summarizeResult(result),
      latency_ms: Date.now() - p.started,
      concurrent_calls: p.concurrent,
      identity_provenance: {
        human_principal_id: principal.source,
        agent_id: agent.source,
        model_id: model.source,
        model_version: modelVersion.source,
      },
      ...extra,
    };
    const scannedResult = scanResult(result);
    if (scannedResult.found) (payload as Record<string, unknown>).result_secrets_found = scannedResult.found;
    let piiRaw: AuditEvent["pii"] = null;
    if ((this.o.storeRaw ?? "encrypted") === "encrypted" && (p.method === "tools/call" || p.method === "resources/read" || p.method === "prompts/get")) {
      const clip = (x: unknown) => {
        const t = JSON.stringify(x ?? null) ?? "null";
        return t.length > 60000 ? t.slice(0, 60000) + "…[truncated]" : t;
      };
      const { _meta, ...params } = p.params;
      piiRaw = { subject: principal.value ?? `mcp-session:${this.sessionId}`, fields: { arguments: clip(params), result: clip(result ?? null) } };
    }
    this.o.recorder.track({
      pii: piiRaw,
      occurredAt: p.timestamp,
      principal: principal.value ? { id: principal.value, type: "human" } : null,
      agent: { id: agent.value ?? "unknown" },
      model: { id: model.value ?? "unknown", version: modelVersion.value ?? null },
      delegation: chain.map(scalarFrame),
      action,
      resource: target,
      outcome,
      payload: jsonSafe(payload) as Record<string, unknown>,
    });
  }

  /** Rug-pull detection: hash each tool definition and compare with pins. */
  private checkPins(tools: any[]): void {
    const store = this.o.pins;
    if (!store) return;
    const server = this.serverName;
    const current: Record<string, string> = {};
    for (const t of tools) if (t && typeof t.name === "string") current[t.name] = sha256Canon(t);
    const pinned = store.get(server);
    const emit = (action: string, tool: string, outcome: Outcome, extra: Record<string, unknown>) =>
      this.o.recorder.track({
        principal: null,
        agent: { id: "audittrail-mcp-proxy" },
        action,
        resource: `mcp://${encodeURIComponent(server)}/tools/${tool}`,
        outcome,
        payload: { tool, server, session_id: this.sessionId, ...extra },
      });
    if (!pinned) {
      store.set(server, current);
      for (const [tool, hash] of Object.entries(current)) emit("mcp.tool/pinned", tool, "allowed", { definition_sha256: hash });
      return;
    }
    const drift = this.o.onDrift === "block" ? "denied" : "error";
    for (const [tool, hash] of Object.entries(current)) {
      if (!(tool in pinned)) {
        emit("mcp.tool/added", tool, drift, { definition_sha256: hash, note: "tool appeared after the server's tools were pinned" });
        this.drifted.add(tool);
      } else if (pinned[tool] !== hash) {
        emit("mcp.tool/definition_changed", tool, drift, { pinned_sha256: pinned[tool], current_sha256: hash, action_taken: this.o.onDrift === "block" ? "calls blocked until re-approved" : "recorded" });
        this.drifted.add(tool);
      }
    }
    for (const tool of Object.keys(pinned)) {
      if (!(tool in current)) emit("mcp.tool/removed", tool, "error", { pinned_sha256: pinned[tool] });
    }
  }

  private captureParams(p: Pending): Record<string, unknown> {
    const { _meta, ...params } = p.params;
    const out: Record<string, unknown> = {};
    const args = p.method === "tools/call" || p.method === "prompts/get" ? params.arguments : params;
    if (p.method === "tools/call") out.tool = params.name;
    if (p.method === "prompts/get") out.prompt = params.name;
    if (p.method === "resources/read") out.uri = params.uri;
    out.arguments_sha256 = sha256Canon(args ?? null);
    const mode = this.o.captureArgs;
    if (mode === "full" || mode === "redacted") {
      let v = mode === "full" ? args : redact(args);
      if (mode === "redacted") {
        const rep = { redacted: 0, kinds: new Set<string>() };
        v = redactValue(v, {}, rep);
        if (rep.redacted) out.secrets_found = { count: rep.redacted, kinds: [...rep.kinds] };
      }
      const size = Buffer.byteLength(JSON.stringify(v ?? null));
      out.arguments = size <= this.o.maxArgBytes ? (v ?? null) : { _omitted: true, bytes: size, reason: "exceeds maxArgBytes" };
      if (mode === "redacted") out.arguments_redacted = true;
    }
    if (_meta && typeof _meta === "object") out.request_meta_keys = Object.keys(_meta);
    return out;
  }
}

function kindOf(method: string): string {
  if (method === "tools/call") return "tool_call";
  if (method === "sampling/createMessage") return "sampling_request";
  if (method === "elicitation/create") return "elicitation_request";
  if (method === "initialize") return "session_start";
  return "request";
}

function describe(p: Pending, serverName: string, clientName?: string): { action: string; target: string } {
  const prm = p.params;
  // Server names may contain "/" (e.g. "mcp-servers/everything"): encode so
  // target_resource stays unambiguous.
  const server = encodeURIComponent(serverName);
  switch (p.method) {
    case "tools/call":
      return { action: "mcp.tools/call", target: `mcp://${server}/tools/${prm.name ?? "unknown"}` };
    case "resources/read":
      return { action: "mcp.resources/read", target: `mcp://${server}/resources/${prm.uri ?? "unknown"}` };
    case "prompts/get":
      return { action: "mcp.prompts/get", target: `mcp://${server}/prompts/${prm.name ?? "unknown"}` };
    case "initialize":
      return { action: "mcp.session/initialize", target: `mcp://${server}` };
    case "sampling/createMessage":
      return { action: "mcp.sampling/createMessage", target: `mcp-client://${encodeURIComponent(clientName ?? "agent")}/sampling` };
    case "elicitation/create":
      return { action: "mcp.elicitation/create", target: `mcp-client://${encodeURIComponent(clientName ?? "agent")}/elicitation` };
    default:
      return { action: `mcp.${p.method}`, target: `mcp://${server}/${p.method}` };
  }
}

export function summarizeResult(result: any): Record<string, unknown> | null {
  if (result === undefined || result === null) return null;
  const content = Array.isArray(result.content) ? result.content : Array.isArray(result.contents) ? result.contents : null;
  return {
    is_error: result.isError === true,
    content_items: content ? content.length : null,
    content_types: content ? [...new Set(content.map((c: any) => c?.type ?? (c?.uri ? "resource" : "unknown")))] : null,
    structured: result.structuredContent !== undefined,
    bytes: Buffer.byteLength(JSON.stringify(result)),
    sha256: sha256Canon(result),
  };
}

export function deriveName(upstream: string): string {
  try {
    const u = new URL(upstream);
    if (u.protocol.startsWith("http")) return u.host;
  } catch {
    /* command line */
  }
  const parts = upstream.split(/\s+/).filter((x) => !x.startsWith("-"));
  const pkg = parts.find((x) => x.includes("server")) ?? parts[parts.length - 1] ?? "mcp-server";
  return pkg.replace(/^@[^/]+\//, "").replace(/@[\d.]+$/, "") || "mcp-server";
}

/** Delegation frames must carry only scalar values (SPEC §1). */
function scalarFrame(f: DelegationFrame): { type: string; id: string; [k: string]: string | number | boolean | null } {
  const out: { type: string; id: string; [k: string]: string | number | boolean | null } = { type: String(f.type).slice(0, 64) || "frame", id: String(f.id).slice(0, 512) || "unknown" };
  for (const [k, v] of Object.entries(f)) {
    if (k === "type" || k === "id") continue;
    if (v === null || typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))) out[k] = v as string | number | boolean | null;
  }
  return out;
}

/** Tool data is arbitrary: make it safe for the strict contract (big numbers -> strings, NUL stripped). */
export function jsonSafe(v: unknown, depth = 0): unknown {
  if (depth > 12) return "[depth limit]";
  if (typeof v === "number") return Number.isFinite(v) && Math.abs(v) <= 2 ** 53 ? v : String(v);
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "string") return v.replace(/\u0000/g, "").toWellFormed();
  if (Array.isArray(v)) return v.map((x) => jsonSafe(x, depth + 1));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) if (x !== undefined) out[k.replace(/\u0000/g, "").toWellFormed()] = jsonSafe(x, depth + 1);
    return out;
  }
  return v;
}

/** Scan a tool result's text for credentials (the result itself is stored only as a digest + encrypted copy). */
function scanResult(result: any): { found?: { count: number; kinds: string[] } } {
  if (!result) return {};
  const rep = { redacted: 0, kinds: new Set<string>() };
  redactValue(result, {}, rep);
  return rep.redacted ? { found: { count: rep.redacted, kinds: [...rep.kinds] } } : {};
}
