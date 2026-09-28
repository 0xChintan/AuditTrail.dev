import { spawn } from "node:child_process";
import http from "node:http";
import type { Readable, Writable } from "node:stream";
import { AuditMirror, type JsonRpcId, type JsonRpcMessage, type MirrorOptions } from "./mirror.js";

type Log = (m: string) => void;

/** Split a byte stream into newline-delimited lines (MCP stdio framing). */
export function onLines(stream: Readable, cb: (line: string) => void): void {
  let buf = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk: string) => {
    buf += chunk;
    let i: number;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      cb(line);
    }
  });
  stream.on("end", () => {
    if (buf.length) cb(buf);
    buf = "";
  });
}

function parse(line: string): JsonRpcMessage[] {
  const t = line.trim();
  if (!t) return [];
  try {
    const v = JSON.parse(t);
    return Array.isArray(v) ? v : [v];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// stdio <-> stdio: the agent host launches us instead of the MCP server.
// ---------------------------------------------------------------------------

export interface StdioOptions {
  command: string;
  args: string[];
  mirror: MirrorOptions;
  input?: Readable;
  output?: Writable;
  log: Log;
  onExit: (code: number) => void;
}

export function runStdioProxy(o: StdioOptions): AuditMirror {
  const input = o.input ?? process.stdin;
  const output = o.output ?? process.stdout;
  const mirror = new AuditMirror(o.mirror);
  const child = spawn(o.command, o.args, { stdio: ["pipe", "pipe", "inherit"], env: process.env });
  child.on("error", (e) => {
    o.log(`failed to start MCP server "${o.command}": ${e.message}`);
    o.onExit(127);
  });

  // agent -> server. Lines are forwarded byte-for-byte; parsing is only for mirroring.
  onLines(input, (line) => {
    const msgs = parse(line);
    if (msgs.length === 1) {
      const d = mirror.onClientMessage(msgs[0]!);
      if (!d.forward) {
        if (d.reply) output.write(JSON.stringify(d.reply) + "\n");
        return;
      }
    } else for (const m of msgs) mirror.onClientMessage(m);
    child.stdin.write(line + "\n");
  });
  input.on("end", () => child.stdin.end());

  // server -> agent
  onLines(child.stdout, (line) => {
    for (const m of parse(line)) mirror.onServerMessage(m);
    output.write(line + "\n");
  });

  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(sig, () => child.kill(sig));
  child.on("exit", (code, signal) => {
    mirror.close(signal ? `server killed by ${signal}` : `server exited with code ${code}`);
    o.onExit(code ?? (signal ? 1 : 0));
  });
  return mirror;
}

// ---------------------------------------------------------------------------
// SSE parsing (Streamable HTTP responses)
// ---------------------------------------------------------------------------

export class SSEParser {
  private buf = "";
  private data: string[] = [];
  constructor(private readonly onEvent: (data: string) => void) {}
  push(chunk: string): void {
    this.buf += chunk;
    let i: number;
    while ((i = this.buf.search(/\r?\n/)) >= 0) {
      const line = this.buf.slice(0, i);
      this.buf = this.buf.slice(i + (this.buf[i] === "\r" ? 2 : 1));
      if (line === "") {
        if (this.data.length) this.onEvent(this.data.join("\n"));
        this.data = [];
      } else if (line.startsWith("data:")) this.data.push(line.slice(5).replace(/^ /, ""));
    }
  }
}

// ---------------------------------------------------------------------------
// stdio -> Streamable HTTP: agent launches us as a stdio server; we speak
// Streamable HTTP to a remote MCP server (`--upstream https://…`).
// ---------------------------------------------------------------------------

export interface StdioToHttpOptions {
  upstream: string;
  headers: Record<string, string>;
  mirror: MirrorOptions;
  input?: Readable;
  output?: Writable;
  log: Log;
  onExit: (code: number) => void;
}

export function runStdioToHttp(o: StdioToHttpOptions): AuditMirror {
  const input = o.input ?? process.stdin;
  const output = o.output ?? process.stdout;
  const mirror = new AuditMirror(o.mirror);
  let sessionId: string | null = null;
  let protocolVersion: string | null = null;
  let getStreamOpened = false;
  const inflight = new Set<Promise<void>>();

  const emit = (m: JsonRpcMessage, related?: JsonRpcId) => {
    mirror.onServerMessage(m, related);
    if (m.id !== undefined && (m as { result?: { protocolVersion?: string } }).result?.protocolVersion) {
      protocolVersion = (m as { result: { protocolVersion: string } }).result.protocolVersion;
    }
    output.write(JSON.stringify(m) + "\n");
  };

  const headers = (): Record<string, string> => ({
    ...o.headers,
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    ...(protocolVersion ? { "mcp-protocol-version": protocolVersion } : {}),
  });

  const consume = async (res: Response, related?: JsonRpcId) => {
    const ct = res.headers.get("content-type") ?? "";
    if (ct.includes("text/event-stream") && res.body) {
      const parser = new SSEParser((data) => {
        for (const m of parse(data)) emit(m, related);
      });
      const dec = new TextDecoder();
      for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) parser.push(dec.decode(chunk, { stream: true }));
    } else if (ct.includes("application/json")) {
      for (const m of parse(await res.text())) emit(m, related);
    } else await res.arrayBuffer().catch(() => undefined);
  };

  const openGetStream = () => {
    if (getStreamOpened || !sessionId) return;
    getStreamOpened = true;
    void fetch(o.upstream, { method: "GET", headers: { ...headers(), accept: "text/event-stream" } })
      .then((res) => (res.ok ? consume(res) : undefined))
      .catch(() => undefined);
  };

  const post = async (line: string, msg: JsonRpcMessage | undefined) => {
    try {
      const res = await fetch(o.upstream, { method: "POST", headers: headers(), body: line });
      const sid = res.headers.get("mcp-session-id");
      if (sid && !sessionId) {
        sessionId = sid;
        mirror.mcpSessionId = sid;
      }
      if (!res.ok && res.status !== 202) {
        const text = await res.text().catch(() => "");
        o.log(`upstream HTTP ${res.status}: ${text.slice(0, 300)}`);
        if (msg?.id !== undefined && msg.id !== null && msg.method) {
          emit({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: `Upstream MCP server returned HTTP ${res.status}` } });
        }
        return;
      }
      await consume(res, msg?.method ? (msg.id ?? undefined) : undefined);
      if (msg?.method === "notifications/initialized") openGetStream();
    } catch (e) {
      o.log(`upstream unreachable: ${(e as Error).message}`);
      if (msg?.id !== undefined && msg.id !== null && msg.method) {
        emit({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: `Upstream MCP server unreachable: ${(e as Error).message}` } });
      }
    }
  };

  onLines(input, (line) => {
    const msgs = parse(line);
    if (msgs.length === 0) return;
    if (msgs.length === 1) {
      const d = mirror.onClientMessage(msgs[0]!);
      if (!d.forward) {
        if (d.reply) output.write(JSON.stringify(d.reply) + "\n");
        return;
      }
    } else for (const m of msgs) mirror.onClientMessage(m);
    const p = post(line, msgs.length === 1 ? msgs[0] : undefined);
    inflight.add(p);
    void p.finally(() => inflight.delete(p));
  });
  input.on("end", async () => {
    await Promise.allSettled([...inflight]);
    if (sessionId) await fetch(o.upstream, { method: "DELETE", headers: headers() }).catch(() => undefined);
    mirror.close("agent closed stdin");
    o.onExit(0);
  });
  return mirror;
}

// ---------------------------------------------------------------------------
// Streamable HTTP reverse proxy: agent host connects to http://localhost:PORT
// and we forward to the upstream MCP server URL.
// ---------------------------------------------------------------------------

export interface HttpProxyOptions {
  upstream: string;
  port: number;
  host?: string;
  headers: Record<string, string>;
  mirror: MirrorOptions;
  log: Log;
}

const HOP = new Set(["connection", "keep-alive", "transfer-encoding", "upgrade", "host", "content-length", "proxy-connection", "te", "trailer"]);

export function runHttpProxy(o: HttpProxyOptions): Promise<http.Server> {
  const sessions = new Map<string, AuditMirror>();
  const target = new URL(o.upstream);

  const server = http.createServer(async (req, res) => {
    try {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = Buffer.concat(chunks);
      const sid = (req.headers["mcp-session-id"] as string | undefined) ?? null;
      let mirror = sid ? sessions.get(sid) : undefined;
      if (!mirror) {
        mirror = new AuditMirror(o.mirror);
        if (sid) {
          mirror.mcpSessionId = sid;
          sessions.set(sid, mirror);
        }
      }
      const hp = req.headers["x-audittrail-principal"];
      if (typeof hp === "string" && hp) mirror.headerPrincipal = hp;

      let related: JsonRpcId | undefined;
      if (req.method === "POST" && body.length) {
        const msgs = parse(body.toString("utf8"));
        if (msgs.length === 1) {
          const d = mirror.onClientMessage(msgs[0]!);
          if (!d.forward) {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify(d.reply));
            return;
          }
          if (msgs[0]!.method && msgs[0]!.id !== undefined) related = msgs[0]!.id ?? undefined;
        } else for (const m of msgs) mirror.onClientMessage(m);
      }

      // Forward (path of the incoming request is ignored; the upstream URL is the MCP endpoint).
      const fwdHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (!HOP.has(k) && k !== "x-audittrail-principal" && typeof v === "string") fwdHeaders[k] = v;
      }
      Object.assign(fwdHeaders, o.headers);
      const up = await fetch(target, { method: req.method, headers: fwdHeaders, body: ["GET", "HEAD", "DELETE"].includes(req.method!) ? undefined : body });

      const newSid = up.headers.get("mcp-session-id");
      if (newSid && !sessions.has(newSid)) {
        mirror.mcpSessionId = newSid;
        sessions.set(newSid, mirror);
      }
      if (req.method === "DELETE" && sid) {
        sessions.get(sid)?.close("session deleted by client");
        sessions.delete(sid);
      }
      const outHeaders: Record<string, string> = {};
      up.headers.forEach((v, k) => {
        if (!HOP.has(k) && k !== "content-encoding") outHeaders[k] = v;
      });
      res.writeHead(up.status, outHeaders);
      const ct = up.headers.get("content-type") ?? "";
      if (!up.body) return res.end();
      if (ct.includes("text/event-stream")) {
        const parser = new SSEParser((data) => {
          for (const m of parse(data)) mirror!.onServerMessage(m, related);
        });
        const dec = new TextDecoder();
        req.on("close", () => void (up.body as ReadableStream).cancel().catch(() => undefined));
        for await (const chunk of up.body as unknown as AsyncIterable<Uint8Array>) {
          res.write(chunk);
          parser.push(dec.decode(chunk, { stream: true }));
        }
        res.end();
      } else {
        const buf = Buffer.from(await up.arrayBuffer());
        if (ct.includes("application/json")) for (const m of parse(buf.toString("utf8"))) mirror.onServerMessage(m, related);
        res.end(buf);
      }
    } catch (e) {
      o.log(`proxy error: ${(e as Error).message}`);
      if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32000, message: `AuditTrail proxy: upstream error: ${(e as Error).message}` } }));
    }
  });
  return new Promise((resolve) => server.listen(o.port, o.host ?? "127.0.0.1", () => resolve(server)));
}
