import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { v2 } from "@audittrail/core";
import { AuditTrail, type Metric } from "../src/index.js";
import { FileSpool } from "../src/node.js";

const KEY = "at2_0123456789ab_" + "A".repeat(43); // gitleaks:allow (fake)
const enc = new TextEncoder();

/** Fake server that verifies signatures like the real one and can be unplugged. */
async function fakeServer() {
  const { publicKeyB64 } = await v2.signingKeyFromApiKey(KEY);
  const pub = await crypto.subtle.importKey("raw", Uint8Array.from(atob(publicKeyB64), (c) => c.charCodeAt(0)), { name: "Ed25519" }, false, ["verify"]);
  const committed = new Map<string, string>();
  const order: string[] = [];
  const wire: string[] = [];
  const nonces = new Set<string>();
  const state = { online: true, dropResponses: 0, badSigs: 0 };
  const f: typeof fetch = async (_url, init) => {
    if (!state.online) throw new TypeError("fetch failed: ECONNREFUSED");
    const h = init!.headers as Record<string, string>;
    const body = String(init!.body);
    wire.push(JSON.stringify(h) + body);
    const msg = await v2.requestMessage("POST", "/v2/events", h["x-at-timestamp"]!, h["x-at-nonce"]!, enc.encode(body));
    const sig = Uint8Array.from(atob(h["x-at-signature"]!), (c) => c.charCodeAt(0));
    if (!(await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, enc.encode(msg))) || nonces.has(h["x-at-nonce"]!)) {
      state.badSigs++;
      return new Response(JSON.stringify({ error: { code: "unauthorized" } }), { status: 401 });
    }
    nonces.add(h["x-at-nonce"]!);
    let env;
    try {
      env = await v2.validateEnvelopeBytes(enc.encode(body));
    } catch (e) {
      const ce = e as v2.ContractError;
      return new Response(JSON.stringify({ error: { code: ce.code } }), { status: ce.status });
    }
    let status = 202;
    if (committed.has(env.event_id)) {
      if (committed.get(env.event_id) !== env.digest) return new Response(JSON.stringify({ error: { code: "idempotency_conflict" } }), { status: 409 });
      status = 200;
    } else {
      committed.set(env.event_id, env.digest);
      order.push(env.action);
    }
    if (state.dropResponses > 0) {
      state.dropResponses--;
      throw new TypeError("socket hang up (after commit)");
    }
    return new Response(JSON.stringify({ event_id: env.event_id, seq: order.indexOf(env.action) + 1, hash: "h" }), { status });
  };
  return { f, order, wire, state };
}

const opts = (f: typeof fetch, extra = {}) => ({ apiKey: KEY, agent: { id: "test-agent" }, fetch: f, retry: { baseDelayMs: 5, maxDelayMs: 20, authPauseMs: 20 }, ...extra });

describe("SDK v2", () => {
  it("signs requests the server can verify; computes payload_hash; server-sealed receipts", async () => {
    const srv = await fakeServer();
    const at = new AuditTrail(opts(srv.f));
    const r = await at.record({ action: "doc.read", resource: "doc/1", outcome: "allowed", payload: { n: 1.5, s: "x" } });
    expect(r?.seq).toBe(1);
    expect(srv.state.badSigs).toBe(0);
    const body = JSON.parse(srv.wire[0]!.slice(srv.wire[0]!.indexOf("}") + 1));
    expect(body.payload_hash).toBe(await v2.payloadHash(v2.fromJS({ n: 1.5, s: "x" })));
    expect(body.event_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7/);
  });

  it("network down mid-record, responses lost after commit: every event once, in order", async () => {
    const srv = await fakeServer();
    const at = new AuditTrail(opts(srv.f));
    await at.record({ action: "a.1", resource: "r", outcome: "allowed" });
    srv.state.online = false;
    const p = [2, 3, 4, 5, 6].map((i) => at.record({ action: `a.${i}`, resource: "r", outcome: "allowed" }));
    await new Promise((r) => setTimeout(r, 80));
    srv.state.online = true;
    srv.state.dropResponses = 2;
    await Promise.all(p);
    expect(srv.order).toEqual(["a.1", "a.2", "a.3", "a.4", "a.5", "a.6"]);
  });

  it("fail-open: invalid events never throw into the host; closed mode throws", async () => {
    const srv = await fakeServer();
    const errors: string[] = [];
    const at = new AuditTrail(opts(srv.f, { onError: (e: { code: string }) => errors.push(e.code) }));
    await expect(at.record({ action: "bad action!", resource: "r", outcome: "allowed" })).resolves.toBeNull();
    expect(at.track({ action: "x", resource: "r", outcome: "maybe" as never })).toMatch(/-7/);
    await new Promise((r) => setTimeout(r, 20));
    expect(errors).toEqual(["invalid_value", "invalid_value"]);
    const strict = new AuditTrail(opts(srv.f, { failMode: "closed" }));
    await expect(strict.record({ action: "bad action!", resource: "r", outcome: "allowed" })).rejects.toThrow();
  });

  it("C4: planted secrets never reach the wire", async () => {
    const srv = await fakeServer();
    const metrics: Metric[] = [];
    const at = new AuditTrail(opts(srv.f, { onMetric: (m: Metric) => metrics.push(m), redact: { piiKeys: ["email"] } }));
    const planted = {
      aws: "AKIAIOSFODNN7EXAMPLE",
      gh: "ghp_" + "a".repeat(36),
      openai: "sk-proj-" + "b".repeat(40),
      anthropic: "sk-ant-api03-" + "c".repeat(40),
      stripe: "sk_live_" + "d".repeat(24),
      jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", // gitleaks:allow (jwt.io sample)
      pem: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
      audittrail: "at2_0123456789ab_" + "Z".repeat(43),
      password_value: "hunter2-very-secret",
      email_value: "jane.doe@example.com",
    };
    await at.record({
      action: "tool.call",
      resource: `https://admin:${planted.password_value}@db.internal/x?token=${planted.gh}`,
      outcome: "allowed",
      payload: {
        note: `use ${planted.aws} and ${planted.openai}`,
        nested: { deep: [planted.anthropic, { k: planted.stripe }], header: `Bearer ${planted.jwt}` },
        key_material: planted.pem,
        forward: planted.audittrail,
        password: planted.password_value,
        email: planted.email_value,
      },
    });
    const wire = srv.wire.join("\n");
    for (const [name, secret] of Object.entries(planted)) {
      expect(wire.includes(secret), `${name} leaked`).toBe(false);
    }
    expect(wire).toContain("[REDACTED:aws_access_key]");
    expect(wire).toContain("[PII]");
    const red = metrics.find((m) => m.name === "redacted") as Extract<Metric, { name: "redacted" }>;
    expect(red.count).toBeGreaterThanOrEqual(10);
  });

  it("disk spool: survives a restart, dedupes, keeps order", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "at-")), "spool.jsonl");
    const down = await fakeServer();
    down.state.online = false;
    const a1 = new AuditTrail(opts(down.f, { spool: new FileSpool(path), retry: { baseDelayMs: 10_000 } }));
    a1.track({ action: "x.1", resource: "r", outcome: "allowed" });
    a1.track({ action: "x.2", resource: "r", outcome: "denied" });
    await new Promise((r) => setTimeout(r, 50));
    const up = await fakeServer();
    const a2 = new AuditTrail(opts(up.f, { spool: new FileSpool(path) }));
    await a2.record({ action: "x.3", resource: "r", outcome: "allowed" });
    await a2.flush();
    expect(up.order).toEqual(["x.1", "x.2", "x.3"]);
    expect(await a2.pending()).toBe(0);
  });

  it("concurrent record()/track() calls keep call order (payload sizes vary build time)", async () => {
    const srv = await fakeServer();
    const at = new AuditTrail(opts(srv.f));
    const want: string[] = [];
    const ps: Promise<unknown>[] = [];
    for (let i = 0; i < 40; i++) {
      want.push(`o.${i}`);
      const payload = { blob: "y".repeat((40 - i) * 2000) }; // earlier calls build slower
      if (i % 2) at.track({ action: `o.${i}`, resource: "r", outcome: "allowed", payload });
      else ps.push(at.record({ action: `o.${i}`, resource: "r", outcome: "allowed", payload }));
    }
    await Promise.all(ps);
    await at.flush();
    expect(srv.order).toEqual(want);
  });

  it("flush() right after track() waits for the event (no loss at shutdown)", async () => {
    const srv = await fakeServer();
    const at = new AuditTrail(opts(srv.f));
    at.track({ action: "last.words", resource: "r", outcome: "allowed", payload: { big: "x".repeat(10000) } });
    await at.flush();
    expect(srv.order).toEqual(["last.words"]);
  });

  it("auth failures keep events spooled (never silently dropped)", async () => {
    let n = 0;
    const f: typeof fetch = async () => (++n <= 3 ? new Response("{}", { status: 401 }) : new Response(JSON.stringify({ seq: 1 }), { status: 202 }));
    const at = new AuditTrail(opts(f));
    const r = await at.record({ action: "a", resource: "r", outcome: "allowed" });
    expect(r?.seq).toBe(1);
    expect(n).toBe(4);
  });
});
