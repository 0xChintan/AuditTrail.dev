import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AuditTrail } from "../src/index.js";
import { FileQueueStore } from "../src/node.js";

/** A fake ingestion server that can be "unplugged". */
function fakeServer() {
  const received: any[] = [];
  const committedIds = new Set<string>();
  const state = { online: true, dropResponses: 0 };
  const f: typeof fetch = async (_url, init) => {
    if (!state.online) throw new TypeError("fetch failed: ECONNREFUSED");
    const body = JSON.parse(String(init!.body));
    let status = 201;
    if (committedIds.has(body.id)) status = 200;
    else {
      committedIds.add(body.id);
      received.push(body);
    }
    if (state.dropResponses > 0) {
      // Request reached the server and was committed, but the response was lost.
      state.dropResponses--;
      throw new TypeError("fetch failed: socket hang up");
    }
    return new Response(JSON.stringify({ ...body, seq: received.findIndex((r) => r.id === body.id) + 1, hash: "h" }), { status });
  };
  return { f, received, state };
}

describe("retry queue", () => {
  it("network down mid-record(): events still arrive, in order, once each", async () => {
    const srv = fakeServer();
    const at = new AuditTrail({ apiKey: "at_x", fetch: srv.f, agentId: "test", retry: { baseDelayMs: 5, maxDelayMs: 20 } });
    await at.record({ action: "a.1", target_resource: "r", outcome: "allowed" });
    srv.state.online = false;
    const pending = [2, 3, 4, 5].map((i) => at.record({ action: `a.${i}`, target_resource: "r", outcome: "allowed" }));
    await new Promise((r) => setTimeout(r, 100));
    expect(srv.received.length).toBe(1);
    expect(await at.pending()).toBe(4);
    srv.state.online = true;
    const recs = await Promise.all(pending);
    expect(recs.map((r) => r.action)).toEqual(["a.2", "a.3", "a.4", "a.5"]);
    expect(srv.received.map((r) => r.action)).toEqual(["a.1", "a.2", "a.3", "a.4", "a.5"]);
  });

  it("response lost after commit: retry is idempotent (no duplicate)", async () => {
    const srv = fakeServer();
    srv.state.dropResponses = 2;
    const at = new AuditTrail({ apiKey: "at_x", fetch: srv.f, agentId: "test", retry: { baseDelayMs: 5, maxDelayMs: 20 } });
    const r = await at.record({ action: "pay", target_resource: "r", outcome: "allowed" });
    expect(r.action).toBe("pay");
    expect(srv.received.length).toBe(1);
  });

  it("permanent 4xx rejection does not block later events", async () => {
    let n = 0;
    const f: typeof fetch = async (_u, init) => {
      n++;
      const b = JSON.parse(String(init!.body));
      if (b.action === "bad") return new Response(JSON.stringify({ error: { code: "validation_failed", message: "nope" } }), { status: 400 });
      return new Response(JSON.stringify(b), { status: 201 });
    };
    const errors: string[] = [];
    const at = new AuditTrail({ apiKey: "at_x", fetch: f, agentId: "t", onError: (e) => errors.push(e.code) });
    await expect(at.record({ action: "bad", target_resource: "r", outcome: "allowed" })).rejects.toThrow("nope");
    await expect(at.record({ action: "good", target_resource: "r", outcome: "allowed" })).resolves.toMatchObject({ action: "good" });
    expect(errors).toEqual(["validation_failed"]);
    expect(n).toBe(2);
  });

  it("FileQueueStore: events survive a process restart and are sent first", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "at-")), "q.jsonl");
    const down = fakeServer();
    down.state.online = false;
    const a1 = new AuditTrail({ apiKey: "at_x", fetch: down.f, agentId: "t", store: new FileQueueStore(path), retry: { baseDelayMs: 1000 } });
    a1.track({ action: "x.1", target_resource: "r", outcome: "allowed" });
    a1.track({ action: "x.2", target_resource: "r", outcome: "denied" });
    await new Promise((r) => setTimeout(r, 50));
    // "crash": abandon a1, start a new process with the same journal
    const up = fakeServer();
    const a2 = new AuditTrail({ apiKey: "at_x", fetch: up.f, agentId: "t", store: new FileQueueStore(path) });
    await a2.record({ action: "x.3", target_resource: "r", outcome: "allowed" });
    await a2.flush();
    expect(up.received.map((r) => r.action)).toEqual(["x.1", "x.2", "x.3"]);
    expect(await a2.pending()).toBe(0);
  });
});
