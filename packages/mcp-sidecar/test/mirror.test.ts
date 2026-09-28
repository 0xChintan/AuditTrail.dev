import { describe, expect, it } from "vitest";
import { AuditMirror, redact } from "../src/mirror.js";
import { evaluate } from "../src/policy.js";

function setup(extra: Record<string, unknown> = {}) {
  const events: any[] = [];
  const m = new AuditMirror({ recorder: { track: (e) => events.push(e) }, identity: { osUserFallback: false }, upstream: "npx server-demo",
    transport: "stdio", ...extra });
  m.onClientMessage({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", clientInfo: { name: "claude-code", version: "2.1.0" } } });
  m.onServerMessage({ jsonrpc: "2.0", id: 0, result: { protocolVersion: "2025-06-18", serverInfo: { name: "demo", version: "1.0.0" } } });
  return { m, events };
}

describe("AuditMirror", () => {
  it("records a tool call with the full identity chain, marking unknowns", () => {
    const { m, events } = setup();
    m.onClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read_file", arguments: { path: "/a", api_key: "sk-123" } } });
    m.onServerMessage({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "hi" }] } });
    const e = events.find((x) => x.action === "mcp.tools/call");
    expect(e.target_resource).toBe("mcp://demo/tools/read_file");
    expect(e.agent_id).toBe("claude-code@2.1.0");
    expect(e.human_principal_id).toBeNull();
    expect(e.model_id).toBe("unknown");
    expect(e.metadata.identity_provenance).toMatchObject({ human_principal_id: "unavailable", agent_id: "client_info", model_id: "unavailable" });
    expect(e.metadata.arguments.api_key).toBe("[REDACTED]");
    expect(e.delegation_chain.map((f: any) => f.type)).toEqual(["human", "agent", "mcp_session", "turn", "tool_call"]);
    expect(e.delegation_chain[0].id).toBe("unknown");
    expect(e.outcome).toBe("allowed");
  });

  it("request _meta overrides identity, isError => error", () => {
    const { m, events } = setup();
    m.onClientMessage({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "x", arguments: {},
      _meta: { "audittrail.dev/principal": "alice", "audittrail.dev/model": "claude-opus-5-5", "audittrail.dev/delegation": [{ type: "subagent", id: "planner" }] } } });
    m.onServerMessage({ jsonrpc: "2.0", id: 2, result: { content: [{ type: "text", text: "boom" }], isError: true } });
    const e = events.at(-1);
    expect(e.human_principal_id).toBe("alice");
    expect(e.model_id).toBe("claude-opus-5-5");
    expect(e.outcome).toBe("error");
    expect(e.metadata.tool_error).toBe("boom");
    expect(e.delegation_chain.some((f: any) => f.type === "subagent" && f.id === "planner")).toBe(true);
  });

  it("server-initiated sampling nests under the in-flight tool call and reveals the model", () => {
    const { m, events } = setup();
    m.onClientMessage({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "summarize", arguments: {} } });
    m.onServerMessage({ jsonrpc: "2.0", id: 99, method: "sampling/createMessage", params: { messages: [] } }, 3);
    m.onClientMessage({ jsonrpc: "2.0", id: 99, result: { model: "claude-sonnet-5", role: "assistant", content: { type: "text", text: "ok" } } });
    m.onServerMessage({ jsonrpc: "2.0", id: 3, result: { content: [] } });
    const s = events.find((x) => x.action === "mcp.sampling/createMessage");
    const parent = s.delegation_chain.find((f: any) => f.type === "tool_call");
    expect(parent.tool).toBe("summarize");
    expect(s.metadata.sampling_model).toBe("claude-sonnet-5");
    const call = events.find((x) => x.action === "mcp.tools/call");
    expect(call.model_id).toBe("claude-sonnet-5");
    expect(call.metadata.identity_provenance.model_id).toBe("observed_sampling");
  });

  it("policy deny short-circuits and records denied", () => {
    const { m, events } = setup({ policy: { deny: ["write_*"], allow: [] } });
    const d = m.onClientMessage({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "write_file", arguments: { path: "/etc/x" } } });
    expect(d.forward).toBe(false);
    expect(d.reply?.result.isError).toBe(true);
    expect(events.at(-1).outcome).toBe("denied");
    expect(events.at(-1).metadata.policy.rule).toBe("deny:write_*");
  });

  it("declined elicitation is a denial by the human", () => {
    const { m, events } = setup();
    m.onServerMessage({ jsonrpc: "2.0", id: 7, method: "elicitation/create", params: { message: "Deploy?" } });
    m.onClientMessage({ jsonrpc: "2.0", id: 7, result: { action: "decline" } });
    expect(events.at(-1).outcome).toBe("denied");
  });

  it("unanswered calls are recorded on close", () => {
    const { m, events } = setup();
    m.onClientMessage({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "slow", arguments: {} } });
    m.close("server exited");
    expect(events.at(-1)).toMatchObject({ outcome: "error" });
    expect(events.at(-1).metadata.no_response).toBe(true);
  });
});

describe("policy + redaction", () => {
  it("allowlist and server-scoped patterns", () => {
    expect(evaluate({ allow: ["read_*"], deny: [] }, "fs", "write_file").allowed).toBe(false);
    expect(evaluate({ allow: ["read_*"], deny: [] }, "fs", "read_file").allowed).toBe(true);
    expect(evaluate({ allow: [], deny: ["fs/*"] }, "fs", "anything").allowed).toBe(false);
  });
  it("redacts nested secrets", () => {
    expect(redact({ a: { Authorization: "Bearer x", ok: 1 } })).toEqual({ a: { Authorization: "[REDACTED]", ok: 1 } });
  });
});
