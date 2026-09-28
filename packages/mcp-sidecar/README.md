# audittrail-mcp-proxy

**A tamper-evident audit trail for every tool call your AI agents make, without changing any code.**

`audittrail-mcp-proxy` sits between an MCP client (Claude Code, Claude Desktop, Cursor, your own agent) and any MCP server. It passes every message through unchanged and records each agent action (tool calls, resource reads, prompt fetches, sampling and elicitation requests) in your [AuditTrail](https://audittrail.dev) ledger. Each record is hash-chained, Ed25519-signed and periodically anchored with an RFC 3161 timestamp.

```
agent host ──stdio/HTTP──▶ audittrail-mcp-proxy ──stdio/HTTP──▶ MCP server
                                  │
                                  └──▶ AuditTrail ledger (one signed, chained record per action)
```

## Wrap a local (stdio) MCP server

In your agent's MCP config, set the proxy as the `command` and put the original server command after `--`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y", "audittrail-mcp-proxy",
        "--principal", "alice@example.com",
        "--model", "claude-opus-5-5",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/projects"
      ],
      "env": {
        "AUDITTRAIL_API_KEY": "at_…",
        "AUDITTRAIL_API_URL": "https://api.audittrail.dev"
      }
    }
  }
}
```

With Claude Code: `claude mcp add filesystem -e AUDITTRAIL_API_KEY=at_… -- npx -y audittrail-mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem ~/projects`

## Wrap a remote (Streamable HTTP) MCP server

The proxy can present a remote server to the agent as a local stdio server:

```sh
npx audittrail-mcp-proxy --upstream https://mcp.example.com/mcp --header "Authorization: Bearer $UPSTREAM_TOKEN"
```

It can also run as an HTTP endpoint that the agent connects to:

```sh
npx audittrail-mcp-proxy --upstream https://mcp.example.com/mcp --listen 7331
# point the agent at http://127.0.0.1:7331/mcp
# optional: the agent host sends "X-AuditTrail-Principal: <user>" per session
```

## What gets recorded

Each action produces one ledger record:

| field | from |
|---|---|
| `human_principal_id` | `_meta["audittrail.dev/principal"]` on the request, then the session's initialize `_meta`, then the `X-AuditTrail-Principal` header, then `--principal` / `AUDITTRAIL_PRINCIPAL`, then the OS user (labeled `inferred:os_user`) |
| `agent_id` | `_meta`, then `--agent-id` / `AUDITTRAIL_AGENT_ID`, then the MCP `clientInfo` name@version |
| `model_id` / `model_version` | `_meta`, then `--model` / `AUDITTRAIL_MODEL` / `ANTHROPIC_MODEL`, then the model reported in a sampling result |
| `delegation_chain` | `human > agent > [caller-supplied frames] > mcp_session > turn > [parent tool_call] > this call` |
| `action` | `mcp.tools/call`, `mcp.resources/read`, `mcp.prompts/get`, `mcp.sampling/createMessage`, `mcp.elicitation/create`, `mcp.session/initialize` |
| `target_resource` | `mcp://<server>/tools/<tool>` (server name taken from MCP `serverInfo`) |
| `outcome` | `allowed`; `error` (JSON-RPC error, `isError`, no response, cancelled); `denied` (blocked by proxy policy, or the human declined an elicitation) |
| `metadata` | arguments (redacted by default) plus their SHA-256, a result summary and SHA-256, latency, session and protocol info, and **`identity_provenance`**, which records where each identity field came from |

**Unknown fields are recorded as unknown, not left out.** If the agent host doesn't reveal the model, the record says `model_id: "unknown"` with provenance `unavailable`. An auditor can always tell a verified identity from an inferred or missing one.

**Nested calls.** When an MCP server sends a request back to the agent during a tool call (sampling or elicitation), that request's delegation chain includes the parent tool call. Over HTTP the link is exact, because the request arrives on the parent call's response stream. Over stdio it's inferred from the single call in flight. Hosts that orchestrate sub-agents can pass their own frames in `_meta["audittrail.dev/delegation"]` and `_meta["audittrail.dev/parent_call"]`.

## Policy

```sh
--deny 'write_*' --deny 'delete_*'      # block matching tools
--allow 'read_*' --allow 'list_*'       # allowlist mode
--deny 'github/*'                       # scope a pattern to one server
```

A blocked call never reaches the server. The agent receives a tool result with `isError: true` that explains the block, and the ledger records the call with outcome `denied`.

## Reliability

- Audit delivery never blocks or changes MCP traffic.
- Events are journaled to a local file (`~/.audittrail/…`, override with `--queue`) before delivery. If the ledger is unreachable or the proxy crashes, events are sent on the next start, in order, with no duplicates.
- Logs go to stderr only. In stdio mode, stdout carries MCP traffic and nothing else.

## Options

Run `npx audittrail-mcp-proxy --help` for the full list: `--capture-args full|redacted|hash|none`, `--audit-all`, `--server-name`, `--no-os-principal`, `--quiet`.
