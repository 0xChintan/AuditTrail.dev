# Dogfood log: real agents through the sidecar

## 2026-09-28: Claude Code 2.1.283 (headless, Haiku) → proxy → server-filesystem

Setup: proxy with `--principal chintan@blokcapital.io --deny write_file`, wrapping `@modelcontextprotocol/server-filesystem`. Prompt: list a directory, read `notes.txt`, then try to write `summary.txt`.

Ledger result (per call):

| seq | outcome | target | principal (source) | agent (source) | model (source) |
|---|---|---|---|---|---|
| 4 | allowed | `mcp://secure-filesystem-server` (session start) | chintan@… (flag) | claude-code@2.1.283 (client_info) | unknown (unavailable) |
| 5 | allowed | `…/tools/list_directory` | ″ | ″ | ″ |
| 6 | allowed | `…/tools/read_text_file` | ″ | ″ | ″ |
| 7 | **denied** | `…/tools/write_file` | ″ | ″ | ″ |

The agent's own summary: *"The directory list and read succeeded, but the write attempt was blocked by AuditTrail policy that denies write_file access for this agent."*

### Findings and fixes

1. **Model is not visible to MCP servers.** Claude Code doesn't send its model in `initialize`, per-request `_meta`, or the server's environment, so `model_id` is `unknown` (provenance `unavailable`). This is honest, but less useful than it could be.
   *Fix / guidance:* set `--model` or `env.AUDITTRAIL_MODEL` in the MCP server config (see the README). The proxy also picks up a model reported in any sampling response (`observed_sampling`).
2. **Turn grouping works as intended.** The list, read and write calls from one agent turn share one inferred `turn` frame. The earlier aborted run (which only listed) is a separate session.
3. **Server names can contain `/`.** server-everything reports `mcp-servers/everything`, which made `target_resource` ambiguous. *Fixed:* the server segment is now percent-encoded (`mcp://mcp-servers%2Feverything/tools/echo`).
4. **Claude Code's own permission prompt is invisible to MCP.** In the first run the agent stopped to ask for tool permission, and nothing reached the proxy for that call. Denials *inside the agent host* aren't MCP events. The ledger shows what reached the tool boundary: an allowed call, or one the proxy denied.

Still to do for Task 7.3: run it daily for a week on a real coding workflow.
