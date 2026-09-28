# Quickstart: from zero to a verifiable compliance export

This takes about 10 minutes and needs no help from anyone. By the end you'll have:

1. a tenant with its own hash chain and signing key,
2. an AI agent whose MCP tool calls are recorded automatically,
3. a PDF/CSV compliance export, and an evidence bundle you've verified yourself.

## 0. Run the stack

```sh
git clone https://github.com/0xChintan/AuditTrail.dev && cd AuditTrail.dev
scripts/setup.sh    # needs Go ≥1.26, Node ≥20 + pnpm, Postgres running locally
scripts/dev.sh      # API :8080 · 3 local witnesses :7101-7103 · worker · dashboard :3000
```

`setup.sh` connects to Postgres as your OS user (`DATABASE_ADMIN_URL` in `.env`). It creates the `audittrail` database and the least-privilege roles, and writes fresh secrets to `.env`: master key, admin token, API-key pepper and `DASHBOARD_PASSWORD`.

## 1. Onboard a tenant

Open **http://localhost:3000** and sign in with any username and the `DASHBOARD_PASSWORD` from `.env`. Go to **Onboard a tenant**, enter a name, and create it. Copy the API key it shows (`at2_…`): it can't be displayed again.

Or from the CLI:

```sh
packages/ingestion-go/bin/admin create-tenant -name "Acme agents"
```

## 2. Wrap your agent's MCP server

Pick any MCP server your agent already uses and put the proxy in front of it. No change to the agent or the server is needed.

**Claude Code**

```sh
claude mcp add fs \
  -e AUDITTRAIL_API_KEY=at2_… -e AUDITTRAIL_API_URL=http://localhost:8080 -e AUDITTRAIL_MODEL=claude-opus-5-5 \
  -- npx -y audittrail-mcp-proxy --principal you@company.com --deny write_file -- \
     npx -y @modelcontextprotocol/server-filesystem ~/some/project
```

**Claude Desktop / Cursor / any MCP client (JSON config)**

```json
{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "audittrail-mcp-proxy", "--principal", "you@company.com", "--deny", "write_file", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"],
      "env": { "AUDITTRAIL_API_KEY": "at2_…", "AUDITTRAIL_API_URL": "http://localhost:8080", "AUDITTRAIL_MODEL": "claude-opus-5-5" }
    }
  }
}
```

> Running from this repo before the npm packages are published? Replace `npx -y audittrail-mcp-proxy` with `node /path/to/audittrail/packages/mcp-sidecar/dist/cli.js`.

Now ask the agent to list, read and then write a file. In the dashboard's **Activity** tab you'll see one record per call, including the `write_file` call **denied** by the policy. The proxy also pins each tool's definition on first sight (`--on-drift block` refuses calls to a tool whose definition later changes) and sends a heartbeat, so a proxy that goes silent raises an alert. Click any row to see its identity chain (human > agent > session > turn > tool call), where each identity field came from, and **Verify in this browser**.

## 3. Wait for a witnessed tree head

Every 30 s in `dev.sh` (every 2 min by default), the worker signs a C2SP tree head for each tenant's log, asks the three local witnesses to cosign it, and time-stamps it with FreeTSA. The witnesses check that each new head is consistent with the last one they saw, so the log can't fork or rewrite history without a witness refusing. The **Checkpoints** tab shows each head, its witnesses and its anchor.

> The local witnesses run with `-tofu` (trust the log key on first sight), which is for development only. In production, witnesses are run by independent parties and configured with your log key out of band.

## 4. Export and verify

Go to **Compliance exports** and choose a template:

- **EU AI Act: Art. 12 / 19(1) / 26(6)**
- **SOC 2: CC7.2**
- **NIST SP 800-53: AU-3**

Download the **PDF report** (for reviewers; it lists the witnessed tree heads), the **CSV** (every column header names its clause, e.g. `timestamp [AU-3(b)]`), and the **Evidence bundle**.

Verify the bundle independently. The auditor needs the file plus the keys they choose to trust: the tenant's log key and the witnesses' keys, obtained out of band.

```sh
TENANT=<tenant id>
curl -s localhost:8080/v2/tenants/$TENANT/log | jq -r '.vkeys[0]' > log.vkey
packages/ingestion-go/bin/verify \
  --log-key "$(cat log.vkey)" \
  --witness "$(cat ~/.audittrail-dev/witnesses/w1.vkey)" \
  --witness "$(cat ~/.audittrail-dev/witnesses/w2.vkey)" \
  --witness "$(cat ~/.audittrail-dev/witnesses/w3.vkey)" \
  --quorum 2 --max-age 24h \
  ~/Downloads/audittrail-*.bundle.v2.json
# RESULT: VERIFIED
```

It checks 14 named invariants (content and payload hashes, chain links, seq continuity, row signatures, Merkle roots, consistency between tree heads, the log signature, the witness quorum, the RFC 3161 anchor, freshness, fork and coverage), and names the exact rows that fail. Add `--require-covered` to fail on rows newer than the last witnessed head.

You can also drop the bundle on **http://localhost:3000/verify**. The same Go verifier, compiled to WebAssembly, runs in your browser with no network access. Every record in the **Activity** tab also has a **Verify in this browser** button.

## 5. See tampering get caught (optional)

```sh
scripts/tamper-demo.sh      # edits and deletes rows directly in Postgres as a superuser
```

The verifier names the invariant and the exact row: `[FAIL content-hash] row 15`, `[FAIL payload-hash] row 33`, `[FAIL seq-continuity] rows 20..20 are missing`. The tree-head worker refuses to sign a log that doesn't verify.

## Using the SDK instead (your own app's events)

```ts
import { AuditTrail } from "@audittrail/sdk";
const audit = new AuditTrail({ apiKey: process.env.AUDITTRAIL_API_KEY!, baseUrl: "http://localhost:8080", agent: { id: "billing-service" } });
await audit.record({ principal: { id: "user_123", type: "human" }, action: "invoice.refund", resource: "invoice/42", outcome: "allowed" });
```

The SDK signs every request, redacts secrets before hashing, spools to disk (`FileSpool`) during outages, and never throws into your app unless you choose `failMode: "closed"`. See [`packages/sdk/README.md`](../packages/sdk/README.md) for Express and Next.js middleware and for crypto-shreddable personal data (`pii`).

## Using OpenTelemetry instead

If your agents already emit OpenTelemetry `gen_ai.*` spans, point an OTLP/HTTP exporter at AuditTrail. JSON and protobuf both work, and semconv 1.36 and 1.37+ attribute names are both understood. Exporters can't sign requests, so create a dedicated key with only the `otlp:write` scope:

```sh
curl -s -X POST localhost:8080/v1/admin/tenants/$TENANT/api-keys \
  -H "Authorization: Bearer $AUDITTRAIL_ADMIN_TOKEN" -d '{"name":"otel","scopes":["otlp:write"]}'

OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:8080/v1/traces
OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer at2_…"
```

Message content attributes are never copied into the log. A re-exported span maps to the same event id, so retries don't create duplicates.
