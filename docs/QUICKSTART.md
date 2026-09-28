# Quickstart: from zero to a verifiable compliance export

This takes about 10 minutes and needs no help from anyone. By the end you'll have:

1. a tenant with its own hash chain and signing key,
2. an AI agent whose MCP tool calls are recorded automatically,
3. a PDF/CSV compliance export, and an evidence bundle you've verified yourself.

## 0. Run the stack

```sh
git clone https://github.com/audittrail-dev/audittrail && cd audittrail
scripts/setup.sh    # needs Go ≥1.26, Node ≥20 + pnpm, Postgres running locally
scripts/dev.sh      # API :8080 · worker · dashboard :3000
```

`setup.sh` connects to Postgres as your OS user (`DATABASE_ADMIN_URL` in `.env`). It creates the `audittrail` database and the least-privilege roles.

## 1. Onboard a tenant

Open **http://localhost:3000**, go to **Onboard a tenant**, enter a name, and create it. Copy the API key it shows: it can't be displayed again.

Or from the CLI:

```sh
packages/ingestion-go/bin/admin create-tenant -name "Acme agents"
```

## 2. Wrap your agent's MCP server

Pick any MCP server your agent already uses and put the proxy in front of it. No change to the agent or the server is needed.

**Claude Code**

```sh
claude mcp add fs \
  -e AUDITTRAIL_API_KEY=at_… -e AUDITTRAIL_API_URL=http://localhost:8080 -e AUDITTRAIL_MODEL=claude-opus-5-5 \
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
      "env": { "AUDITTRAIL_API_KEY": "at_…", "AUDITTRAIL_API_URL": "http://localhost:8080", "AUDITTRAIL_MODEL": "claude-opus-5-5" }
    }
  }
}
```

> Running from this repo before the npm packages are published? Replace `npx -y audittrail-mcp-proxy` with `node /path/to/audittrail/packages/mcp-sidecar/dist/cli.js`.

Now ask the agent to list, read and then write a file. In the dashboard's **Activity** tab you'll see one record per call, including the `write_file` call **denied** by the policy. Click any row to see its identity chain (human > agent > session > turn > tool call), where each identity field came from, and **Verify in this browser**.

## 3. Wait for a checkpoint

The worker checkpoints new records every 30 s in `dev.sh` (every 2 min by default), then time-stamps each checkpoint with FreeTSA. The **Checkpoints** tab shows the status change from `pending` to `anchored`.

## 4. Export and verify

Go to **Compliance exports** and choose a template:

- **EU AI Act: Art. 12 / 19(1) / 26(6)**
- **SOC 2: CC7.2**
- **NIST SP 800-53: AU-3**

Download the **PDF report** (for reviewers), the **CSV** (every column header names its clause, e.g. `timestamp [AU-3(b)]`), and the **Evidence bundle**.

Verify the bundle independently. The auditor needs only the file:

```sh
packages/ingestion-go/bin/verify \
  --tsa-roots schemas/tsa-roots/freetsa-cacert.pem --require-anchors \
  ~/Downloads/audittrail-*.bundle.json
# RESULT: VERIFIED
```

You can also drop the bundle on **http://localhost:3000/verify**, where everything is recomputed in the browser.

## 5. See tampering get caught (optional)

```sh
scripts/tamper-demo.sh      # edits and deletes rows directly in Postgres as a superuser
```

The verifier names the exact records: `content_tampered seq 15`, `checkpoint_rows_missing seq 20`. The checkpoint worker refuses to sign a chain that doesn't verify.

## Using the SDK instead (your own app's events)

```ts
import { AuditTrail } from "@audittrail/sdk";
const audit = new AuditTrail({ apiKey: process.env.AUDITTRAIL_API_KEY!, baseUrl: "http://localhost:8080", agentId: "billing-service" });
await audit.record({ human_principal_id: "user_123", action: "invoice.refund", target_resource: "invoice/42", outcome: "allowed" });
```

See [`packages/sdk/README.md`](../packages/sdk/README.md) for Express and Next.js middleware.
