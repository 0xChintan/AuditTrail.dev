export function setupSnippets(apiKey: string, apiUrl: string) {
  return {
    sdk: `npm install @audittrail/sdk

import { AuditTrail } from "@audittrail/sdk";

const audit = new AuditTrail({
  apiKey: process.env.AUDITTRAIL_API_KEY,   // ${apiKey.slice(0, 16)}…
  baseUrl: "${apiUrl}",
  agentId: "billing-service",
});

await audit.record({
  human_principal_id: "user_123",
  action: "invoice.refund",
  target_resource: "invoice/INV-2041",
  outcome: "allowed",
});`,
    mcp: JSON.stringify(
      {
        mcpServers: {
          filesystem: {
            command: "npx",
            args: ["-y", "audittrail-mcp-proxy", "--principal", "you@company.com", "--model", "claude-opus-5-5", "--",
              "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"],
            env: { AUDITTRAIL_API_KEY: apiKey, AUDITTRAIL_API_URL: apiUrl },
          },
        },
      },
      null,
      2,
    ),
    claude: `claude mcp add filesystem \\
  -e AUDITTRAIL_API_KEY=${apiKey} -e AUDITTRAIL_API_URL=${apiUrl} \\
  -- npx -y audittrail-mcp-proxy --principal you@company.com -- \\
  npx -y @modelcontextprotocol/server-filesystem ~/project`,
    curl: `curl -X POST ${apiUrl}/v1/events \\
  -H "Authorization: Bearer ${apiKey}" \\
  -d '{"agent_id":"smoke-test","action":"test.ping","target_resource":"none","outcome":"allowed"}'`,
  };
}
