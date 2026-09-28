# AuditTrail dashboard

Next.js 16 + Tailwind 4 + shadcn (Base UI).

- **Tenants**: onboarding creates the genesis chain, signing key and API key, and shows the key once with copy-paste setup for the MCP proxy, Claude Code, the SDK and curl.
- **Activity**: a live timeline of every record, filterable by outcome (denied and error included), agent and action. Selecting a record shows its identity chain, the provenance of each identity field, metadata, and **in-browser verification**: hash, signature, Merkle inclusion and checkpoint signature.
- **Checkpoints**: Merkle checkpoints and their RFC 3161 anchor status.
- **Compliance exports**: EU AI Act / SOC 2 / NIST templates as PDF, CSV or evidence bundle.
- **Keys**: create and revoke API keys; view and rotate Ed25519 signing keys.
- **Retention & settings**: legal hold (with a required reason), retention window, rate limit.
- **/verify**: a public verification portal for a record, an inclusion proof or a whole bundle, computed in the browser.

## Configuration (`.env.local`)

| var | |
|---|---|
| `AUDITTRAIL_API_URL` | Ingestion API (server-side), default `http://localhost:8080` |
| `AUDITTRAIL_ADMIN_TOKEN` | Admin token. Used only on the server and never sent to the browser. |
| `AUDITTRAIL_PUBLIC_API_URL` | API URL shown in the setup snippets, if it differs |
| `DASHBOARD_PASSWORD` | Optional HTTP basic-auth gate. `/verify` stays public. |

`pnpm dev` runs on http://localhost:3000.
