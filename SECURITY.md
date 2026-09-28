# Security policy

## Reporting a vulnerability

Please **don't open a public issue**. Report privately through GitHub Security Advisories:
https://github.com/0xChintan/AuditTrail.dev/security/advisories/new

Include affected versions or commits, reproduction steps, and the impact you see. We aim to:

| Step | Target |
|---|---|
| Acknowledge | within 3 business days |
| Initial assessment + severity | within 7 days |
| Fix for critical/high | within 30 days |
| Public advisory + credit | after the fix ships, coordinated with you |

We won't take legal action for good-faith research that avoids privacy violations, data destruction and service disruption, and that gives us reasonable time to fix before disclosure.

## Scope

In scope: the ingestion API, checkpoint worker, witness, verifier, SDK (`@audittrail/sdk`, `@audittrail/core`), MCP proxy (`audittrail-mcp-proxy`) and dashboard in this repository.

**Especially interesting:** anything that lets an event be changed, removed, reordered or forked without the offline verifier noticing. Also cross-tenant access, request replay, and secrets or PII reaching storage in plaintext.

Out of scope: vulnerabilities in third-party MCP servers or agent hosts, missing hardening headers on local dev servers, and denial of service by volume against a self-hosted instance.

## Design

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threats, controls and the tests that enforce them, and [SECRETS.md](SECRETS.md) for key handling and rotation.
