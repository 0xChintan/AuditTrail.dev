# Your AI agents' logs aren't evidence yet

*For security and compliance leads at companies running AI agents in regulated workflows.*

Your agents already call tools: they read patient records, move money, edit production config. Somewhere there's a log of it. The question an auditor, a regulator or opposing counsel will ask is not *"do you have logs?"* It's **"how do you know these logs weren't changed, and who, exactly, was acting?"**

For most agent deployments today, the honest answer is: we don't, and we're not sure.

## What Article 12 actually asks for

The EU AI Act's Article 12 requires high-risk AI systems to **automatically record events over the system's lifetime**. The logs must let you identify situations that present a risk, support post-market monitoring, and support deployers' monitoring of operation. Articles 19(1) and 26(6) then require providers and deployers to **keep those logs for at least six months**.

(Article 113 scheduled the high-risk obligations, including Article 12, to apply from 2 August 2026. EU institutions have debated postponing parts of the high-risk regime, so check the current date for your system's category. The engineering is the same either way, and SOC 2 CC7.2 and NIST 800-53 AU-3 already ask for most of it.)

Three gaps show up again and again when teams try to meet this with ordinary application logs:

1. **Integrity.** A log row in Postgres or a log bucket can be edited by anyone with enough access, and nothing proves it wasn't.
2. **Attribution.** Agent logs record *that a tool was called*. They rarely record *which human it acted for, which model made the decision, and through which chain of delegation*. That chain is what Art. 12(2) and 12(3)(d) are really asking about.
3. **Denials.** Many setups log only successes. Blocked and failed actions are the evidence a risk review needs most.

## What we built

**AuditTrail** is an open-source, tamper-evident audit ledger with one front door built specifically for AI agents.

**`audittrail-mcp-proxy`** wraps any MCP server your agents already use (filesystem, GitHub, your internal tools) with **no code changes to the agent or the server**. Every tool call, resource read, and sampling or elicitation request becomes a signed ledger record containing:

- the **human principal**, the **agent**, the **model and version**, and **where each of those came from** (config, header, `_meta`, inferred, or unavailable). Unknown fields are recorded as unknown, never silently dropped;
- the **delegation chain**: human, then agent, then session, then turn, then the parent tool call, then this call. Nested server-to-agent requests are linked to the call that caused them;
- the **outcome**: allowed, **denied** (by policy, or declined by a human), or error.

Each record is **SHA-256 hash-chained** on the server, **Ed25519-signed** with a per-tenant key, and batched into **Merkle checkpoints** that are **time-stamped by an independent RFC 3161 authority**. Once a checkpoint is anchored, nobody can rewrite the records it covers without it being provable, not even someone with superuser access to the database and the signing key. Our test suite does exactly that and shows the verifier naming the altered record.

**Exports are what you hand to the auditor.** One click produces a PDF and CSV mapped to **EU AI Act Art. 12 / 19(1) / 26(6)**, **SOC 2 CC7.2** or **NIST SP 800-53 AU-3**. Every column is labeled with the clause it evidences, and the covering checkpoints and time-stamp proofs are included. The reviewer doesn't have to trust us: a standalone verifier, and a browser portal, recompute every hash, link, signature, Merkle root and time-stamp from the exported file alone.

Retention is enforced by the database, not by policy documents. The application role has no `DELETE` privilege. The only purge path refuses to run while a **legal hold** is set, and never breaks the chain's verifiability.

## Try it in 10 minutes

```sh
git clone https://github.com/audittrail-dev/audittrail && cd audittrail
scripts/setup.sh && scripts/dev.sh
```

Then wrap one MCP server your agent uses, let the agent work for a few minutes, and export an Article 12 report. The [quickstart](QUICKSTART.md) walks through each step.

## What we want to learn from you

We're talking with security and compliance teams running agents in healthcare, financial services and other regulated work. If you're working out how to evidence agent behavior for an auditor, regulator or customer due diligence, we'd like to hear:

- What does your auditor ask for today, and what couldn't you produce?
- Which identity fields does your agent stack actually expose (principal, model, delegation)?
- Where do the logs need to live: your cloud, your region, your KMS?

Reply to this post or open an issue. We read every one.

---
*AuditTrail maps evidence to clauses; it is not legal advice, and using it doesn't by itself make a system compliant.*
