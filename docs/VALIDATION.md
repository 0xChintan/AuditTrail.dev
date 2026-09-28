# Validation: 15 compliance/security-lead calls (v2 task 7.4)

**Goal:** find out whether people will pay for *offline-verifiable evidence* of AI-agent activity over what they use today.

**Kill criterion:** if fewer than **3 of 15** say they would pay for it over their current tool, pivot or stop. Decide by the date you set below; don't move the goalposts afterwards.

## Who to call

Security and compliance leads (CISO org, GRC, internal audit, AI governance) at companies that run AI agents in regulated work: healthcare, financial services, insurance, and B2B SaaS selling into them. Mix sizes. Skip generic SaaS CTOs.

## Script (30 min, listen more than you talk)

1. *Context:* "Which AI agents or copilots take actions in your environment today? Which ones touch regulated data or systems?"
2. *Current evidence:* "If an auditor or regulator asked 'show me what this agent did on 3 March and who authorized it', what would you hand over? How long would it take?"
3. *Trust gap:* "Could the team that runs the agent, or the vendor, alter those logs? Would your auditor accept them if they could?"
4. *Identity:* "Do your logs today tie an agent action to the human it acted for, the model version, and the chain of delegation?"
5. *Drivers:* "What's forcing this: EU AI Act (Annex III, Dec 2027), SOC 2, customer due diligence, internal risk? When is the deadline?"
6. *Show, don't pitch (5 min):* the dashboard → export a SOC 2 or Art. 12 PDF → the auditor verifies the bundle offline with `audittrail-verify` / the browser portal, and a tampered row is caught.
7. *Willingness to pay:* "Would you pay for this instead of what you have? What would it replace? Who signs off, and roughly at what price band?"
8. *Deal-breakers:* "What would stop you: self-hosting, data residency, KMS, SSO, witness operators?"

## Tracker

| # | Company / role | Sector | Agents in prod? | Current evidence | Would pay over current tool? (Y/N/maybe) | Price signal | Blockers | Next step |
|---|---|---|---|---|---|---|---|---|
| 1 | | | | | | | | |
| 2 | | | | | | | | |
| 3 | | | | | | | | |
| 4 | | | | | | | | |
| 5 | | | | | | | | |
| 6 | | | | | | | | |
| 7 | | | | | | | | |
| 8 | | | | | | | | |
| 9 | | | | | | | | |
| 10 | | | | | | | | |
| 11 | | | | | | | | |
| 12 | | | | | | | | |
| 13 | | | | | | | | |
| 14 | | | | | | | | |
| 15 | | | | | | | | |

**Count of "Yes":** ___ / 15 → **continue** if ≥ 3, otherwise **pivot or stop**. Decision date: ______
