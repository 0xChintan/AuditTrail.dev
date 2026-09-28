package export

// Compliance export templates (Task 6.1). Each template says which clause a
// field evidences and why, so a reviewer with no context can check the
// mapping row by row. Requirement texts are short paraphrases with the
// clause reference; the authoritative wording is the cited regulation or
// framework. This is evidence mapping, not legal advice.

type Clause struct {
	Ref         string `json:"ref"`
	Title       string `json:"title"`
	Requirement string `json:"requirement"`
	Evidence    string `json:"evidence"`
}

type FieldMapping struct {
	Field     string   `json:"field"`
	Label     string   `json:"label"`
	Clauses   []string `json:"clauses"`
	Rationale string   `json:"rationale"`
}

type Template struct {
	ID               string         `json:"id"`
	Title            string         `json:"title"`
	Source           string         `json:"source"`
	Summary          string         `json:"summary"`
	MinRetentionDays int            `json:"min_retention_days"`
	RetentionClause  string         `json:"retention_clause"`
	Clauses          []Clause       `json:"clauses"`
	Fields           []FieldMapping `json:"fields"`
	HighlightOutcome []string       `json:"highlight_outcomes"`
	Applicability    string         `json:"applicability,omitempty"`
}

var integrityFields = []string{"seq", "previous_hash", "hash", "signature", "key_id"}

var Templates = []Template{
	{
		ID:     "eu-ai-act-art12",
		Title:  "EU AI Act: Article 12 record-keeping and log retention (Art. 19(1) / 26(6))",
		Source: "Regulation (EU) 2024/1689 (Artificial Intelligence Act)",
		Summary: "Shows that events of the AI system were recorded automatically across its lifetime, cryptographically protected " +
			"against later alteration, attributable to the humans, agents and models involved, and kept for at least six months.",
		MinRetentionDays: 183,
		RetentionClause:  "Art. 19(1) / Art. 26(6)",
		Applicability:    "Timeline: after the Digital Omnibus amendment, Article 12 logging applies to Annex III high-risk systems from 2 December 2027 and to Annex I (product-embedded) systems from 2 August 2028. Confirm current dates for your system with counsel.",
		HighlightOutcome: []string{"denied", "error"},
		Clauses: []Clause{
			{"Art. 12(1)", "Automatic recording of events", "High-risk AI systems must technically allow the automatic recording of events (logs) over the lifetime of the system.",
				"Every agent tool call is recorded automatically by the MCP sidecar or SDK, with no manual step. Rows are gapless (seq) and hash-chained from genesis, so the log's completeness can be checked over the system's lifetime."},
			{"Art. 12(2)(a)", "Events relevant to identifying risk", "Logging must enable recording of events relevant to identifying situations that may result in the system presenting a risk (Art. 79(1)) or in a substantial modification.",
				"action, target_resource and outcome record what the agent did and whether it was allowed, denied or failed. model_id / model_version show when the model changed (a possible substantial modification)."},
			{"Art. 12(2)(b)", "Post-market monitoring", "Logging must facilitate the post-market monitoring referred to in Art. 72.",
				"Structured, exportable records (CSV / JSON bundle) with outcome statistics and per-event metadata (arguments digest, result digest, latency)."},
			{"Art. 12(2)(c)", "Monitoring of operation by deployers", "Logging must facilitate monitoring of the system's operation referred to in Art. 26(5).",
				"delegation_chain reconstructs who asked which agent to do what, through which session and nested tool calls."},
			{"Art. 12(3)(a)", "Period of each use", "For Annex III point 1(a) systems: record the period of each use (start and end date and time).",
				"timestamp (UTC, ms) on every event, plus mcp.session/initialize records marking session start. latency_ms in metadata gives call duration."},
			{"Art. 12(3)(d)", "Natural persons involved", "For Annex III point 1(a) systems: identify the natural persons involved in verifying the results (Art. 14(5)).",
				"human_principal_id, with its provenance in metadata.identity_provenance. Declined elicitations are recorded as human 'denied' decisions."},
			{"Art. 19(1) / Art. 26(6)", "Log retention of at least six months", "Providers (19(1)) and deployers (26(6)) must keep automatically generated logs for a period appropriate to the intended purpose, of at least six months, unless other law provides otherwise.",
				"Tenant retention_days is enforced by the database to be at least 183 days. The only delete path refuses to purge while a legal hold is set, and deletes only whole, anchored checkpoint ranges."},
		},
		Fields: []FieldMapping{
			{"timestamp", "timestamp", []string{"Art. 12(1)", "Art. 12(3)(a)"}, "When the event occurred (UTC, millisecond precision)."},
			{"human_principal_id", "human_principal_id", []string{"Art. 12(3)(d)"}, "The natural person on whose behalf the agent acted; null means autonomous. See identity_provenance."},
			{"agent_id", "agent_id", []string{"Art. 12(2)(a)", "Art. 12(2)(c)"}, "Which AI agent or system performed the action."},
			{"model_id", "model_id", []string{"Art. 12(2)(a)"}, "Model identifier. A change can indicate a substantial modification. \"unknown\" means the host did not disclose it."},
			{"model_version", "model_version", []string{"Art. 12(2)(a)"}, "Model version, for traceability of behavior changes."},
			{"delegation_chain", "delegation_chain", []string{"Art. 12(2)(c)"}, "Ancestry of the action: human > agent > session > turn > parent call > this call."},
			{"action", "action", []string{"Art. 12(1)", "Art. 12(2)(a)"}, "What type of event occurred."},
			{"target_resource", "target_resource", []string{"Art. 12(2)(a)"}, "What the action acted on (tool, resource, prompt)."},
			{"outcome", "outcome", []string{"Art. 12(2)(a)", "Art. 12(2)(b)"}, "allowed / denied / error. Denials and errors are recorded, not just successes."},
			{"metadata", "metadata", []string{"Art. 12(2)(b)"}, "Argument and result digests, latency, protocol and session details."},
			{"seq", "seq", []string{"Art. 12(1)"}, "Gapless per-tenant sequence number, so missing rows can be detected."},
			{"previous_hash", "previous_hash", []string{"Art. 12(1)", "Art. 19(1) / Art. 26(6)"}, "Links each record to the previous one (SHA-256 hash chain)."},
			{"hash", "hash", []string{"Art. 12(1)", "Art. 19(1) / Art. 26(6)"}, "SHA-256 over previous_hash and the canonical record. Any edit changes it."},
			{"signature", "signature", []string{"Art. 12(1)"}, "Ed25519 signature by the tenant key over the hash."},
			{"checkpoint", "checkpoint_id / anchor", []string{"Art. 12(1)", "Art. 19(1) / Art. 26(6)"}, "Signed Merkle checkpoint covering the row, time-stamped by an independent RFC 3161 authority."},
			{"received_at", "received_at", []string{"Art. 12(1)", "Art. 12(3)(a)"}, "Server-assigned receipt time (trusted), alongside the client-reported occurred_at."},
			{"tree_head", "tree head + witness cosignatures", []string{"Art. 12(1)", "Art. 19(1) / Art. 26(6)"}, "C2SP checkpoint over the whole log, cosigned by independent witnesses: rewriting or forking history is detectable by anyone."},
			{"pii_ct", "pii (encrypted)", []string{"Art. 12(3)(d)"}, "Personal data encrypted per subject; can be crypto-shredded without breaking the log (GDPR Art. 17 interplay)."},
		},
	},
	{
		ID:     "soc2-cc7.2",
		Title:  "SOC 2: CC7.2 system monitoring for anomalies",
		Source: "AICPA Trust Services Criteria (2017, revised points of focus 2022)",
		Summary: "Shows that system components, including autonomous AI agents, are monitored; that anomalies (denied and failed actions) are captured " +
			"and attributable; and that the monitoring records are protected from undetected alteration.",
		MinRetentionDays: 365,
		RetentionClause:  "CC7.2 (entity-defined retention; 1 year typical for a Type II period)",
		HighlightOutcome: []string{"denied", "error"},
		Clauses: []Clause{
			{"CC7.2", "Monitoring for anomalies", "The entity monitors system components and their operation for anomalies indicative of malicious acts, natural disasters and errors affecting its objectives, and analyzes anomalies to determine whether they are security events.",
				"Every agent action is logged with its outcome. Denied (policy-blocked or human-declined) and error outcomes are the anomaly signals; the report lists them separately for analysis."},
			{"CC7.2 (PoF)", "Implements detection policies, procedures and tools", "Detection tools are implemented and monitored for effective operation.",
				"The MCP sidecar enforces allow/deny policy at the tool boundary and records every decision. The chain verifier confirms the monitoring data itself is complete and unaltered."},
			{"CC7.3", "Evaluates security events (supporting)", "Security events are evaluated to determine whether they could have caused a failure to meet objectives.",
				"The attribution fields (human, agent, model, delegation chain) and the argument/result digests give an evaluator the context of each anomaly."},
			{"CC6.1 (supporting)", "Logical access, attribution", "Logical access is restricted and attributable.",
				"human_principal_id and agent_id identify who acted, with the provenance of each identity recorded."},
		},
		Fields: []FieldMapping{
			{"timestamp", "timestamp", []string{"CC7.2"}, "When the monitored event occurred."},
			{"human_principal_id", "human_principal_id", []string{"CC6.1 (supporting)", "CC7.3"}, "The person accountable for the action."},
			{"agent_id", "agent_id", []string{"CC7.2", "CC6.1 (supporting)"}, "The monitored system component (AI agent / service)."},
			{"model_id", "model_id", []string{"CC7.3"}, "Model behind the agent, for anomaly analysis."},
			{"delegation_chain", "delegation_chain", []string{"CC7.3"}, "Context of the action, for evaluating a security event."},
			{"action", "action", []string{"CC7.2"}, "The monitored operation."},
			{"target_resource", "target_resource", []string{"CC7.2"}, "The system component acted on."},
			{"outcome", "outcome", []string{"CC7.2"}, "The anomaly signal: denied and error are highlighted."},
			{"metadata", "metadata", []string{"CC7.3"}, "Digests, errors and policy rules for analysis."},
			{"seq", "seq", []string{"CC7.2 (PoF)"}, "Completeness: gaps in the monitoring record are detectable."},
			{"hash", "hash / previous_hash", []string{"CC7.2 (PoF)"}, "Integrity of the monitoring records (hash chain)."},
			{"signature", "signature", []string{"CC7.2 (PoF)"}, "Authenticity of the monitoring records (Ed25519)."},
			{"checkpoint", "checkpoint_id / anchor", []string{"CC7.2 (PoF)"}, "Independent RFC 3161 time-stamp proving the records existed unaltered at the anchor time."},
		},
	},
	{
		ID:     "nist-800-53-au3",
		Title:  "NIST SP 800-53 Rev. 5: AU-3 content of audit records",
		Source: "NIST SP 800-53 Revision 5, Audit and Accountability (AU) family",
		Summary: "Shows that each audit record states what, when, where, source, outcome and identity (AU-3 a–f), with protection of " +
			"audit information (AU-9(3)), non-repudiation (AU-10) and retention (AU-11) as supporting controls.",
		MinRetentionDays: 183,
		RetentionClause:  "AU-11 (organization-defined retention)",
		HighlightOutcome: []string{"denied", "error"},
		Clauses: []Clause{
			{"AU-3(a)", "Type of event", "Audit records establish what type of event occurred.", "action (for example mcp.tools/call, invoice.refund)."},
			{"AU-3(b)", "Time of event", "Audit records establish when the event occurred.", "timestamp, UTC with millisecond precision (see also AU-8)."},
			{"AU-3(c)", "Location of event", "Audit records establish where the event occurred.", "target_resource (for example mcp://server/tools/name), plus server and session details in metadata."},
			{"AU-3(d)", "Source of event", "Audit records establish the source of the event.", "agent_id and delegation_chain (which agent, on whose request, through which session)."},
			{"AU-3(e)", "Outcome", "Audit records establish the outcome of the event.", "outcome: allowed, denied or error."},
			{"AU-3(f)", "Identities", "Audit records establish the identity of any individuals, subjects or objects/entities associated with the event.", "human_principal_id, agent_id, model_id / model_version and target_resource, with identity provenance."},
			{"AU-3(1)", "Additional audit information", "Organization-defined additional information.", "metadata: argument and result digests, latency, protocol version, policy rule."},
			{"AU-9(3)", "Cryptographic protection of audit information", "Cryptographic mechanisms protect the integrity of audit information.", "SHA-256 hash chain, Ed25519 signatures, signed Merkle checkpoints."},
			{"AU-10", "Non-repudiation", "Irrefutable evidence that an individual or process performed an action.", "Per-record Ed25519 signatures and RFC 3161 time-stamps from an independent authority."},
			{"AU-11", "Audit record retention", "Retain audit records for an organization-defined period.", "Tenant retention_days enforced in the database; legal hold blocks every purge."},
		},
		Fields: []FieldMapping{
			{"action", "action", []string{"AU-3(a)"}, "What type of event occurred."},
			{"timestamp", "timestamp", []string{"AU-3(b)"}, "When the event occurred."},
			{"target_resource", "target_resource", []string{"AU-3(c)", "AU-3(f)"}, "Where the event occurred / the object acted on."},
			{"agent_id", "agent_id", []string{"AU-3(d)", "AU-3(f)"}, "Source of the event."},
			{"delegation_chain", "delegation_chain", []string{"AU-3(d)"}, "Full source ancestry."},
			{"outcome", "outcome", []string{"AU-3(e)"}, "Outcome of the event."},
			{"human_principal_id", "human_principal_id", []string{"AU-3(f)"}, "Individual associated with the event."},
			{"model_id", "model_id / model_version", []string{"AU-3(f)"}, "The AI model as the acting subject."},
			{"metadata", "metadata", []string{"AU-3(1)"}, "Additional audit information."},
			{"hash", "hash / previous_hash / seq", []string{"AU-9(3)"}, "Cryptographic integrity and completeness."},
			{"signature", "signature / key_id", []string{"AU-9(3)", "AU-10"}, "Authenticity and non-repudiation."},
			{"checkpoint", "checkpoint_id / anchor", []string{"AU-9(3)", "AU-10"}, "Independent time-stamped proof of existence."},
		},
	},
}

func TemplateByID(id string) *Template {
	for i := range Templates {
		if Templates[i].ID == id {
			return &Templates[i]
		}
	}
	return nil
}

// ClausesFor returns the clause refs mapped to a field, or nil.
func (t Template) ClausesFor(field string) []string {
	for _, f := range t.Fields {
		if f.Field == field {
			return f.Clauses
		}
	}
	return nil
}

var _ = integrityFields
