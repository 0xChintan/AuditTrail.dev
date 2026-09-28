export type { SealedRecord, Checkpoint, PublicKey, Bundle, Outcome } from "@audittrail/core";

export interface Tenant {
  id: string;
  name: string;
  retention_days: number;
  legal_hold: boolean;
  legal_hold_reason: string | null;
  legal_hold_set_at: string | null;
  rate_limit_rps: number;
  rate_limit_burst: number;
  created_at: string;
}

export interface ApiKey {
  id: string;
  tenant_id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface NameCount {
  name: string;
  count: number;
}

export interface Stats {
  total: number;
  by_outcome: Record<"allowed" | "denied" | "error", number>;
  last_24h: number;
  top_agents: NameCount[];
  top_actions: NameCount[];
  head_seq: number;
  head_hash: string;
  oldest_seq: number;
}

export interface ServerIssue {
  severity: "error" | "warning";
  kind: string;
  seq?: number;
  event_id?: string;
  checkpoint_id?: string;
  detail: string;
}

export interface ServerReport {
  ok: boolean;
  tenant_id: string;
  events_checked: number;
  signatures_verified: number;
  checkpoints_checked: number;
  first_seq: number;
  last_seq: number;
  head_hash: string;
  chain_start: string;
  anchors: { checkpoint_id: string; status: string; authority?: string; time?: string; chain_trust?: string }[];
  tampered_seqs: number[];
  issues: ServerIssue[];
}

export interface Template {
  id: string;
  title: string;
  source: string;
  summary: string;
  min_retention_days: number;
  retention_clause: string;
  clauses: { ref: string; title: string; requirement: string; evidence: string }[];
  fields: { field: string; label: string; clauses: string[]; rationale: string }[];
}
