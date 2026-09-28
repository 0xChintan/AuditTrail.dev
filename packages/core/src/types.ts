export type Outcome = "allowed" | "denied" | "error";

export interface DelegationFrame {
  type: string;
  id: string;
  [k: string]: unknown;
}

/** What a client submits (schemas/event.schema.json). */
export interface EventInput {
  id?: string;
  timestamp?: string | Date;
  human_principal_id?: string | null;
  agent_id: string;
  model_id?: string | null;
  model_version?: string | null;
  delegation_chain?: DelegationFrame[] | null;
  action: string;
  target_resource: string;
  outcome: Outcome;
  metadata?: Record<string, unknown> | null;
  previous_hash?: string;
  hash?: string;
}

/** A sealed ledger row as returned by the API. */
export interface SealedRecord {
  id: string;
  tenant_id: string;
  seq: number;
  timestamp: string;
  human_principal_id: string | null;
  agent_id: string;
  model_id: string | null;
  model_version: string | null;
  delegation_chain: DelegationFrame[] | null;
  action: string;
  target_resource: string;
  outcome: Outcome;
  metadata: Record<string, unknown> | null;
  previous_hash: string;
  hash: string;
  signature: string;
  key_id: string;
  created_at: string;
}

export interface Checkpoint {
  id: string;
  tenant_id: string;
  first_seq: number;
  last_seq: number;
  row_count: number;
  merkle_root: string;
  head_hash: string;
  prev_checkpoint_head: string;
  statement: string;
  signature: string;
  key_id: string;
  external_anchor_proof: string | null;
  anchor_status: "pending" | "anchored" | "failed" | "disabled";
  anchor_authority: string | null;
  anchored_at: string | null;
  created_at: string;
}

export interface PublicKey {
  key_id: string;
  algorithm: string;
  public_key: string;
  created_at?: string;
  retired_at?: string | null;
}

export interface Bundle {
  format: "audittrail.bundle.v1";
  generated_at: string;
  tenant: { id: string; name: string; retention_days?: number; legal_hold?: boolean };
  public_keys: PublicKey[];
  events: SealedRecord[];
  checkpoints: Checkpoint[];
  template?: unknown;
}
