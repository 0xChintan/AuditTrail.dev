import { canonicalize } from "./jcs.js";
import { concat, sha256Hex, utf8 } from "./crypto.js";
import type { SealedRecord } from "./types.js";

export const GENESIS = "0".repeat(64);
export const EVENT_SIG_PREFIX = "audittrail.event.v1\n";

const TS_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/i;

/**
 * Normalize to UTC millisecond precision, `YYYY-MM-DDTHH:MM:SS.sssZ`.
 * Extra fractional digits are truncated (never rounded), matching Go.
 */
export function normalizeTimestamp(t: string | Date): string {
  if (t instanceof Date) return t.toISOString();
  const m = TS_RE.exec(t.trim());
  if (!m) throw new Error(`timestamp must be RFC 3339: ${t}`);
  const frac = (m[2] ?? "").slice(0, 3).padEnd(3, "0");
  const d = new Date(`${m[1]}.${frac}${m[3]!.toUpperCase()}`);
  if (Number.isNaN(d.getTime())) throw new Error(`invalid timestamp: ${t}`);
  return d.toISOString();
}

/** The hashed subset of an event (SPEC §1). */
export interface CanonicalEventFields {
  id: string;
  tenant_id: string;
  timestamp: string | Date;
  human_principal_id?: string | null;
  agent_id: string;
  model_id?: string | null;
  model_version?: string | null;
  delegation_chain?: unknown[] | null;
  action: string;
  target_resource: string;
  outcome: string;
  metadata?: Record<string, unknown> | null;
}

export function canonicalPayload(e: CanonicalEventFields): string {
  return canonicalize({
    v: 1,
    id: e.id.toLowerCase(),
    tenant_id: e.tenant_id.toLowerCase(),
    timestamp: normalizeTimestamp(e.timestamp),
    human_principal_id: e.human_principal_id ?? null,
    agent_id: e.agent_id,
    model_id: e.model_id ?? null,
    model_version: e.model_version ?? null,
    delegation_chain: e.delegation_chain ?? null,
    action: e.action,
    target_resource: e.target_resource,
    outcome: e.outcome,
    metadata: e.metadata ?? null,
  });
}

/** hash = hex(SHA-256(ascii(previous_hash) || canonical_payload)) */
export async function chainHash(previousHash: string, payload: string): Promise<string> {
  return sha256Hex(concat(utf8(previousHash), utf8(payload)));
}

export async function computeEventHash(previousHash: string, e: CanonicalEventFields): Promise<string> {
  return chainHash(previousHash, canonicalPayload(e));
}

export function eventSigningMessage(hash: string): Uint8Array {
  return utf8(EVENT_SIG_PREFIX + hash);
}

/** Recompute a sealed record's hash from its own content. */
export async function recomputeRecordHash(r: SealedRecord): Promise<string> {
  return computeEventHash(r.previous_hash, r);
}
