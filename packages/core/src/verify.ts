import { canonicalize } from "./jcs.js";
import { ed25519Verify, utf8 } from "./crypto.js";
import { GENESIS, eventSigningMessage, recomputeRecordHash } from "./event.js";
import { merkleRoot } from "./merkle.js";
import type { Bundle, Checkpoint, PublicKey, SealedRecord } from "./types.js";

export interface Issue {
  severity: "error" | "warning";
  kind: string;
  seq?: number;
  event_id?: string;
  checkpoint_id?: string;
  detail: string;
}

export interface RecordCheck {
  ok: boolean;
  hashMatches: boolean;
  recomputedHash: string;
  signatureValid: boolean | null; // null = no key available
  linkValid: boolean | null; // null = no previous record supplied
  issues: Issue[];
}

function keyMap(keys: PublicKey[]): Map<string, string> {
  return new Map(keys.map((k) => [k.key_id, k.public_key]));
}

/**
 * Verify one sealed record: recompute its hash from content, check its
 * Ed25519 signature, and (optionally) its link to the previous record.
 */
export async function verifyRecord(
  record: SealedRecord,
  publicKeys: PublicKey[],
  previous?: SealedRecord | null,
): Promise<RecordCheck> {
  const issues: Issue[] = [];
  const recomputedHash = await recomputeRecordHash(record);
  const hashMatches = recomputedHash === record.hash;
  if (!hashMatches) {
    issues.push({ severity: "error", kind: "content_tampered", seq: record.seq, event_id: record.id,
      detail: `content hashes to ${recomputedHash.slice(0, 12)}…, record claims ${record.hash.slice(0, 12)}…` });
  }
  const pk = keyMap(publicKeys).get(record.key_id);
  let signatureValid: boolean | null = null;
  if (pk) {
    signatureValid = await ed25519Verify(pk, eventSigningMessage(record.hash), record.signature);
    if (!signatureValid) issues.push({ severity: "error", kind: "bad_signature", seq: record.seq, event_id: record.id, detail: "Ed25519 signature does not verify" });
  } else {
    issues.push({ severity: "warning", kind: "unknown_key", seq: record.seq, event_id: record.id, detail: `no public key for ${record.key_id}` });
  }
  let linkValid: boolean | null = null;
  if (previous) {
    linkValid = record.previous_hash === previous.hash && record.seq === previous.seq + 1;
    if (!linkValid) issues.push({ severity: "error", kind: "link_broken", seq: record.seq, event_id: record.id,
      detail: `does not link to seq ${previous.seq}` });
  } else if (record.seq === 1) {
    linkValid = record.previous_hash === GENESIS;
    if (!linkValid) issues.push({ severity: "error", kind: "link_broken", seq: 1, event_id: record.id, detail: "first record does not link to genesis" });
  }
  return { ok: issues.every((i) => i.severity !== "error"), hashMatches, recomputedHash, signatureValid, linkValid, issues };
}

export interface BundleReport {
  ok: boolean;
  eventsChecked: number;
  signaturesVerified: number;
  checkpointsChecked: number;
  firstSeq: number;
  lastSeq: number;
  headHash: string;
  chainStart: string;
  tamperedSeqs: number[];
  anchors: { checkpoint_id: string; status: string; note: string }[];
  issues: Issue[];
}

export interface VerifyProgress {
  (done: number, total: number): void;
}

/**
 * Verify a full evidence bundle (same checks as the Go `audittrail-verify`
 * CLI, except RFC 3161 token validation, which needs CMS/X.509 parsing and
 * is left to the CLI; anchors are reported as "present, verify with CLI").
 */
export async function verifyBundle(b: Bundle, onProgress?: VerifyProgress): Promise<BundleReport> {
  const rep: BundleReport = { ok: true, eventsChecked: 0, signaturesVerified: 0, checkpointsChecked: 0, firstSeq: 0, lastSeq: 0,
    headHash: "", chainStart: "", tamperedSeqs: [], anchors: [], issues: [] };
  const add = (i: Issue) => {
    rep.issues.push(i);
    if (i.severity === "error") rep.ok = false;
  };
  const tampered = new Set<number>();
  if (b.format !== "audittrail.bundle.v1") {
    add({ severity: "error", kind: "bad_format", detail: `unsupported bundle format ${String(b.format)}` });
    return rep;
  }
  const pub = keyMap(b.public_keys);
  const evs = [...b.events].sort((x, y) => x.seq - y.seq);
  const bySeq = new Map(evs.map((e) => [e.seq, e]));
  const cps = [...b.checkpoints].sort((x, y) => x.first_seq - y.first_seq);
  const cpValid = new Map<string, boolean>();

  for (let i = 0; i < cps.length; i++) {
    const cp = cps[i]!;
    rep.checkpointsChecked++;
    const ok = await verifyCheckpointStatement(cp, b.tenant.id, pub, add);
    cpValid.set(cp.id, ok);
    const prevCp = cps[i - 1];
    if (prevCp && prevCp.last_seq + 1 === cp.first_seq && prevCp.head_hash !== cp.prev_checkpoint_head) {
      add({ severity: "error", kind: "checkpoint_chain_broken", checkpoint_id: cp.id, detail: "prev_checkpoint_head does not match previous checkpoint" });
    }
    rep.anchors.push({ checkpoint_id: cp.id, status: cp.anchor_status,
      note: cp.external_anchor_proof ? "RFC 3161 token present — verify its TSA signature with audittrail-verify" : "no external anchor yet" });
    const hashes: string[] = [];
    const missing: number[] = [];
    for (let s = cp.first_seq; s <= cp.last_seq; s++) {
      const e = bySeq.get(s);
      if (e) hashes.push(e.hash);
      else missing.push(s);
    }
    if (missing.length) {
      const lo = evs[0]?.seq ?? Infinity;
      const hi = evs[evs.length - 1]?.seq ?? -Infinity;
      if (lo <= cp.first_seq && hi >= cp.last_seq) {
        add({ severity: "error", kind: "checkpoint_rows_missing", seq: missing[0], checkpoint_id: cp.id,
          detail: `${missing.length} row(s) covered by signed checkpoint ${cp.first_seq}..${cp.last_seq} are missing: seq ${missing.slice(0, 20).join(", ")}` });
        missing.forEach((s) => tampered.add(s));
      }
      continue;
    }
    if ((await merkleRoot(hashes)) !== cp.merkle_root) {
      add({ severity: "error", kind: "checkpoint_root_mismatch", checkpoint_id: cp.id, seq: cp.first_seq,
        detail: `rows ${cp.first_seq}..${cp.last_seq} no longer match the signed Merkle root` });
    }
    const last = bySeq.get(cp.last_seq);
    if (last && last.hash !== cp.head_hash) {
      add({ severity: "error", kind: "checkpoint_head_mismatch", seq: cp.last_seq, checkpoint_id: cp.id, detail: "row hash differs from signed head_hash" });
    }
  }

  if (evs.length === 0) return rep;
  rep.firstSeq = evs[0]!.seq;
  rep.lastSeq = evs[evs.length - 1]!.seq;
  rep.headHash = evs[evs.length - 1]!.hash;
  let expectedPrev: string | null = null;
  if (rep.firstSeq === 1) {
    expectedPrev = GENESIS;
    rep.chainStart = "genesis";
  } else {
    const cp = cps.find((c) => c.last_seq === rep.firstSeq - 1 && cpValid.get(c.id));
    if (cp) {
      expectedPrev = cp.head_hash;
      rep.chainStart = `checkpoint:${cp.id}`;
    } else {
      rep.chainStart = "unanchored";
      add({ severity: "warning", kind: "chain_start_unanchored", seq: rep.firstSeq, detail: "first link cannot be checked" });
    }
  }

  let prev: SealedRecord | null = null;
  for (let i = 0; i < evs.length; i++) {
    const e = evs[i]!;
    rep.eventsChecked++;
    if (e.tenant_id !== b.tenant.id) {
      add({ severity: "error", kind: "wrong_tenant", seq: e.seq, event_id: e.id, detail: `row belongs to ${e.tenant_id}` });
      tampered.add(e.seq);
    }
    const h = await recomputeRecordHash(e);
    if (h !== e.hash) {
      add({ severity: "error", kind: "content_tampered", seq: e.seq, event_id: e.id, detail: `row ${e.seq} content does not hash to its stored hash` });
      tampered.add(e.seq);
    }
    if (prev) {
      if (e.seq !== prev.seq + 1) {
        add({ severity: "error", kind: "seq_gap", seq: prev.seq + 1, event_id: e.id, detail: `seq jumps from ${prev.seq} to ${e.seq}: rows ${prev.seq + 1}..${e.seq - 1} are missing` });
        for (let s = prev.seq + 1; s < e.seq; s++) tampered.add(s);
      } else if (e.previous_hash !== prev.hash) {
        add({ severity: "error", kind: "link_broken", seq: e.seq, event_id: e.id, detail: `previous_hash does not match row ${prev.seq}` });
        tampered.add(e.seq);
      }
    } else if (expectedPrev && e.previous_hash !== expectedPrev) {
      add({ severity: "error", kind: "link_broken", seq: e.seq, event_id: e.id, detail: `first row does not link to ${rep.chainStart}` });
      tampered.add(e.seq);
    }
    const pk = pub.get(e.key_id);
    if (!pk) add({ severity: "error", kind: "unknown_key", seq: e.seq, event_id: e.id, detail: `signing key ${e.key_id} not in bundle` });
    else if (await ed25519Verify(pk, eventSigningMessage(e.hash), e.signature)) rep.signaturesVerified++;
    else {
      add({ severity: "error", kind: "bad_signature", seq: e.seq, event_id: e.id, detail: "Ed25519 signature does not verify" });
      tampered.add(e.seq);
    }
    prev = e;
    if (onProgress && i % 200 === 0) onProgress(i, evs.length);
  }
  onProgress?.(evs.length, evs.length);
  rep.tamperedSeqs = [...tampered].sort((a, b) => a - b);
  return rep;
}

async function verifyCheckpointStatement(cp: Checkpoint, tenantId: string, pub: Map<string, string>, add: (i: Issue) => void): Promise<boolean> {
  let st: Record<string, unknown>;
  try {
    st = JSON.parse(cp.statement);
  } catch {
    add({ severity: "error", kind: "checkpoint_statement_invalid", checkpoint_id: cp.id, detail: "statement is not JSON" });
    return false;
  }
  if (canonicalize(st) !== cp.statement) {
    add({ severity: "error", kind: "checkpoint_statement_invalid", checkpoint_id: cp.id, detail: "statement not canonical" });
    return false;
  }
  let ok = true;
  const fields: [string, unknown][] = [["tenant_id", tenantId], ["first_seq", cp.first_seq], ["last_seq", cp.last_seq], ["row_count", cp.row_count],
    ["merkle_root", cp.merkle_root], ["head_hash", cp.head_hash], ["prev_checkpoint_head", cp.prev_checkpoint_head], ["type", "audittrail.checkpoint.v1"]];
  for (const [k, v] of fields) {
    if (st[k] !== v) {
      add({ severity: "error", kind: "checkpoint_field_mismatch", checkpoint_id: cp.id, detail: `${k} differs from signed statement` });
      ok = false;
    }
  }
  const pk = pub.get(cp.key_id);
  if (!pk || !(await ed25519Verify(pk, utf8(cp.statement), cp.signature))) {
    add({ severity: "error", kind: "checkpoint_bad_signature", checkpoint_id: cp.id, detail: "checkpoint signature does not verify" });
    return false;
  }
  return ok;
}
