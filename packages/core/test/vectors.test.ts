import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  GENESIS, canonicalPayload, canonicalizeJSON, chainHash, ed25519Verify, eventSigningMessage,
  merkleRoot, normalizeTimestamp, utf8, verifyBundle, verifyInclusion, type SealedRecord,
} from "../src/index.js";

const v = JSON.parse(readFileSync(fileURLToPath(new URL("../../../schemas/test-vectors.json", import.meta.url)), "utf8"));

describe("cross-implementation test vectors (Go <-> TS)", () => {
  it("JCS", () => {
    for (const c of v.jcs) expect(canonicalizeJSON(c.input)).toBe(c.output);
  });
  it("canonical payload, chain hash and signatures", async () => {
    for (const e of v.events) {
      const p = canonicalPayload(e.input);
      expect(p).toBe(e.canonical_payload);
      expect(await chainHash(e.previous_hash, p)).toBe(e.hash);
      expect(await ed25519Verify(v.public_key_b64, eventSigningMessage(e.hash), e.signature)).toBe(true);
    }
    expect(v.events[0].previous_hash).toBe(GENESIS);
  });
  it("merkle root + inclusion proof + checkpoint signature", async () => {
    const hs = v.events.map((e: { hash: string }) => e.hash);
    expect(await merkleRoot(hs)).toBe(v.merkle_root);
    expect(await verifyInclusion(hs[v.inclusion_index], v.inclusion_index, hs.length, v.inclusion_path, v.merkle_root)).toBe(true);
    expect(await verifyInclusion(hs[0], v.inclusion_index, hs.length, v.inclusion_path, v.merkle_root)).toBe(false);
    expect(await ed25519Verify(v.public_key_b64, utf8(v.checkpoint.statement), v.checkpoint.signature)).toBe(true);
  });
  it("timestamps truncate (never round) to ms", () => {
    expect(normalizeTimestamp("2026-08-02T09:30:00.123999999Z")).toBe("2026-08-02T09:30:00.123Z");
    expect(normalizeTimestamp("2026-08-02T11:30:00+02:00")).toBe("2026-08-02T09:30:00.000Z");
  });
});

describe("bundle verification localizes tampering", () => {
  const tenant = v.events[0].input.tenant_id;
  const records: SealedRecord[] = v.events.map((e: any, i: number) => ({
    ...e.input, timestamp: normalizeTimestamp(e.input.timestamp), seq: i + 1, previous_hash: e.previous_hash,
    hash: e.hash, signature: e.signature, key_id: v.key_id, created_at: "2026-08-02T09:31:00Z",
  }));
  const st = JSON.parse(v.checkpoint.statement);
  const cp = { id: "cp1", tenant_id: tenant, first_seq: 1, last_seq: 3, row_count: 3, merkle_root: st.merkle_root, head_hash: st.head_hash,
    prev_checkpoint_head: GENESIS, statement: v.checkpoint.statement, signature: v.checkpoint.signature, key_id: v.key_id,
    external_anchor_proof: null, anchor_status: "pending" as const, anchor_authority: null, anchored_at: null, created_at: st.created_at };
  const bundle = (events: SealedRecord[]) => ({ format: "audittrail.bundle.v1" as const, generated_at: "", tenant: { id: tenant, name: "t" },
    public_keys: [{ key_id: v.key_id, algorithm: "ed25519", public_key: v.public_key_b64 }], events, checkpoints: [cp] });

  it("clean bundle verifies", async () => {
    const r = await verifyBundle(bundle(records));
    expect(r.ok).toBe(true);
    expect(r.signaturesVerified).toBe(3);
  });
  it("edited row is localized", async () => {
    const t = records.map((r) => ({ ...r }));
    t[1]!.outcome = "allowed";
    const r = await verifyBundle(bundle(t));
    expect(r.ok).toBe(false);
    expect(r.tamperedSeqs).toEqual([2]);
  });
});
