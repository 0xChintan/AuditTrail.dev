import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { fromBase64, fromHex, toBase64, sha256Hex, utf8 } from "../src/crypto.js";
import { v2 } from "../src/index.js";

const V = JSON.parse(readFileSync(fileURLToPath(new URL("../../../schemas/v2/vectors.json", import.meta.url)), "utf8"));
const enc = new TextEncoder();

function bodyOf(c: { body?: string; body_b64?: string; body_gen?: string }): Uint8Array {
  if (c.body_b64) return fromBase64(c.body_b64);
  if (c.body_gen?.startsWith("oversize:")) return enc.encode(`{"pad":"${"a".repeat(Number(c.body_gen.slice(9)))}"}`);
  return enc.encode(c.body ?? "");
}

describe(`v2 cross-language vectors (${V.counts.total} cases)`, () => {
  it(`JCS (${V.jcs.length})`, () => {
    for (const c of V.jcs) expect(v2.jcs(v2.parseText(c.input)), c.name).toBe(c.output);
  });

  it(`valid envelopes: normalization, payload hash, digest, record hash (${V.valid_envelopes.length})`, async () => {
    for (const c of V.valid_envelopes) {
      const e = await v2.validateEnvelopeBytes(enc.encode(c.body));
      expect(e.occurred_at, c.name).toBe(c.expect.occurred_at);
      expect(e.payload_hash, c.name).toBe(c.expect.payload_hash);
      expect(e.digest, c.name).toBe(c.expect.digest);
      expect(v2.jcs(e.payload), c.name).toBe(c.expect.payload_jcs);
      const r = c.record;
      const rec = { tenant_id: r.tenant_id, seq: r.seq, event_id: e.event_id, occurred_at: e.occurred_at, received_at: r.received_at,
        agent: e.agent, principal: e.principal, model: e.model, delegation: e.delegation, action: e.action, resource: e.resource,
        outcome: e.outcome, payload_hash: e.payload_hash, pii_ct: r.pii_ct ? v2.parseText(r.pii_ct) : null, prev_hash: r.prev_hash };
      expect(await sha256Hex(v2.recordHashInput(rec)), c.name).toBe(r.hash_input_sha256);
      expect(await v2.recordHash(rec), c.name).toBe(r.hash);
    }
  });

  it(`hostile / invalid envelopes give the same status + code (${V.invalid_envelopes.length})`, async () => {
    for (const c of V.invalid_envelopes) {
      let err: v2.ContractError | null = null;
      try {
        await v2.validateEnvelopeBytes(bodyOf(c));
      } catch (e) {
        err = e as v2.ContractError;
      }
      expect(err, c.name).toBeInstanceOf(v2.ContractError);
      expect([err!.status, err!.code], c.name).toEqual([c.status, c.code]);
    }
  });

  it(`Merkle roots, inclusion and consistency (${V.merkle.length})`, async () => {
    for (const c of V.merkle) {
      const ls = c.leaves.map(fromHex);
      const root = fromHex(c.root);
      const proof = (c.proof ?? []).map(fromHex);
      let ok: boolean;
      if (c.kind === "root") ok = Buffer.from(await v2.merkleRootRaw(ls)).toString("hex") === c.root;
      else if (c.kind === "inclusion") ok = await v2.verifyInclusionRaw(ls[c.index], c.index, ls.length, proof, root);
      else ok = await v2.verifyConsistency(c.old_size, ls.length, fromHex(c.old_root), root, proof);
      expect(ok, c.name).toBe(c.valid);
    }
  });

  it(`request signatures (${V.request_signatures.length})`, async () => {
    for (const c of V.request_signatures) {
      const body = enc.encode(c.body);
      expect(await v2.requestMessage(c.method, c.path, c.timestamp, c.nonce, body), c.name).toBe(c.message);
      const k = await v2.signingKeyFromApiKey(c.api_key);
      expect(k.publicKeyB64, c.name).toBe(c.public_key_b64);
      expect(await v2.signRequest(c.api_key, c.method, c.path, c.timestamp, c.nonce, body), c.name).toBe(c.signature_b64);
    }
  });

  it(`C2SP notes: log signatures + cosignatures (${V.notes.length})`, async () => {
    for (const c of V.notes) {
      const n = v2.parseNote(c.signed_note);
      expect(n.text, c.name).toBe(c.checkpoint_text);
      expect(await v2.verifyLogSignature(n, c.log_vkey), c.name).toBe(true);
      if (c.witness_vkey) expect(await v2.verifyCosignature(n, c.witness_vkey), c.name).toBe(c.cosig_time);
      const tampered = v2.parseNote(c.signed_note.replace(/\n(\d+)\n/, (_: string, d: string) => `\n${Number(d) + 1}\n`));
      await expect(v2.verifyLogSignature(tampered, c.log_vkey)).rejects.toThrow();
    }
  });
});

void toBase64; void utf8;
