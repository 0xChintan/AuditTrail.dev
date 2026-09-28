// v2 record hash (SPEC §3), request signatures (§7), Merkle proofs (§5)
// and C2SP notes (§6).
import { concat, fromBase64, fromHex, sha256, toBase64, toHex, utf8 } from "../crypto.js";
import { jcs, type JValue } from "./json.js";

export const GENESIS = "0".repeat(64);
const RECORD_DOMAIN = utf8("AuditTrail/v2/record\0");

type F = Uint8Array | null;

function lp(parts: F[]): Uint8Array {
  const chunks: Uint8Array[] = [RECORD_DOMAIN];
  for (const p of parts) {
    const len = new Uint8Array(4);
    if (p === null) {
      len.fill(0xff);
      chunks.push(len);
    } else {
      new DataView(len.buffer).setUint32(0, p.length);
      chunks.push(len, p);
    }
  }
  return concat(...chunks);
}

export interface V2Record {
  tenant_id: string;
  seq: number;
  event_id: string;
  occurred_at: string;
  received_at: string;
  agent: JValue;
  principal: JValue | null;
  model: JValue | null;
  delegation: JValue;
  action: string;
  resource: string;
  outcome: string;
  payload_hash: string;
  pii_ct: JValue | null;
  prev_hash: string;
}

const j = (v: JValue | null) => (v === null || v.kind === "null" ? null : utf8(jcs(v)));

export function recordHashInput(r: V2Record): Uint8Array {
  return lp([utf8("2"), utf8(r.tenant_id), utf8(String(r.seq)), utf8(r.event_id), utf8(r.occurred_at), utf8(r.received_at),
    j(r.agent), j(r.principal), j(r.model), utf8(jcs(r.delegation)), utf8(r.action), utf8(r.resource), utf8(r.outcome),
    utf8(r.payload_hash), j(r.pii_ct), utf8(r.prev_hash)]);
}

export async function recordHash(r: V2Record): Promise<string> {
  return toHex(await sha256(recordHashInput(r)));
}

export const receiptMessage = (hash: string) => utf8("AuditTrail/v2/receipt\n" + hash);

// ---- request signing (§7) -------------------------------------------------------

function subtle(): SubtleCrypto {
  return (globalThis as { crypto: Crypto }).crypto.subtle;
}

const PKCS8_ED25519_PREFIX = fromHex("302e020100300506032b657004220420");

export async function signingKeyFromApiKey(apiKey: string): Promise<{ privateKey: CryptoKey; publicKeyB64: string }> {
  const ikm = await subtle().importKey("raw", utf8(apiKey) as BufferSource, "HKDF", false, ["deriveBits"]);
  const seed = new Uint8Array(await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8("AuditTrail/v2") as BufferSource, info: utf8("request-signing") as BufferSource }, ikm, 256));
  const privateKey = await subtle().importKey("pkcs8", concat(PKCS8_ED25519_PREFIX, seed) as BufferSource, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await subtle().exportKey("jwk", privateKey);
  const x = jwk.x!.replace(/-/g, "+").replace(/_/g, "/");
  return { privateKey, publicKeyB64: toBase64(fromBase64(x + "=".repeat((4 - (x.length % 4)) % 4))) };
}

export async function requestMessage(method: string, path: string, timestamp: string, nonce: string, body: Uint8Array): Promise<string> {
  return `AuditTrail/v2/request\n${method}\n${path}\n${timestamp}\n${nonce}\n${toHex(await sha256(body))}`;
}

export async function signRequest(apiKey: string, method: string, path: string, timestamp: string, nonce: string, body: Uint8Array): Promise<string> {
  const { privateKey } = await signingKeyFromApiKey(apiKey);
  const msg = await requestMessage(method, path, timestamp, nonce, body);
  return toBase64(new Uint8Array(await subtle().sign({ name: "Ed25519" }, privateKey, utf8(msg) as BufferSource)));
}

// ---- Merkle (RFC 9162) ----------------------------------------------------------

const leafHash = (h: Uint8Array) => sha256(concat(new Uint8Array([0]), h));
const nodeHash = (l: Uint8Array, r: Uint8Array) => sha256(concat(new Uint8Array([1]), l, r));
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

function split(n: number) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export async function merkleRootRaw(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256(new Uint8Array());
  if (leaves.length === 1) return leafHash(leaves[0]!);
  const k = split(leaves.length);
  return nodeHash(await merkleRootRaw(leaves.slice(0, k)), await merkleRootRaw(leaves.slice(k)));
}

export async function verifyInclusionRaw(leaf: Uint8Array, index: number, size: number, proof: Uint8Array[], root: Uint8Array): Promise<boolean> {
  if (index < 0 || index >= size) return false;
  let fn = BigInt(index);
  let sn = BigInt(size - 1);
  let r = await leafHash(leaf);
  for (const p of proof) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = await nodeHash(p, r);
      while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else r = await nodeHash(r, p);
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && eq(r, root);
}

export async function verifyConsistency(first: number, second: number, firstRoot: Uint8Array, secondRoot: Uint8Array, proof: Uint8Array[]): Promise<boolean> {
  if (first > second) return false;
  if (first === second) return proof.length === 0 && eq(firstRoot, secondRoot);
  if (first === 0) return proof.length === 0;
  if (proof.length === 0) return false;
  let p = proof;
  let fn = BigInt(first);
  if ((fn & (fn - 1n)) === 0n) p = [firstRoot, ...proof];
  fn = BigInt(first - 1);
  let sn = BigInt(second - 1);
  while ((fn & 1n) === 1n) { fn >>= 1n; sn >>= 1n; }
  let fr = p[0]!;
  let sr = p[0]!;
  for (const c of p.slice(1)) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else sr = await nodeHash(sr, c);
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && eq(fr, firstRoot) && eq(sr, secondRoot);
}

// ---- C2SP notes -----------------------------------------------------------------

export interface NoteSig { name: string; keyId: number; raw: Uint8Array }
export interface Note { text: string; sigs: NoteSig[] }

export function parseNote(s: string): Note {
  const i = s.lastIndexOf("\n\n");
  if (i < 0) throw new Error("note has no signature block");
  const text = s.slice(0, i + 1);
  const block = s.slice(i + 2);
  if (!block.endsWith("\n")) throw new Error("signature block must end in newline");
  const sigs = block.slice(0, -1).split("\n").map((line) => {
    if (!line.startsWith("— ")) throw new Error("signature line must start with em dash");
    const [name, b64, extra] = line.slice(2).split(" ");
    if (!name || !b64 || extra !== undefined) throw new Error("malformed signature line");
    const raw = fromBase64(b64);
    if (raw.length < 5) throw new Error("malformed signature");
    return { name, keyId: new DataView(raw.buffer, raw.byteOffset).getUint32(0), raw: raw.slice(4) };
  });
  return { text, sigs };
}

export async function keyId(name: string, type: number, pub: Uint8Array): Promise<number> {
  const h = await sha256(concat(utf8(name), new Uint8Array([0x0a, type]), pub));
  return new DataView(h.buffer).getUint32(0);
}

export function parseVkey(v: string): { name: string; type: number; pub: Uint8Array; id: number } {
  const [name, idHex, b64] = [v.slice(0, v.indexOf("+")), v.slice(v.indexOf("+") + 1, v.indexOf("+", v.indexOf("+") + 1)), v.slice(v.indexOf("+", v.indexOf("+") + 1) + 1)];
  const raw = fromBase64(b64);
  if (!name || raw.length !== 33) throw new Error("malformed vkey");
  return { name, type: raw[0]!, pub: raw.slice(1), id: parseInt(idHex, 16) };
}

async function edVerify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  try {
    const k = await subtle().importKey("raw", pub as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    return await subtle().verify({ name: "Ed25519" }, k, sig as BufferSource, msg as BufferSource);
  } catch {
    return false;
  }
}

/** true if a valid log (0x01) signature from the vkey is present; throws on a matching-but-bad signature. */
export async function verifyLogSignature(note: Note, vkey: string): Promise<boolean> {
  const k = parseVkey(vkey);
  const id = await keyId(k.name, 0x01, k.pub);
  let ok = false;
  for (const s of note.sigs) {
    if (s.name !== k.name || s.keyId !== id) continue;
    if (!(await edVerify(k.pub, utf8(note.text), s.raw))) throw new Error("log signature does not verify");
    ok = true;
  }
  return ok;
}

/** Returns the cosignature time (unix seconds) or null if absent; throws if present but invalid. */
export async function verifyCosignature(note: Note, witnessVkey: string): Promise<number | null> {
  const k = parseVkey(witnessVkey);
  const id = await keyId(k.name, 0x04, k.pub);
  for (const s of note.sigs) {
    if (s.name !== k.name || s.keyId !== id) continue;
    if (s.raw.length !== 72) throw new Error("malformed cosignature");
    const t = new DataView(s.raw.buffer, s.raw.byteOffset).getBigUint64(0);
    const msg = utf8(`cosignature/v1\ntime ${t}\n${note.text}`);
    if (!(await edVerify(k.pub, msg, s.raw.slice(8)))) throw new Error(`cosignature from ${k.name} does not verify`);
    return Number(t);
  }
  return null;
}
