import { concat, fromHex, sha256, toHex } from "./crypto.js";

// RFC 6962 Merkle tree over 32-byte chain hashes (SPEC §4).

const leafHash = (h: Uint8Array) => sha256(concat(new Uint8Array([0]), h));
const nodeHash = (l: Uint8Array, r: Uint8Array) => sha256(concat(new Uint8Array([1]), l, r));

function split(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

async function mth(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256(new Uint8Array());
  if (leaves.length === 1) return leafHash(leaves[0]!);
  const k = split(leaves.length);
  return nodeHash(await mth(leaves.slice(0, k)), await mth(leaves.slice(k)));
}

export async function merkleRoot(hashesHex: string[]): Promise<string> {
  return toHex(await mth(hashesHex.map(fromHex)));
}

/** RFC 9162 §2.1.3.2 inclusion proof verification. */
export async function verifyInclusion(leafHex: string, index: number, size: number, proof: string[], rootHex: string): Promise<boolean> {
  if (index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = await leafHash(fromHex(leafHex));
  for (const ph of proof) {
    if (sn === 0) return false;
    const p = fromHex(ph);
    if ((fn & 1) === 1 || fn === sn) {
      r = await nodeHash(p, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && toHex(r) === rootHex;
}
