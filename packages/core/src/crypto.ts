const enc = new TextEncoder();

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error("WebCrypto (crypto.subtle) is not available in this environment");
  return c.subtle;
}

export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error("invalid hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function fromBase64(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toBase64(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", data as BufferSource));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  return toHex(await sha256(typeof data === "string" ? utf8(data) : data));
}

const keyCache = new Map<string, Promise<CryptoKey>>();

/** Verify an Ed25519 signature (base64 key + signature) with WebCrypto. */
export async function ed25519Verify(publicKeyB64: string, message: Uint8Array, signatureB64: string): Promise<boolean> {
  try {
    let kp = keyCache.get(publicKeyB64);
    if (!kp) {
      kp = subtle().importKey("raw", fromBase64(publicKeyB64) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
      keyCache.set(publicKeyB64, kp);
    }
    return await subtle().verify({ name: "Ed25519" }, await kp, fromBase64(signatureB64) as BufferSource, message as BufferSource);
  } catch {
    return false;
  }
}
