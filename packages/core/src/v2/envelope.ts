// Envelope validation (SPEC §1). Check order mirrors contract/envelope.go.
import { ContractError, get, jcs, parseBytes, serr, type JValue } from "./json.js";
import { sha256Hex, utf8 } from "../crypto.js";

export const SPEC_VERSION = "2";
const ALLOWED = new Set(["spec_version", "event_id", "occurred_at", "agent", "principal", "model", "delegation", "action", "resource", "outcome", "payload", "payload_hash", "pii"]);
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ACTION = /^[A-Za-z0-9._:/-]+$/;
const HEX64 = /^[0-9a-f]{64}$/;
const TS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export interface Envelope {
  event_id: string;
  occurred_at: string;
  agent: JValue;
  principal: JValue | null;
  model: JValue | null;
  delegation: JValue;
  action: string;
  resource: string;
  outcome: "allowed" | "denied" | "error";
  payload: JValue | null;
  payload_hash: string;
  pii: { subject: string; fields: [string, string][] } | null;
  digest: string;
}

const isNull = (v: JValue | undefined) => !v || v.kind === "null";
const runes = (s: string) => [...s].length;

function wantString(v: JValue | undefined, path: string, min: number, max: number): string {
  if (!v || v.kind !== "string") throw serr("wrong_type", `${path} must be a string`);
  const n = runes(v.s);
  if (n < min || n > max) throw serr("invalid_value", `${path} length must be ${min}..${max}`);
  return v.s;
}

type Lim = [key: string, min: number, max: number];

function checkObject(v: JValue, path: string, required: Lim[], optional: Lim[], nullableOpt: boolean) {
  if (v.kind !== "object") throw serr("wrong_type", `${path} must be an object`);
  const known = new Set([...required, ...optional].map((l) => l[0]));
  for (const [k] of v.o) if (!known.has(k)) throw serr("unknown_field", `${path}.${k} is not allowed`);
  for (const [k, min, max] of required) {
    const f = get(v, k);
    if (!f) throw serr("missing_field", `${path}.${k} is required`);
    wantString(f, `${path}.${k}`, min, max);
  }
  for (const [k, min, max] of optional) {
    const f = get(v, k);
    if (!f || (nullableOpt && f.kind === "null")) continue;
    wantString(f, `${path}.${k}`, min, max);
  }
}

const daysIn = (y: number, m: number) => new Date(Date.UTC(y, m, 0)).getUTCDate();

/** RFC 3339 -> UTC millisecond string (truncating), or null. */
export function normalizeTime(s: string): string | null {
  const m = TS.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number) as number[];
  if (mo! < 1 || mo! > 12 || d! < 1 || d! > daysIn(y!, mo!) || h! > 23 || mi! > 59 || se! > 59) return null;
  const frac = (m[7] ?? ".").slice(1).slice(0, 3).padEnd(3, "0");
  let off = 0;
  if (m[8] !== "Z") {
    const oh = Number(m[8]!.slice(1, 3));
    const om = Number(m[8]!.slice(4, 6));
    if (oh > 23 || om > 59) return null;
    off = (m[8]![0] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const t = Date.UTC(y!, mo! - 1, d!, h!, mi!, se!, Number(frac)) - off * 60000;
  return new Date(t).toISOString();
}

export async function payloadHash(p: JValue | null | undefined): Promise<string> {
  return sha256Hex(utf8(jcs(p ?? null)));
}

export async function validateEnvelopeBytes(body: Uint8Array): Promise<Envelope> {
  return validateEnvelopeValue(parseBytes(body));
}

export async function validateEnvelopeValue(root: JValue): Promise<Envelope> {
  if (root.kind !== "object") throw serr("wrong_type", "envelope must be a JSON object");
  if (hasNUL(root)) throw serr("invalid_value", "strings and keys may not contain U+0000");
  for (const [k] of root.o) if (!ALLOWED.has(k)) throw serr("unknown_field", `${k} is not allowed`);
  const g = (k: string) => get(root, k);
  const sv = g("spec_version");
  if (!sv) throw serr("missing_field", "spec_version is required");
  if (sv.kind !== "string") throw serr("wrong_type", "spec_version must be a string");
  if (sv.s !== SPEC_VERSION) throw serr("unsupported_spec_version", `spec_version ${JSON.stringify(sv.s.slice(0, 40))} is not supported (want "2")`);
  for (const k of ["event_id", "occurred_at", "agent", "action", "resource", "outcome", "payload_hash"]) {
    if (!g(k)) throw serr("missing_field", `${k} is required`);
  }
  const event_id = wantString(g("event_id"), "event_id", 36, 36);
  if (!UUID_V7.test(event_id)) throw serr("invalid_value", "event_id must be a lowercase UUIDv7");
  const occurred_at = normalizeTime(wantString(g("occurred_at"), "occurred_at", 1, 64));
  if (!occurred_at) throw serr("invalid_value", "occurred_at must be RFC 3339");

  const agent = g("agent")!;
  checkObject(agent, "agent", [["id", 1, 256]], [["version", 0, 128]], false);
  let principal: JValue | null = null;
  const pv = g("principal");
  if (!isNull(pv)) {
    checkObject(pv!, "principal", [["id", 1, 512], ["type", 1, 16]], [], false);
    const t = (get(pv, "type") as { s: string }).s;
    if (t !== "human" && t !== "service") throw serr("invalid_value", "principal.type must be human or service");
    principal = pv!;
  }
  let model: JValue | null = null;
  const mv = g("model");
  if (!isNull(mv)) {
    checkObject(mv!, "model", [["id", 1, 256]], [["version", 0, 128], ["provider", 0, 128]], true);
    model = mv!;
  }
  let delegation: JValue = { kind: "array", a: [] };
  const dv = g("delegation");
  if (!isNull(dv)) {
    if (dv!.kind !== "array") throw serr("wrong_type", "delegation must be an array");
    if (dv!.a.length > 32) throw serr("invalid_value", "delegation may have at most 32 frames");
    dv!.a.forEach((f, i) => {
      const path = `delegation[${i}]`;
      if (f.kind !== "object") throw serr("wrong_type", `${path} must be an object`);
      for (const [name, max] of [["type", 64], ["id", 512]] as const) {
        const fv = get(f, name);
        if (!fv) throw serr("missing_field", `${path}.${name} is required`);
        wantString(fv, `${path}.${name}`, 1, max);
      }
      for (const [k, x] of f.o) if (x.kind === "object" || x.kind === "array") throw serr("wrong_type", `${path}.${k} must be a scalar`);
    });
    delegation = dv!;
  }
  const action = wantString(g("action"), "action", 1, 256);
  if (!ACTION.test(action)) throw serr("invalid_value", "action may only contain [A-Za-z0-9._:/-]");
  const resource = wantString(g("resource"), "resource", 1, 2048);
  const outcome = wantString(g("outcome"), "outcome", 1, 16);
  if (outcome !== "allowed" && outcome !== "denied" && outcome !== "error") throw serr("invalid_value", "outcome must be allowed, denied or error");
  let payload: JValue | null = null;
  const pl = g("payload");
  if (!isNull(pl)) {
    if (pl!.kind !== "object") throw serr("wrong_type", "payload must be an object or null");
    payload = pl!;
  }
  const payload_hash = wantString(g("payload_hash"), "payload_hash", 64, 64);
  if (!HEX64.test(payload_hash)) throw serr("invalid_value", "payload_hash must be 64 lowercase hex characters");
  if ((await payloadHash(payload)) !== payload_hash) throw serr("payload_hash_mismatch", "payload_hash does not match SHA-256(JCS(payload))");
  let pii: Envelope["pii"] = null;
  const piv = g("pii");
  if (!isNull(piv)) {
    if (piv!.kind !== "object") throw serr("wrong_type", "pii must be an object or null");
    for (const [k] of piv!.o) if (k !== "subject" && k !== "fields") throw serr("unknown_field", `pii.${k} is not allowed`);
    const sub = get(piv, "subject");
    if (!sub) throw serr("missing_field", "pii.subject is required");
    const subject = wantString(sub, "pii.subject", 1, 256);
    const fields = get(piv, "fields");
    if (!fields) throw serr("missing_field", "pii.fields is required");
    if (fields.kind !== "object") throw serr("wrong_type", "pii.fields must be an object");
    if (fields.o.length === 0 || fields.o.length > 64) throw serr("invalid_value", "pii.fields must have 1..64 members");
    const fs: [string, string][] = fields.o.map(([k, x]) => [k, wantString(x, `pii.fields.${k}`, 0, 65536)]);
    pii = { subject, fields: fs };
  }
  const digest = await sha256Hex(utf8(jcs(root)));
  return { event_id, occurred_at, agent, principal, model, delegation, action, resource, outcome: outcome as Envelope["outcome"], payload, payload_hash, pii, digest };
}

export { ContractError };

function hasNUL(v: JValue): boolean {
  if (v.kind === "string") return v.s.includes("\u0000");
  if (v.kind === "array") return v.a.some(hasNUL);
  if (v.kind === "object") return v.o.some(([k, x]) => k.includes("\u0000") || hasNUL(x));
  return false;
}
