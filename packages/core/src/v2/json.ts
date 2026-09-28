// Strict JSON parser + RFC 8785 serializer for the v2 contract
// (schemas/v2/SPEC.md §2). Mirrors packages/ingestion-go/internal/contract/json.go
// so both produce identical error codes for identical input.

export const MAX_BODY_BYTES = 262144;
export const MAX_DEPTH = 16;

export class ContractError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = "ContractError";
  }
}

const perr = (code: string, msg: string) => new ContractError(400, code, msg);
export const serr = (code: string, msg: string) => new ContractError(422, code, msg);

export type JValue =
  | { kind: "null" }
  | { kind: "bool"; b: boolean }
  | { kind: "number"; n: number; raw: string }
  | { kind: "string"; s: string }
  | { kind: "array"; a: JValue[] }
  | { kind: "object"; o: [string, JValue][] };

export function get(v: JValue | undefined, key: string): JValue | undefined {
  if (!v || v.kind !== "object") return undefined;
  for (const [k, x] of v.o) if (k === key) return x;
  return undefined;
}

const MAX_SAFE = 2n ** 53n;
const utf8 = new TextDecoder("utf-8", { fatal: true });

/** Parse raw bytes with every strict check of SPEC §2. */
export function parseBytes(body: Uint8Array): JValue {
  if (body.length > MAX_BODY_BYTES) throw new ContractError(413, "body_too_large", `body exceeds ${MAX_BODY_BYTES} bytes`);
  let text: string;
  try {
    text = utf8.decode(body);
  } catch {
    throw perr("invalid_utf8", "body is not valid UTF-8");
  }
  return parseText(text);
}

export function parseText(d: string): JValue {
  let i = 0;
  const ws = () => {
    while (i < d.length && (d[i] === " " || d[i] === "\t" || d[i] === "\n" || d[i] === "\r")) i++;
  };
  const syntax = (what: string) =>
    perr("invalid_json", i >= d.length ? `unexpected end of input (${what})` : `unexpected ${JSON.stringify(d[i])} at offset ${i} (${what})`);

  const hex4 = (): number => {
    if (i + 4 > d.length) return -1;
    const h = d.slice(i, i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) return -1;
    i += 4;
    return parseInt(h, 16);
  };

  const str = (): string => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= d.length) throw perr("invalid_json", "unterminated string");
      const c = d.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return out;
      }
      if (c < 0x20) throw perr("invalid_json", `unescaped control character in string at offset ${i}`);
      if (c === 0x5c) {
        i++;
        if (i >= d.length) throw perr("invalid_json", "unterminated escape");
        const e = d[i++]!;
        switch (e) {
          case '"': case "\\": case "/": out += e; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const r = hex4();
            if (r < 0) throw perr("invalid_json", "bad \\u escape");
            if (r >= 0xd800 && r <= 0xdbff) {
              if (d[i] === "\\" && d[i + 1] === "u") {
                i += 2;
                const lo = hex4();
                if (lo < 0) throw perr("invalid_json", "bad \\u escape");
                if (lo < 0xdc00 || lo > 0xdfff) throw perr("invalid_surrogate", "high surrogate not followed by a low surrogate");
                out += String.fromCharCode(r, lo);
              } else throw perr("invalid_surrogate", "unpaired high surrogate");
            } else if (r >= 0xdc00 && r <= 0xdfff) {
              throw perr("invalid_surrogate", "unpaired low surrogate");
            } else out += String.fromCharCode(r);
            break;
          }
          default:
            throw perr("invalid_json", `invalid escape \\${e}`);
        }
        continue;
      }
      out += d[i++];
    }
  };

  const num = (): JValue => {
    const start = i;
    if (d[i] === "-") i++;
    if (i >= d.length) throw syntax("number");
    if (d[i] === "0") i++;
    else if (d[i]! >= "1" && d[i]! <= "9") while (i < d.length && d[i]! >= "0" && d[i]! <= "9") i++;
    else throw syntax("number");
    let integer = true;
    if (d[i] === ".") {
      integer = false;
      i++;
      const n = i;
      while (i < d.length && d[i]! >= "0" && d[i]! <= "9") i++;
      if (i === n) throw syntax("fraction digits");
    }
    if (d[i] === "e" || d[i] === "E") {
      integer = false;
      i++;
      if (d[i] === "+" || d[i] === "-") i++;
      const n = i;
      while (i < d.length && d[i]! >= "0" && d[i]! <= "9") i++;
      if (i === n) throw syntax("exponent digits");
    }
    const raw = d.slice(start, i);
    if (integer) {
      let bi = BigInt(raw);
      if (bi < 0n) bi = -bi;
      if (bi > MAX_SAFE) throw perr("unsafe_integer", `integer ${raw.slice(0, 40)} exceeds 2^53; send it as a string`);
    }
    const n = Number(raw);
    if (!Number.isFinite(n)) throw perr("non_finite_number", `number ${raw.slice(0, 40)} is not a finite double`);
    if (Math.abs(n) > 2 ** 53) throw perr("unsafe_integer", `number ${raw.slice(0, 40)} exceeds 2^53 in magnitude; send it as a string`);
    return { kind: "number", n, raw };
  };

  const value = (depth: number): JValue => {
    if (i >= d.length) throw syntax("value");
    const c = d[i]!;
    if (c === "{") {
      if (depth > MAX_DEPTH) throw perr("depth_exceeded", `nesting deeper than ${MAX_DEPTH}`);
      i++;
      const o: [string, JValue][] = [];
      const seen = new Set<string>();
      ws();
      if (d[i] === "}") {
        i++;
        return { kind: "object", o };
      }
      for (;;) {
        ws();
        if (d[i] !== '"') throw syntax("object key");
        const k = str();
        if (seen.has(k)) throw perr("duplicate_key", `duplicate object key ${JSON.stringify(k.slice(0, 40))}`);
        seen.add(k);
        ws();
        if (d[i] !== ":") throw syntax("':'");
        i++;
        ws();
        o.push([k, value(depth + 1)]);
        ws();
        if (d[i] === ",") { i++; continue; }
        if (d[i] === "}") { i++; return { kind: "object", o }; }
        throw syntax("',' or '}'");
      }
    }
    if (c === "[") {
      if (depth > MAX_DEPTH) throw perr("depth_exceeded", `nesting deeper than ${MAX_DEPTH}`);
      i++;
      const a: JValue[] = [];
      ws();
      if (d[i] === "]") {
        i++;
        return { kind: "array", a };
      }
      for (;;) {
        ws();
        a.push(value(depth + 1));
        ws();
        if (d[i] === ",") { i++; continue; }
        if (d[i] === "]") { i++; return { kind: "array", a }; }
        throw syntax("',' or ']'");
      }
    }
    if (c === '"') return { kind: "string", s: str() };
    if (d.startsWith("true", i)) { i += 4; return { kind: "bool", b: true }; }
    if (d.startsWith("false", i)) { i += 5; return { kind: "bool", b: false }; }
    if (d.startsWith("null", i)) { i += 4; return { kind: "null" }; }
    if (c === "-" || (c >= "0" && c <= "9")) return num();
    throw syntax("value");
  };

  ws();
  const v = value(1);
  ws();
  if (i !== d.length) throw perr("invalid_json", `trailing data at offset ${i}`);
  return v;
}

/** RFC 8785 serialization of a parsed value (undefined = null). */
export function jcs(v: JValue | undefined | null): string {
  if (!v) return "null";
  switch (v.kind) {
    case "null": return "null";
    case "bool": return v.b ? "true" : "false";
    case "number": return JSON.stringify(v.n);
    case "string": return JSON.stringify(v.s);
    case "array": return "[" + v.a.map(jcs).join(",") + "]";
    case "object": {
      const ms = [...v.o].sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
      return "{" + ms.map(([k, x]) => JSON.stringify(k) + ":" + jcs(x)).join(",") + "}";
    }
  }
}

/** Convert a plain JS value (from the SDK) into a JValue, applying the same limits. */
export function fromJS(x: unknown, depth = 1): JValue {
  if (x === null || x === undefined) return { kind: "null" };
  if (typeof x === "boolean") return { kind: "bool", b: x };
  if (typeof x === "number") {
    if (!Number.isFinite(x)) throw perr("non_finite_number", `number ${x} is not finite`);
    if (Math.abs(x) > 2 ** 53) throw perr("unsafe_integer", `number ${x} exceeds 2^53 in magnitude; send it as a string`);
    return { kind: "number", n: x, raw: String(x) };
  }
  if (typeof x === "bigint") throw perr("unsafe_integer", "bigint values must be sent as strings");
  if (typeof x === "string") {
    if (!x.isWellFormed()) throw perr("invalid_surrogate", "string contains a lone surrogate");
    return { kind: "string", s: x };
  }
  if (depth > MAX_DEPTH) throw perr("depth_exceeded", `nesting deeper than ${MAX_DEPTH}`);
  if (Array.isArray(x)) return { kind: "array", a: x.map((e) => fromJS(e === undefined ? null : e, depth + 1)) };
  if (typeof x === "object") {
    const o: [string, JValue][] = [];
    for (const [k, v] of Object.entries(x as Record<string, unknown>)) if (v !== undefined) o.push([k, fromJS(v, depth + 1)]);
    return { kind: "object", o };
  }
  throw serr("wrong_type", `cannot encode ${typeof x}`);
}
