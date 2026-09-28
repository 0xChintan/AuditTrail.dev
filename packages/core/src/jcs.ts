/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * ECMAScript's own JSON.stringify already serializes numbers and strings the
 * way JCS requires (JCS was defined in terms of it); what remains is sorting
 * object keys by UTF-16 code units — which is JS's default string ordering.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError(`JCS: non-finite number ${value}`);
      return JSON.stringify(value); // -0 -> "0", 1e21 -> "1e+21"
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return "[" + value.map((v) => canonicalize(v === undefined ? null : v)).join(",") + "]";
      if (typeof (value as { toJSON?: unknown }).toJSON === "function") {
        return canonicalize((value as { toJSON: () => unknown }).toJSON());
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
    }
    default:
      throw new TypeError(`JCS: cannot canonicalize ${typeof value}`);
  }
}

/** Canonicalize JSON text. */
export function canonicalizeJSON(text: string): string {
  return canonicalize(JSON.parse(text));
}
