/**
 * Redaction runs on the client BEFORE payload_hash is computed, so secrets
 * and unwanted PII never leave the process, and what is hashed is exactly
 * what is stored (v2 task 2.3, threat T8).
 */

export interface SecretPattern {
  name: string;
  re: RegExp;
}

/** Well-known credential formats. Matches are replaced with [REDACTED:<name>]. */
export const DEFAULT_SECRET_PATTERNS: SecretPattern[] = [
  { name: "private_key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: "aws_access_key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "github_token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { name: "slack_token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,200}\b/g },
  { name: "anthropic_key", re: /\bsk-ant-[A-Za-z0-9_-]{20,200}\b/g },
  { name: "openai_key", re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,200}\b/g },
  { name: "stripe_key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,200}\b/g },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "audittrail_key", re: /\bat2?_[0-9a-f]{12}_[A-Za-z0-9_-]{20,}\b/g },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: "bearer", re: /\b[Bb]earer\s+[A-Za-z0-9._~+/-]{16,}=*/g },
  { name: "url_credentials", re: /(?<=:\/\/)[^\s:/@]{1,200}:[^\s@/]{1,200}(?=@)/g },
];

/** Object keys whose values are always secrets, whatever they contain. */
export const DEFAULT_SECRET_KEYS = /^(?:pass(?:word|phrase)?|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|authorization|auth|cookie|set-cookie|private[_-]?key|credentials?|session[_-]?(?:id|token))$/i;

export interface RedactionOptions {
  /** Extra patterns (added to the defaults unless replaceDefaults). */
  patterns?: SecretPattern[];
  replaceDefaults?: boolean;
  /** Keys whose values are always replaced. Default DEFAULT_SECRET_KEYS. */
  secretKeys?: RegExp;
  /** Payload keys that hold personal data: replaced with "[PII]" (send them via `pii` to have them encrypted instead). */
  piiKeys?: string[];
  /** Final custom hook. */
  custom?: (payload: Record<string, unknown>) => Record<string, unknown>;
}

export interface RedactionReport {
  redacted: number;
  kinds: Set<string>;
}

export function redactString(s: string, patterns: SecretPattern[], rep?: RedactionReport): string {
  let out = s;
  for (const p of patterns) {
    out = out.replace(p.re, () => {
      if (rep) {
        rep.redacted++;
        rep.kinds.add(p.name);
      }
      return `[REDACTED:${p.name}]`;
    });
  }
  return out;
}

export function redactValue(v: unknown, o: RedactionOptions, rep: RedactionReport, depth = 0): unknown {
  const patterns = o.replaceDefaults ? (o.patterns ?? []) : [...DEFAULT_SECRET_PATTERNS, ...(o.patterns ?? [])];
  const secretKeys = o.secretKeys ?? DEFAULT_SECRET_KEYS;
  const pii = new Set((o.piiKeys ?? []).map((k) => k.toLowerCase()));
  const walk = (x: unknown, d: number): unknown => {
    if (d > 16) return "[TRUNCATED:depth]";
    if (typeof x === "string") return redactString(x, patterns, rep);
    if (Array.isArray(x)) return x.map((e) => walk(e, d + 1));
    if (x && typeof x === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(x as Record<string, unknown>)) {
        if (val === undefined) continue;
        if (secretKeys.test(k) && val !== null && val !== "") {
          rep.redacted++;
          rep.kinds.add("secret_key:" + k.toLowerCase());
          out[k] = "[REDACTED]";
        } else if (pii.has(k.toLowerCase()) && val !== null) {
          rep.redacted++;
          rep.kinds.add("pii:" + k.toLowerCase());
          out[k] = "[PII]";
        } else out[k] = walk(val, d + 1);
      }
      return out;
    }
    return x;
  };
  return walk(v, depth);
}
