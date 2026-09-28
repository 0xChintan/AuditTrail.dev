import { userInfo } from "node:os";

/**
 * Where an identity field came from. Recorded on every event so an auditor
 * can tell a verified identity from an inferred or missing one — the
 * proxy never silently omits a field, it says "unknown" and why.
 */
export type Provenance =
  | "request_meta" // params._meta on the individual MCP request
  | "session_meta" // _meta sent with the initialize request
  | "header" // HTTP header from the agent host (HTTP mode)
  | "flag" // proxy command-line flag
  | "env" // environment variable
  | "client_info" // MCP initialize clientInfo
  | "observed_sampling" // model reported in a sampling/createMessage result
  | "inferred:os_user" // OS account running the agent host
  | "unavailable";

export interface Resolved {
  value: string | null;
  source: Provenance;
}

export interface IdentityConfig {
  principal?: string;
  agentId?: string;
  model?: string;
  modelVersion?: string;
  /** Fall back to the OS user as human principal (labelled inferred). Default true. */
  osUserFallback?: boolean;
}

/** Keys the proxy reads from `_meta` (namespaced per MCP _meta conventions). */
export const META = {
  principal: "audittrail.dev/principal",
  agent: "audittrail.dev/agent",
  model: "audittrail.dev/model",
  modelVersion: "audittrail.dev/model_version",
  delegation: "audittrail.dev/delegation",
  parentCall: "audittrail.dev/parent_call",
} as const;

export function metaString(meta: unknown, key: string): string | undefined {
  if (meta && typeof meta === "object") {
    const v = (meta as Record<string, unknown>)[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
}

export function first(...candidates: [string | undefined | null, Provenance][]): Resolved {
  for (const [v, s] of candidates) {
    if (typeof v === "string" && v.trim()) return { value: v.trim(), source: s };
  }
  return { value: null, source: "unavailable" };
}

export function envModel(): string | undefined {
  return process.env.AUDITTRAIL_MODEL || process.env.ANTHROPIC_MODEL || process.env.CLAUDE_MODEL || process.env.OPENAI_MODEL || undefined;
}

export function osUser(): string | undefined {
  try {
    const u = userInfo().username;
    return u ? `os:${u}` : undefined;
  } catch {
    return undefined;
  }
}
