/**
 * Optional allow/deny policy on tool names. Patterns are globs (`*`, `?`)
 * matched against the tool name, or `server/tool` to scope to a server.
 * Deny wins over allow; if any allow pattern is given, unmatched tools are
 * denied. Blocked calls never reach the MCP server and are recorded with
 * outcome "denied".
 */
export interface Policy {
  allow: string[];
  deny: string[];
}

function globToRegExp(g: string): RegExp {
  const esc = g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${esc}$`, "i");
}

export interface Decision {
  allowed: boolean;
  rule: string | null;
}

export function evaluate(policy: Policy, server: string, tool: string): Decision {
  const names = [tool, `${server}/${tool}`];
  for (const p of policy.deny) if (names.some((n) => globToRegExp(p).test(n))) return { allowed: false, rule: `deny:${p}` };
  if (policy.allow.length === 0) return { allowed: true, rule: null };
  for (const p of policy.allow) if (names.some((n) => globToRegExp(p).test(n))) return { allowed: true, rule: `allow:${p}` };
  return { allowed: false, rule: "not_in_allowlist" };
}
