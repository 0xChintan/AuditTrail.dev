import "server-only";
import { headers } from "next/headers";

/**
 * Server-side client for the AuditTrail ingestion API. The admin token never
 * leaves the server: browser code goes through /api/at/* (see route.ts).
 */
export const API_URL = (process.env.AUDITTRAIL_API_URL ?? "http://localhost:8080").replace(/\/+$/, "");
const ADMIN = process.env.AUDITTRAIL_ADMIN_TOKEN ?? "";

export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly code: string) {
    super(message);
  }
}

/** The signed-in operator (set by proxy.ts from a verified SSO session), if any. */
export async function operator(): Promise<string | null> {
  try {
    return (await headers()).get("x-at-operator");
  } catch {
    return null; // outside a request (build time)
  }
}

export async function api<T>(path: string, opts: { tenant?: string; method?: string; body?: unknown } = {}): Promise<T> {
  if (!ADMIN) throw new ApiError("AUDITTRAIL_ADMIN_TOKEN is not configured for the dashboard", 500, "config");
  const op = await operator();
  const res = await fetch(`${API_URL}${path}`, {
    method: opts.method ?? "GET",
    headers: {
      authorization: `Bearer ${ADMIN}`,
      "content-type": "application/json",
      ...(opts.tenant ? { "x-audittrail-tenant": opts.tenant } : {}),
      // Admin actions are sealed into the ledger under this person's name.
      ...(op ? { "x-audittrail-operator": op } : {}),
    },
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    cache: "no-store",
  }).catch((e: Error) => {
    throw new ApiError(`AuditTrail API unreachable at ${API_URL}: ${e.message}`, 503, "unreachable");
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    throw new ApiError(data?.error?.message ?? `HTTP ${res.status}`, res.status, data?.error?.code ?? "http_error");
  }
  return data as T;
}
