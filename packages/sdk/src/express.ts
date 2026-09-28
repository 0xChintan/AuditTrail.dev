import type { AuditTrail } from "./client.js";
import type { Outcome } from "./client.js";

// Minimal structural types so the SDK doesn't depend on @types/express.
interface Req {
  method: string;
  originalUrl?: string;
  url: string;
  ip?: string;
  headers: Record<string, string | string[] | undefined>;
  [k: string]: unknown;
}
interface Res {
  statusCode: number;
  on(event: "finish", cb: () => void): unknown;
}

export interface ExpressAuditOptions {
  /** Who is acting. Default: req.user?.id as a human principal, else null */
  principal?: (req: Req) => string | null | undefined;
  /** Action name. Default: "http.<method>" e.g. "http.delete" */
  action?: (req: Req) => string;
  /** Resource. Default: path without query string */
  resource?: (req: Req) => string;
  /** Which requests to record. Default: mutating methods only (POST/PUT/PATCH/DELETE). */
  filter?: (req: Req) => boolean;
  /** Extra metadata. */
  metadata?: (req: Req, res: Res) => Record<string, unknown> | undefined;
}

export function outcomeFromStatus(status: number): Outcome {
  if (status === 401 || status === 403) return "denied";
  if (status >= 400) return "error";
  return "allowed";
}

/**
 * Express middleware: records one audit event per matching request, after
 * the response is sent (so the outcome reflects what actually happened —
 * denied requests are logged too, not just successes).
 */
export function auditTrailMiddleware(client: AuditTrail, opts: ExpressAuditOptions = {}) {
  const mutating = new Set(["POST", "PUT", "PATCH", "DELETE"]);
  return (req: Req, res: Res, next: () => void) => {
    if (!(opts.filter ? opts.filter(req) : mutating.has(req.method))) return next();
    const started = Date.now();
    const timestamp = new Date();
    res.on("finish", () => {
      const user = (req as { user?: { id?: string } }).user;
      const pid = opts.principal ? opts.principal(req) : user?.id;
      client.track({
        occurredAt: timestamp,
        principal: pid ? { id: pid, type: "human" } : null,
        action: opts.action ? opts.action(req) : `http.${req.method.toLowerCase()}`,
        resource: opts.resource ? opts.resource(req) : (req.originalUrl ?? req.url).split("?")[0]!,
        outcome: outcomeFromStatus(res.statusCode),
        payload: { status: res.statusCode, duration_ms: Date.now() - started, ip: req.ip ?? null, ...(opts.metadata?.(req, res) ?? {}) },
      });
    });
    next();
  };
}
