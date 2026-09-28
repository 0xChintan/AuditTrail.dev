import type { AuditTrail } from "./client.js";
import { outcomeFromStatus } from "./express.js";

export interface NextAuditOptions {
  action: string | ((req: Request) => string);
  resource?: (req: Request) => string;
  principal?: (req: Request) => string | null | undefined | Promise<string | null | undefined>;
  metadata?: (req: Request, res: Response) => Record<string, unknown> | undefined;
}

type Handler<C> = (req: Request, ctx: C) => Response | Promise<Response>;

/**
 * Wrap a Next.js App Router route handler. Records the event after the
 * handler returns (or throws — recorded as outcome "error").
 *
 *   export const DELETE = withAuditTrail(audit, { action: "invoice.delete" }, async (req) => { … });
 */
export function withAuditTrail<C = unknown>(client: AuditTrail, opts: NextAuditOptions, handler: Handler<C>): Handler<C> {
  return async (req, ctx) => {
    const timestamp = new Date();
    const started = Date.now();
    const principal = (await opts.principal?.(req)) ?? null;
    const action = typeof opts.action === "function" ? opts.action(req) : opts.action;
    const resource = opts.resource ? opts.resource(req) : new URL(req.url).pathname;
    try {
      const res = await handler(req, ctx);
      client.track({ timestamp, human_principal_id: principal, action, target_resource: resource, outcome: outcomeFromStatus(res.status),
        metadata: { status: res.status, duration_ms: Date.now() - started, ...(opts.metadata?.(req, res) ?? {}) } });
      return res;
    } catch (e) {
      client.track({ timestamp, human_principal_id: principal, action, target_resource: resource, outcome: "error",
        metadata: { error: String((e as Error)?.message ?? e), duration_ms: Date.now() - started } });
      throw e;
    }
  };
}
