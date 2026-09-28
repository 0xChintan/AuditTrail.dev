import type { NextRequest } from "next/server";
import { API_URL } from "@/lib/api";

/**
 * Browser -> dashboard server -> AuditTrail API. Injects the admin token and
 * the tenant header server-side. Only tenant-scoped read endpoints are
 * exposed here; mutations go through server actions.
 */
const ALLOWED = [/^v1\/events(\/[0-9a-f-]+(\/proof)?)?$/, /^v1\/checkpoints(\/[0-9a-f-]+)?$/, /^v1\/export$/, /^v1\/verify$/,
  /^v1\/stats$/, /^v1\/chain\/head$/, /^v2\/export$/, /^v2\/tree-heads$/, /^v2\/tenants\/[0-9a-f-]+\/log$/, /^v1\/templates$/, /^v1\/purges$/, /^v1\/tenants\/[0-9a-f-]+\/public-keys$/];

export async function GET(req: NextRequest, ctx: RouteContext<"/api/at/[...path]">) {
  const { path } = await ctx.params;
  const p = path.join("/");
  if (!ALLOWED.some((r) => r.test(p))) return Response.json({ error: { message: "not allowed" } }, { status: 404 });
  const tenant = req.nextUrl.searchParams.get("tenant") ?? "";
  const qs = new URLSearchParams(req.nextUrl.searchParams);
  qs.delete("tenant");
  const upstream = await fetch(`${API_URL}/${p}${qs.size ? `?${qs}` : ""}`, {
    headers: { authorization: `Bearer ${process.env.AUDITTRAIL_ADMIN_TOKEN ?? ""}`, ...(tenant ? { "x-audittrail-tenant": tenant } : {}) },
    cache: "no-store",
  }).catch(() => null);
  if (!upstream) return Response.json({ error: { message: `AuditTrail API unreachable at ${API_URL}` } }, { status: 503 });
  const headers = new Headers();
  for (const h of ["content-type", "content-disposition"]) {
    const v = upstream.headers.get(h);
    if (v) headers.set(h, v);
  }
  return new Response(upstream.body, { status: upstream.status, headers });
}
