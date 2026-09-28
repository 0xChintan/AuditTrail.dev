import { API_URL } from "@/lib/api";

// Public: a tenant's signing public keys, for the verification portal.
export async function GET(_req: Request, ctx: RouteContext<"/api/pubkeys/[tenant]">) {
  const { tenant } = await ctx.params;
  if (!/^[0-9a-f-]{36}$/i.test(tenant)) return Response.json({ error: { message: "bad tenant id" } }, { status: 400 });
  const res = await fetch(`${API_URL}/v1/tenants/${tenant}/public-keys`, { cache: "no-store" }).catch(() => null);
  if (!res) return Response.json({ error: { message: "API unreachable" } }, { status: 503 });
  return new Response(res.body, { status: res.status, headers: { "content-type": "application/json" } });
}
