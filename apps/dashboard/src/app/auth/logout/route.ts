import * as oidc from "openid-client";
import { authConfig, cookie, oidcClient, secureCookies, sessionCookieName } from "@/lib/auth";

/** Signs out: POST only (with an Origin check in proxy.ts), then ends the IdP session if it supports that. */
export async function POST() {
  const c = authConfig();
  if (!c) return new Response(null, { status: 404 });
  let to = new URL("/auth/login", c.baseUrl).href;
  try {
    const client = await oidcClient(c);
    if (client.serverMetadata().end_session_endpoint) {
      to = oidc.buildEndSessionUrl(client, { client_id: c.clientId, post_logout_redirect_uri: c.baseUrl.origin + "/" }).href;
    }
  } catch {
    // IdP unreachable: the local session is still cleared.
  }
  const headers = new Headers({ Location: to, "Cache-Control": "no-store" });
  headers.append("Set-Cookie", cookie(sessionCookieName(c), "", 0, secureCookies(c)));
  return new Response(null, { status: 303, headers });
}
