import type { NextRequest } from "next/server";
import * as oidc from "openid-client";
import { authConfig, cookie, oidcClient, safeNext, sealTx, secureCookies, txCookieName } from "@/lib/auth";

/** Starts OIDC sign-in: PKCE + state + nonce, kept in a short-lived encrypted cookie. */
export async function GET(req: NextRequest) {
  const c = authConfig();
  if (!c) return new Response("SSO is not configured", { status: 404 });
  const client = await oidcClient(c);
  const verifier = oidc.randomPKCECodeVerifier();
  const tx = { state: oidc.randomState(), nonce: oidc.randomNonce(), verifier, next: safeNext(req.nextUrl.searchParams.get("next")) };
  const url = oidc.buildAuthorizationUrl(client, {
    redirect_uri: new URL("/auth/callback", c.baseUrl).href,
    scope: process.env.OIDC_SCOPES ?? "openid email profile",
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    state: tx.state,
    nonce: tx.nonce,
  });
  const headers = new Headers({ Location: url.href, "Cache-Control": "no-store" });
  headers.append("Set-Cookie", cookie(txCookieName(c), await sealTx(c, tx), 600, secureCookies(c)));
  return new Response(null, { status: 302, headers });
}
