import type { NextRequest } from "next/server";
import * as oidc from "openid-client";
import { authConfig, cookie, authorize, oidcClient, readTx, sealSession, secureCookies, sessionCookieName, txCookieName } from "@/lib/auth";

/** Completes OIDC sign-in: verifies the code exchange and ID token, then applies the allowlist. */
export async function GET(req: NextRequest) {
  const c = authConfig();
  if (!c) return new Response("SSO is not configured", { status: 404 });
  const tx = await readTx(c, req.cookies.get(txCookieName(c))?.value);
  if (!tx) return denied("sign-in expired or was started elsewhere; try again");
  // The public URL the IdP redirected to (the server may sit behind a proxy).
  const current = new URL(`/auth/callback${req.nextUrl.search}`, c.baseUrl);
  let claims: oidc.IDToken | undefined;
  try {
    const client = await oidcClient(c);
    const tokens = await oidc.authorizationCodeGrant(client, current, {
      pkceCodeVerifier: tx.verifier,
      expectedState: tx.state,
      expectedNonce: tx.nonce,
      idTokenExpected: true,
    });
    claims = tokens.claims();
    // Some IdPs put email only in UserInfo; fetchUserInfo checks its subject matches the ID token.
    if (claims && typeof claims.email !== "string" && tokens.access_token) {
      const info = await oidc.fetchUserInfo(client, tokens.access_token, claims.sub);
      claims = { ...claims, email: info.email, email_verified: info.email_verified, name: info.name ?? claims.name };
    }
  } catch (e) {
    console.warn("oidc callback rejected:", (e as Error).message);
    return denied("sign-in could not be verified");
  }
  if (!claims) return denied("sign-in could not be verified");
  const verdict = authorize(c, claims);
  if (!verdict.ok) {
    console.warn("oidc sign-in refused:", verdict.reason, typeof claims.email === "string" ? claims.email : claims.sub);
    return denied(verdict.reason === "mfa_required" ? "multi-factor authentication is required" : "this account is not allowed to use this dashboard");
  }
  const headers = new Headers({ Location: new URL(tx.next, c.baseUrl).href, "Cache-Control": "no-store" });
  headers.append("Set-Cookie", cookie(sessionCookieName(c), await sealSession(c, verdict.session), c.maxAgeSeconds, secureCookies(c)));
  headers.append("Set-Cookie", cookie(txCookieName(c), "", 0, secureCookies(c)));
  return new Response(null, { status: 302, headers });
}

function denied(message: string) {
  return new Response(`Sign-in failed: ${message}.\n`, { status: 403, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
}
