import "server-only";
import * as oidc from "openid-client";
import { EncryptJWT, jwtDecrypt } from "jose";
import { createHash } from "node:crypto";

/**
 * Operator sign-in for the dashboard: OpenID Connect (authorization code +
 * PKCE, confidential client) with an encrypted, HttpOnly session cookie.
 * Enabled by OIDC_ISSUER; otherwise the dashboard falls back to
 * DASHBOARD_PASSWORD (see proxy.ts).
 *
 *   OIDC_ISSUER            https://accounts.google.com, https://login.microsoftonline.com/<tenant>/v2.0, …
 *   OIDC_CLIENT_ID / OIDC_CLIENT_SECRET
 *   DASHBOARD_URL          public origin, e.g. https://app.example.com (redirect URI = DASHBOARD_URL/auth/callback)
 *   SESSION_SECRET         >= 32 random characters; encrypts session cookies
 *   OIDC_ALLOWED_EMAILS    alice@example.com,bob@example.com   } at least one of these
 *   OIDC_ALLOWED_DOMAINS   example.com                         } is required
 *   OIDC_REQUIRE_MFA       true: the ID token's amr must show a second factor
 *   OIDC_TRUST_UNVERIFIED_EMAIL  true only for IdPs that never send email_verified
 *   SESSION_MAX_AGE_HOURS  default 8
 */

export type Session = { sub: string; email: string; name?: string };

export type AuthConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  baseUrl: URL;
  key: Uint8Array;
  emails: Set<string>;
  domains: Set<string>;
  requireMfa: boolean;
  trustUnverifiedEmail: boolean;
  maxAgeSeconds: number;
};

const list = (v: string | undefined) =>
  new Set((v ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean));

let cached: AuthConfig | null | undefined;

/** null when OIDC is not configured; throws when it is configured unsafely. */
export function authConfig(): AuthConfig | null {
  if (cached !== undefined) return cached;
  const issuer = process.env.OIDC_ISSUER?.trim();
  if (!issuer) return (cached = null);
  const need = (k: string) => {
    const v = process.env[k]?.trim();
    if (!v) throw new Error(`OIDC_ISSUER is set but ${k} is missing`);
    return v;
  };
  const secret = need("SESSION_SECRET");
  if (secret.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters");
  const emails = list(process.env.OIDC_ALLOWED_EMAILS);
  const domains = list(process.env.OIDC_ALLOWED_DOMAINS);
  // Fail closed: "anyone the IdP knows" is never a sensible default.
  if (emails.size === 0 && domains.size === 0) throw new Error("set OIDC_ALLOWED_EMAILS and/or OIDC_ALLOWED_DOMAINS");
  const baseUrl = new URL(need("DASHBOARD_URL"));
  const hours = Number(process.env.SESSION_MAX_AGE_HOURS ?? "8");
  cached = {
    issuer,
    clientId: need("OIDC_CLIENT_ID"),
    clientSecret: need("OIDC_CLIENT_SECRET"),
    baseUrl,
    key: createHash("sha256").update(`audittrail-dashboard-session\0${secret}`).digest(),
    emails,
    domains,
    requireMfa: process.env.OIDC_REQUIRE_MFA === "true",
    trustUnverifiedEmail: process.env.OIDC_TRUST_UNVERIFIED_EMAIL === "true",
    maxAgeSeconds: Math.round((Number.isFinite(hours) && hours > 0 ? hours : 8) * 3600),
  };
  return cached;
}

const loopback = (u: URL) => ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);

let discovered: Promise<oidc.Configuration> | null = null;
export function oidcClient(c: AuthConfig): Promise<oidc.Configuration> {
  discovered ??= oidc
    .discovery(new URL(c.issuer), c.clientId, c.clientSecret, undefined, {
      // Plain http is allowed only for an IdP on this machine (tests, local dev).
      execute: loopback(new URL(c.issuer)) ? [oidc.allowInsecureRequests] : [],
    })
    .catch((e) => {
      discovered = null; // retry discovery on the next request
      throw e;
    });
  return discovered;
}

export const secureCookies = (c: AuthConfig) => c.baseUrl.protocol === "https:";
// __Host- cookies: Secure, Path=/, no Domain: can't be set or overwritten by a sibling subdomain.
export const sessionCookieName = (c: AuthConfig) => (secureCookies(c) ? "__Host-at_session" : "at_session");
export const txCookieName = (c: AuthConfig) => (secureCookies(c) ? "__Host-at_oidc_tx" : "at_oidc_tx");

async function seal(c: AuthConfig, payload: Record<string, unknown>, ttlSeconds: number, purpose: string) {
  return new EncryptJWT({ ...payload, pur: purpose })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .encrypt(c.key);
}

async function unseal(c: AuthConfig, token: string | undefined, purpose: string) {
  if (!token) return null;
  try {
    const { payload } = await jwtDecrypt(token, c.key, { clockTolerance: 5 });
    return payload.pur === purpose ? payload : null;
  } catch {
    return null;
  }
}

export const sealSession = (c: AuthConfig, s: Session) => seal(c, s, c.maxAgeSeconds, "session");
export async function readSession(c: AuthConfig, token: string | undefined): Promise<Session | null> {
  const p = await unseal(c, token, "session");
  return p && typeof p.sub === "string" && typeof p.email === "string"
    ? { sub: p.sub, email: p.email, name: typeof p.name === "string" ? p.name : undefined }
    : null;
}

export type Tx = { state: string; nonce: string; verifier: string; next: string };
export const sealTx = (c: AuthConfig, t: Tx) => seal(c, t, 600, "oidc-tx");
export async function readTx(c: AuthConfig, token: string | undefined): Promise<Tx | null> {
  const p = await unseal(c, token, "oidc-tx");
  return p && typeof p.state === "string" && typeof p.nonce === "string" && typeof p.verifier === "string"
    ? { state: p.state, nonce: p.nonce, verifier: p.verifier, next: safeNext(String(p.next ?? "/")) }
    : null;
}

/** Only same-site relative paths: never "//evil.example" or "https://…". */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  return next;
}

const MFA_AMR = new Set(["mfa", "otp", "hwk", "swk", "sms", "fpt", "face", "iris", "retina", "vbm", "pin", "sc"]);

/** Decides whether a verified ID token's claims may use the dashboard. */
export function authorize(c: AuthConfig, claims: oidc.IDToken): { ok: true; session: Session } | { ok: false; reason: string } {
  const email = typeof claims.email === "string" ? claims.email.trim().toLowerCase() : "";
  if (!email) return { ok: false, reason: "no_email_claim" };
  if (claims.email_verified !== true && !c.trustUnverifiedEmail) return { ok: false, reason: "email_not_verified" };
  const domain = email.slice(email.lastIndexOf("@") + 1);
  if (!c.emails.has(email) && !c.domains.has(domain)) return { ok: false, reason: "not_in_allowlist" };
  if (c.requireMfa) {
    const amr = Array.isArray(claims.amr) ? claims.amr.map(String) : [];
    if (!amr.some((m) => MFA_AMR.has(m))) return { ok: false, reason: "mfa_required" };
  }
  const name = typeof claims.name === "string" ? claims.name : undefined;
  return { ok: true, session: { sub: String(claims.sub), email, name } };
}

/** Set-Cookie value. SameSite=Lax: sent on the IdP's top-level redirect back, never on cross-site POSTs. */
export function cookie(name: string, value: string, maxAge: number, secure: boolean) {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}
