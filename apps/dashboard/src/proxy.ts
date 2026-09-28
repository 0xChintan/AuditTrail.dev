import { NextResponse, type NextRequest } from "next/server";
import { authConfig, readSession, sessionCookieName, type AuthConfig } from "@/lib/auth";

/**
 * Every page gets a strict, per-request nonce-based CSP (v2 task 6.1, T12)
 * plus hardening headers. Log content is attacker-controlled (agents, tool
 * output), so even if an escaping bug slipped in, injected script could not
 * run.
 *
 * Operator sign-in: OIDC SSO when OIDC_ISSUER is set (lib/auth.ts), else
 * the DASHBOARD_PASSWORD basic-auth gate. /verify stays public: verifying
 * evidence must not require an account.
 */
export async function proxy(req: NextRequest) {
  const path = req.nextUrl.pathname;
  const publicPath = path.startsWith("/verify") || path.startsWith("/api/pubkeys") || path.startsWith("/verifier/") || path.startsWith("/auth/");
  let sso: AuthConfig | null;
  try {
    sso = authConfig();
  } catch (e) {
    return new NextResponse(`Dashboard SSO is misconfigured: ${(e as Error).message}`, { status: 503 });
  }
  const requestHeaders = new Headers(req.headers);
  // Set only below, after verifying the caller; never trusted from the client.
  requestHeaders.delete("x-at-operator");
  requestHeaders.delete("x-at-authed");

  // CSRF: state-changing requests must come from the dashboard's own origin.
  if (!["GET", "HEAD", "OPTIONS"].includes(req.method) && !sameOrigin(req, sso)) {
    return new NextResponse("Cross-origin request refused", { status: 403 });
  }

  if (sso) {
    const session = await readSession(sso, req.cookies.get(sessionCookieName(sso))?.value);
    if (session) {
      requestHeaders.set("x-at-operator", session.email);
      requestHeaders.set("x-at-authed", "1");
    } else if (!publicPath) {
      if (path.startsWith("/api/")) return NextResponse.json({ error: { message: "sign-in required" } }, { status: 401 });
      const login = new URL("/auth/login", sso.baseUrl);
      login.searchParams.set("next", path + req.nextUrl.search);
      return NextResponse.redirect(login, 302);
    }
  } else {
    const pw = process.env.DASHBOARD_PASSWORD;
    // Secure by default (ASVS V2/V4): a production dashboard with no sign-in
    // configured refuses to serve admin pages unless explicitly opted out.
    const openAllowed = process.env.NODE_ENV !== "production" || process.env.DASHBOARD_ALLOW_NO_AUTH === "true";
    if (!publicPath && !pw && !openAllowed) {
      return new NextResponse("Dashboard authentication is not configured: set OIDC_ISSUER (SSO) or DASHBOARD_PASSWORD (or DASHBOARD_ALLOW_NO_AUTH=true for local use).", { status: 503 });
    }
    let ok = !pw && openAllowed; // local development without a password
    if (pw) {
      const auth = req.headers.get("authorization") ?? "";
      if (auth.startsWith("Basic ")) {
        let decoded = "";
        try {
          decoded = atob(auth.slice(6));
        } catch {
          decoded = "";
        }
        ok = constantTimeEqual(decoded.slice(decoded.indexOf(":") + 1), pw);
      }
    }
    if (ok) requestHeaders.set("x-at-authed", "1");
    else if (!publicPath) return new NextResponse("Authentication required", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="AuditTrail dashboard"' } });
  }

  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const dev = process.env.NODE_ENV === "development";
  const csp = [
    "default-src 'self'",
    // 'wasm-unsafe-eval' lets the in-browser verifier (WebAssembly) run; no JS eval is allowed.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'${dev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    // Style *attributes* (widths, indentation) can't execute script.
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' blob: data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(dev ? [] : ["upgrade-insecure-requests"]),
  ].join("; ");

  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const res = NextResponse.next({ request: { headers: requestHeaders } });
  res.headers.set("Content-Security-Policy", csp);
  res.headers.set("X-Content-Type-Options", "nosniff");
  res.headers.set("X-Frame-Options", "DENY");
  res.headers.set("Referrer-Policy", "no-referrer");
  res.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.headers.set("Cross-Origin-Opener-Policy", "same-origin");
  return res;
}

export const config = {
  matcher: [{ source: "/((?!_next/static|_next/image|favicon.ico).*)", missing: [{ type: "header", key: "next-router-prefetch" }] }],
};

/** The Origin must be the dashboard's public origin (SSO) or match the Host it was served on. */
function sameOrigin(req: NextRequest, sso: AuthConfig | null): boolean {
  const origin = req.headers.get("origin");
  if (!origin || origin === "null") return false;
  if (sso) return origin === sso.baseUrl.origin;
  try {
    // Behind a TLS proxy the scheme differs internally; compare hosts, as Next.js does for server actions.
    const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < Math.max(ea.length, eb.length); i++) diff |= (ea[i % (ea.length || 1)] ?? 0) ^ (eb[i % (eb.length || 1)] ?? 0);
  return diff === 0;
}
