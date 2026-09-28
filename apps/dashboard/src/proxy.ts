import { NextResponse, type NextRequest } from "next/server";

/**
 * Every page gets a strict, per-request nonce-based CSP (v2 task 6.1, T12)
 * plus hardening headers. Log content is attacker-controlled (agents, tool
 * output), so even if an escaping bug slipped in, injected script could not
 * run.
 *
 * Optional password gate (DASHBOARD_PASSWORD, HTTP basic auth). /verify
 * stays public: verifying evidence must not require an account.
 */
export function proxy(req: NextRequest) {
  const path = req.nextUrl.pathname;
  const pw = process.env.DASHBOARD_PASSWORD;
  const publicPath = path.startsWith("/verify") || path.startsWith("/api/pubkeys") || path.startsWith("/verifier/");
  // Secure by default (ASVS V2/V4): a production dashboard with no password
  // configured refuses to serve admin pages unless explicitly opted out.
  const openAllowed = process.env.NODE_ENV !== "production" || process.env.DASHBOARD_ALLOW_NO_AUTH === "true";
  if (!publicPath && !pw && !openAllowed) {
    return new NextResponse("Dashboard authentication is not configured: set DASHBOARD_PASSWORD (or DASHBOARD_ALLOW_NO_AUTH=true for local use).", { status: 503 });
  }
  if (pw && !publicPath) {
    const auth = req.headers.get("authorization") ?? "";
    let ok = false;
    if (auth.startsWith("Basic ")) {
      let decoded = "";
      try {
        decoded = atob(auth.slice(6));
      } catch {
        decoded = "";
      }
      ok = constantTimeEqual(decoded.slice(decoded.indexOf(":") + 1), pw);
    }
    if (!ok) return new NextResponse("Authentication required", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="AuditTrail dashboard"' } });
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

  const requestHeaders = new Headers(req.headers);
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

function constantTimeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < Math.max(ea.length, eb.length); i++) diff |= (ea[i % (ea.length || 1)] ?? 0) ^ (eb[i % (eb.length || 1)] ?? 0);
  return diff === 0;
}
