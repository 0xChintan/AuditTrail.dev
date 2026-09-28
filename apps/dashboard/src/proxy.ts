import { NextResponse, type NextRequest } from "next/server";

/**
 * Optional password gate (DASHBOARD_PASSWORD, HTTP basic auth, any user).
 * The /verify portal stays public: verifying evidence must not require an
 * account with the party whose records are being checked.
 */
export function proxy(req: NextRequest) {
  const pw = process.env.DASHBOARD_PASSWORD;
  if (!pw) return NextResponse.next();
  const auth = req.headers.get("authorization") ?? "";
  if (auth.startsWith("Basic ")) {
    const decoded = atob(auth.slice(6));
    if (decoded.slice(decoded.indexOf(":") + 1) === pw) return NextResponse.next();
  }
  return new NextResponse("Authentication required", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="AuditTrail dashboard"' } });
}

export const config = {
  matcher: ["/((?!verify|api/pubkeys|_next/static|_next/image|favicon.ico).*)"],
};
