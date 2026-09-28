// Dashboard SSO end to end against a real OpenID provider (panva's
// oidc-provider, certified): authorization code + PKCE, ID token checks,
// allowlist, email verification, MFA (amr), CSRF, open-redirect and cookie
// tampering. Runs the production dashboard build (standalone server).
//
//   NEXT_OUTPUT=standalone pnpm --filter @audittrail/dashboard build && node scripts/oidc-e2e.mjs
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { readFileSync, cpSync, existsSync } from "node:fs";
import http from "node:http";

const require = createRequire(new URL("../apps/dashboard/package.json", import.meta.url));
const { default: Provider } = await import(require.resolve("oidc-provider"));

const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
  .filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const OP_PORT = 4455, DASH_PORT = 3102;
const ISSUER = `http://127.0.0.1:${OP_PORT}`;
const DASH = `http://localhost:${DASH_PORT}`;
const CLIENT = { client_id: "audittrail-dashboard", client_secret: "e2e-client-secret-0123456789abcdef", redirect_uris: [`${DASH}/auth/callback`],
  post_logout_redirect_uris: [`${DASH}/`], grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "client_secret_basic" };

// ---- the identity provider -------------------------------------------------------------
const accounts = {
  alice: { email: "alice@example.com", email_verified: true, name: "Alice Operator" },
  mallory: { email: "mallory@evil.test", email_verified: true, name: "Mallory" },
  eve: { email: "eve@example.com", email_verified: false, name: "Eve (unverified)" },
};
let loginAs = { id: "alice", amr: ["pwd"] }; // set per scenario
const provider = new Provider(ISSUER, {
  clients: [CLIENT],
  pkce: { required: () => true },
  claims: { openid: ["sub", "amr"], email: ["email", "email_verified"], profile: ["name"] },
  features: { devInteractions: { enabled: false }, rpInitiatedLogout: { enabled: true } },
  findAccount: (_ctx, id) => accounts[id] && { accountId: id, claims: () => ({ sub: id, ...accounts[id] }) },
  interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
  cookies: { keys: ["e2e-cookie-key-0123456789"] },
});
provider.proxy = false;
const opServer = http.createServer(async (req, res) => {
  const m = req.url.match(/^\/interaction\/([^/?]+)/);
  if (!m) return provider.callback()(req, res);
  // Stands in for the IdP's login + consent screens: sign in the scenario's account.
  const details = await provider.interactionDetails(req, res);
  const grant = new provider.Grant({ accountId: loginAs.id, clientId: details.params.client_id });
  grant.addOIDCScope(details.params.scope);
  const grantId = await grant.save();
  await provider.interactionFinished(req, res, { login: { accountId: loginAs.id, amr: loginAs.amr }, consent: { grantId } }, { mergeWithLastSubmission: false });
});
await new Promise((r) => opServer.listen(OP_PORT, "127.0.0.1", r));

// ---- the dashboard (production build) ---------------------------------------------------
const standalone = new URL("../apps/dashboard/.next/standalone/apps/dashboard/", import.meta.url).pathname;
if (!existsSync(standalone + "server.js")) throw new Error("build the dashboard first");
let dash;
async function startDashboard(extra = {}) {
  if (dash) { dash.kill(); await new Promise((r) => dash.once("exit", r)); }
  dash = spawn(process.execPath, ["server.js"], {
    cwd: standalone,
    env: { PATH: process.env.PATH, NODE_ENV: "production", PORT: String(DASH_PORT), HOSTNAME: "127.0.0.1",
      AUDITTRAIL_API_URL: "http://localhost:8080", AUDITTRAIL_ADMIN_TOKEN: env.AUDITTRAIL_ADMIN_TOKEN,
      OIDC_ISSUER: ISSUER, OIDC_CLIENT_ID: CLIENT.client_id, OIDC_CLIENT_SECRET: CLIENT.client_secret,
      DASHBOARD_URL: DASH, SESSION_SECRET: "e2e-session-secret-please-change-0123456789", OIDC_ALLOWED_DOMAINS: "example.com", ...extra },
    stdio: ["ignore", "ignore", "pipe"],
  });
  dash.stderr.on("data", (d) => { if (process.env.E2E_DEBUG) process.stderr.write("[dash] " + d); });
  for (let i = 0; i < 60; i++) {
    try { await fetch(`${DASH}/verify`); return; } catch { await new Promise((r) => setTimeout(r, 200)); }
  }
  throw new Error("dashboard did not start");
}

// ---- a tiny browser: cookie jar per host, manual redirects -------------------------------
function browser() {
  const jar = new Map(); // host -> Map(name -> value)
  const cookiesFor = (u) => [...(jar.get(u.host) ?? new Map())].map(([k, v]) => `${k}=${v}`).join("; ");
  async function request(url, opts = {}) {
    const u = new URL(url);
    const res = await fetch(u, { ...opts, redirect: "manual", headers: { ...(opts.headers ?? {}), cookie: cookiesFor(u) } });
    for (const sc of res.headers.getSetCookie()) {
      const [pair, ...attrs] = sc.split(";");
      const name = pair.slice(0, pair.indexOf("=")).trim(), value = pair.slice(pair.indexOf("=") + 1).trim();
      const m = jar.get(u.host) ?? new Map();
      if (attrs.some((a) => /max-age=0\b/i.test(a.trim())) || value === "") m.delete(name); else m.set(name, value);
      jar.set(u.host, m);
    }
    return res;
  }
  async function follow(url, opts = {}, max = 15) {
    let res = await request(url, opts);
    const trail = [url];
    while ([301, 302, 303, 307, 308].includes(res.status) && max--) {
      url = new URL(res.headers.get("location"), url).href;
      trail.push(url);
      res = await request(url);
    }
    return { res, url, trail, body: await res.text() };
  }
  return { request, follow, jar };
}

let failed = 0;
const check = (ok, what) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failed++; };

try {
  await startDashboard();

  // 1. Allowed, verified operator signs in and lands where they started.
  loginAs = { id: "alice", amr: ["pwd"] };
  const b = browser();
  const start = await b.request(`${DASH}/verify?x=1`);
  check(start.status === 200, "public /verify needs no sign-in");
  const r1 = await b.follow(`${DASH}/`);
  check(r1.trail.some((u) => u.startsWith(`${ISSUER}/auth?`)) && r1.trail.some((u) => u.includes("code_challenge_method=S256")), "unauthenticated page redirects to the IdP with PKCE (S256)");
  check(r1.res.status === 200 && r1.url === `${DASH}/`, `alice signs in and lands on the dashboard (${r1.res.status} ${r1.url})`);
  check(r1.body.includes("alice@example.com") && r1.body.includes("Sign out"), "sidebar shows the operator and a sign-out button");
  const sess = b.jar.get(`localhost:${DASH_PORT}`)?.get("at_session");
  check(Boolean(sess) && sess.split(".").length === 5, "session is an encrypted JWE cookie");
  check(!b.jar.get(`localhost:${DASH_PORT}`)?.has("at_oidc_tx"), "one-time sign-in transaction cookie is cleared");
  const api1 = await b.request(`${DASH}/api/at/v1/templates`);
  check(api1.status === 200, "API proxy works with a session");

  // 1b. An admin action from the dashboard is sealed under the operator's name.
  const manifest = JSON.parse(readFileSync(new URL("../apps/dashboard/.next/server/server-reference-manifest.json", import.meta.url), "utf8"));
  const createId = Object.entries(manifest.node).find(([, v]) => v.exportedName === "createTenant")?.[0];
  const tname = `sso-operator-e2e-${Date.now()}`;
  const action = (origin) => b.request(`${DASH}/`, { method: "POST", headers: { "Next-Action": createId, origin, "content-type": "text/plain;charset=UTF-8", accept: "text/x-component" },
    body: JSON.stringify([{ name: tname, retention_days: 365 }]) });
  check((await action("https://evil.example")).status === 403, "server action from a foreign origin is refused");
  const act = await action(DASH);
  check(act.status === 200, `createTenant server action as alice (${act.status})`);
  const admin = { authorization: `Bearer ${env.AUDITTRAIL_ADMIN_TOKEN}` };
  const { tenants } = await (await fetch("http://localhost:8080/v1/admin/tenants", { headers: admin })).json();
  const created = tenants.find((t) => t.name === tname);
  const evs = created && (await (await fetch("http://localhost:8080/v1/events?action=tenant.created", { headers: { ...admin, "x-audittrail-tenant": created.id } })).json()).events;
  check(evs?.[0]?.human_principal_id === "alice@example.com" && evs[0].metadata?.operator_asserted_by === "admin-token",
    `tenant.created is sealed with principal ${evs?.[0]?.human_principal_id}`);

  // 2. No session / tampered session.
  const anon = browser();
  check((await anon.request(`${DASH}/api/at/v1/templates`)).status === 401, "API proxy without a session: 401");
  const forged = browser();
  forged.jar.set(`localhost:${DASH_PORT}`, new Map([["at_session", sess.slice(0, -4) + (sess.endsWith("AAAA") ? "BBBB" : "AAAA")]]));
  const fr = await forged.request(`${DASH}/`);
  check(fr.status === 302 && fr.headers.get("location").includes("/auth/login"), "tampered session cookie is rejected");
  const spoof = await anon.request(`${DASH}/api/at/v1/templates`, { headers: { "x-at-operator": "ceo@example.com", "x-at-authed": "1" } });
  check(spoof.status === 401, "client-sent x-at-operator / x-at-authed headers are ignored");

  // 3. Allowlist and email verification.
  loginAs = { id: "mallory", amr: ["pwd"] };
  const rm = await browser().follow(`${DASH}/`);
  check(rm.res.status === 403 && /not allowed/.test(rm.body), "account outside the allowed domains is refused (403)");
  loginAs = { id: "eve", amr: ["pwd"] };
  const re = await browser().follow(`${DASH}/`);
  check(re.res.status === 403, "unverified email is refused (403)");

  // 4. Open redirect: next=//evil must land on the dashboard.
  loginAs = { id: "alice", amr: ["pwd"] };
  const ro = await browser().follow(`${DASH}/auth/login?next=//evil.example/steal`);
  check(ro.url === `${DASH}/`, `next=//evil.example is neutralized (landed on ${ro.url})`);

  // 5. State/PKCE: a callback without the matching transaction cookie fails.
  const rc = await browser().request(`${DASH}/auth/callback?code=stolen&state=x`);
  check(rc.status === 403, "callback without its transaction cookie is refused");

  // 6. CSRF on logout, then logout.
  const csrf = await b.request(`${DASH}/auth/logout`, { method: "POST", headers: { origin: "https://evil.example" } });
  check(csrf.status === 403, "cross-origin POST is refused (CSRF)");
  const lo = await b.request(`${DASH}/auth/logout`, { method: "POST", headers: { origin: DASH } });
  check(lo.status === 303 && lo.headers.get("location").startsWith(`${ISSUER}/session/end`), "logout clears the session and ends the IdP session");
  check(!b.jar.get(`localhost:${DASH_PORT}`)?.has("at_session"), "session cookie removed");
  check((await b.request(`${DASH}/`)).status === 302, "signed out: pages require sign-in again");

  // 7. MFA required.
  await startDashboard({ OIDC_REQUIRE_MFA: "true" });
  loginAs = { id: "alice", amr: ["pwd"] };
  const rp = await browser().follow(`${DASH}/`);
  check(rp.res.status === 403 && /multi-factor/.test(rp.body), "OIDC_REQUIRE_MFA: password-only sign-in is refused");
  loginAs = { id: "alice", amr: ["pwd", "otp"] };
  const rmfa = await browser().follow(`${DASH}/`);
  check(rmfa.res.status === 200, "OIDC_REQUIRE_MFA: sign-in with a second factor succeeds");

  // 8. Misconfiguration fails closed.
  await startDashboard({ OIDC_ALLOWED_DOMAINS: "" });
  const mis = await browser().request(`${DASH}/`);
  check(mis.status === 503, "SSO without an allowlist refuses to serve (fail closed)");
} finally {
  dash?.kill();
  opServer.close();
}
console.log(failed ? `FAIL: ${failed} check(s)` : "PASS: dashboard SSO");
process.exit(failed ? 1 : 0);
