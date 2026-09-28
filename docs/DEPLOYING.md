# Deploying AuditTrail

A single-host production stack using Docker Compose: `deploy/compose/`. It is secure by default. The same images run on Kubernetes or any container platform; the compose file is the reference for which settings each service needs.

```
 internet ──443──▶ Caddy (TLS 1.2+, automatic certs, HSTS, HTTP→HTTPS)
                     ├── api.example.com ──▶ api        ┐  edge network (internal)
                     └── app.example.com ──▶ dashboard  ┘
 api, worker, purge, migrate ──TLS 1.3, verify-full──▶ Postgres   db network (internal)
 worker ──egress──▶ RFC 3161 TSA, witnesses
```

| Control | How |
|---|---|
| TLS at the edge (ASVS V9) | Caddy obtains and renews ACME certificates, redirects HTTP to HTTPS, and sends `Strict-Transport-Security`. The API and dashboard are never published directly |
| TLS to Postgres | `pg_hba.conf` has only `hostssl` lines, so plaintext TCP is refused. TLS 1.3 minimum, SCRAM passwords. Every client uses `sslmode=verify-full` against a private CA, which checks the certificate *and* the hostname `postgres` |
| Network isolation | `db` and `edge` are internal networks with no route out. Only Caddy (ingress) and the worker (TSA, witnesses) can reach the internet |
| Least privilege | Each service connects with its own DB role (app / worker / control / purge; the owner only runs migrations). Containers run as non-root with a read-only root filesystem, all Linux capabilities dropped (Caddy keeps only `NET_BIND_SERVICE`) and `no-new-privileges` |
| Secrets | Docker secrets mounted under `/run/secrets`, read through the `*_FILE` convention, so they never appear in the container spec or `docker inspect`. The master key can live in a KMS (`compose.kms.yaml`) |
| Operator access | OIDC SSO with an allowlist and optional MFA (`compose.sso.yaml`). Admin actions are recorded under each operator's name |
| Supply chain | Base images pinned by digest, bumped by Dependabot. Release images are multi-arch, with SBOM and provenance attestations, signed with cosign (keyless) |

## Install

Requirements: Docker Engine 25+ with Compose v2, and DNS A/AAAA records for two hostnames pointing at the host, with ports 80 and 443 open.

```sh
git clone https://github.com/0xChintan/AuditTrail.dev && cd AuditTrail.dev/deploy/compose
./init-secrets.sh                 # private CA, Postgres cert, every secret (never overwrites)
cp .env.example .env              # set API_DOMAIN, DASHBOARD_DOMAIN, CADDY_GLOBAL_OPTIONS=email you@…
docker compose up -d --build --wait
```

To use released images instead of building, set `AUDITTRAIL_SERVER_IMAGE` and `AUDITTRAIL_DASHBOARD_IMAGE` in `.env` and verify their signatures first:

```sh
cosign verify ghcr.io/0xchintan/audittrail-server:v0.2.0 \
  --certificate-identity-regexp 'https://github.com/0xChintan/AuditTrail.dev/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Sign in to `https://$DASHBOARD_DOMAIN` with any username and the password in `secrets/dashboard_password`, then onboard a tenant. `deploy/compose/smoke.sh` runs an end-to-end check of a live deployment: tenant, signed ingest, tree head, export, offline verification.

### Trying it locally

With no public DNS, use Caddy's internal CA:

```sh
API_DOMAIN=api.localhost DASHBOARD_DOMAIN=app.localhost CADDY_GLOBAL_OPTIONS=local_certs docker compose up -d --build --wait
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./edge-root.crt
curl --cacert edge-root.crt https://api.localhost/healthz
```

CI runs exactly this on every change (`.github/workflows/deploy-smoke.yml`). It also checks that Postgres refuses plaintext connections, that the containers run as non-root with read-only filesystems, and that the API and database ports aren't reachable from the host.

## Master key in a KMS

In production, the master key (which seals every tenant's signing key and PII key) should exist only in wrapped form. Supported: AWS KMS (`awskms://`), Google Cloud KMS (`gcpkms://`), Azure Key Vault (`azurekeyvault://`) and HashiCorp Vault transit (`hashivault://`). The api and worker unwrap it once at startup, so every unwrap goes through your KMS access policy and audit log.

Follow the steps at the top of [`compose.kms.yaml`](../deploy/compose/compose.kms.yaml): wrap the key, set `AUDITTRAIL_KMS_KEY_URL`, and run with `-f compose.yaml -f compose.kms.yaml`. That override also sets `AUDITTRAIL_REQUIRE_KMS=true`, so a plaintext key is refused, and gives the API the outbound route it needs to reach the KMS. Credentials come from the platform (an instance role or workload identity) or the provider's standard variables. Moving to a new KMS key: `audittrail-admin kms-rewrap -to <new URL>`.

## Operator sign-in (SSO)

By default the dashboard is protected by one shared password (`secrets/dashboard_password`). For production, sign operators in through your identity provider instead. [`compose.sso.yaml`](../deploy/compose/compose.sso.yaml) enables OpenID Connect (authorization code + PKCE). It works with any compliant IdP, including Microsoft Entra ID, Google Workspace, Okta, Auth0 and Keycloak.

- **Who can sign in.** Only accounts matching `OIDC_ALLOWED_EMAILS` or `OIDC_ALLOWED_DOMAINS`, with a verified email. The dashboard refuses to start SSO without an allowlist.
- **MFA.** `OIDC_REQUIRE_MFA=true` requires the ID token's `amr` claim to show a second factor. Entra ID and Okta send `amr`. Google does not, so there you enforce 2-Step Verification in the Workspace admin console instead.
- **Sessions.** Sessions are encrypted (JWE), HttpOnly, SameSite=Lax cookies with the `__Host-` prefix, lasting 8 hours by default (`SESSION_MAX_AGE_HOURS`). Signing out also ends the IdP session when the IdP supports RP-initiated logout.
- **Accountability.** Admin actions (tenant created, settings changed, keys created, revoked or rotated) are sealed into the tenant's ledger with the operator's email as principal, not a shared token.
- **CSRF.** State-changing requests must come from the dashboard's own origin.

`scripts/oidc-e2e.mjs` checks all of this against a real OpenID provider.

## Witnesses

Tree heads are only as trustworthy as the witnesses that cosign them. In production, witnesses must be run by **independent parties**: an auditor, a customer, a partner. Each runs `audittrail-witness` with your log's public key configured out of band (the `-log` flag, not `-tofu`). Then list them for the worker:

```sh
WITNESSES=auditor=https://witness.auditor.example/,customer=https://witness.customer.example/
```

For a demo, `docker compose --profile local-witnesses up -d` starts three witnesses on the same host (`WITNESSES=w1=http://witness1:7101,w2=http://witness2:7101,w3=http://witness3:7101`). They provide no independence.

## Operations

**Backups.** Back up two things: the database (`docker compose exec postgres pg_dump -U postgres -Fc audittrail > audittrail.dump`) and `secrets/`, above all `master_key` and `key_pepper`. Without the master key, tenant signing keys can't be unsealed. Changing the pepper invalidates every API key. The ledger's integrity doesn't depend on backups: any copy can be checked with `audittrail-verify`.

**Upgrades.** Pull or build the new images and run `docker compose up -d --wait`. The `migrate` service runs first and the other services wait for it to finish successfully. Migrations only add to the schema.

**Rotating secrets.** Delete the file in `secrets/`, rerun `./init-secrets.sh` and restart. Database role passwords are applied by `migrate`, which runs on every `up`. For the master key and tenant signing keys, follow [SECRETS.md](../SECRETS.md). The Postgres server certificate is valid for 825 days; delete `secrets/postgres.crt` to reissue it from the same CA. After setup, keep `secrets/ca.key` offline.

**Scaling.** One API instance handles thousands of events per second ([PERFORMANCE.md](PERFORMANCE.md)). Several instances can share the database safely, since the sequencer serializes per tenant in Postgres. Tenant rate limits are enforced through a token bucket in Postgres: each instance leases small batches of tokens, so the limit holds across instances at about 1% throughput cost. `RATE_LIMIT_MODE=local` switches back to per-instance buckets. Run exactly one `worker` and one `purge`: extra copies are safe, because they take advisory locks, but they add nothing.

**Kubernetes.** Use the same images and environment. Mount each secret as a file and point the matching `*_FILE` variable at it. Put an ingress with TLS and HSTS in front of `api` and `dashboard`. Keep Postgres TLS-only with `verify-full` clients. Apply NetworkPolicies equivalent to the `db` and `edge` networks.

## Not covered here

Database replication and point-in-time recovery: use a managed Postgres and point the `*_db_url` secrets at it with `sslmode=verify-full`.
