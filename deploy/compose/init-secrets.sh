#!/usr/bin/env bash
# Creates deploy/compose/secrets/: a private CA and Postgres server
# certificate, database role passwords, verify-full connection strings, and
# the application secrets. Existing files are never overwritten, so rerunning
# it is safe; delete a file to rotate that secret.
#
# Back up the master key and pepper: losing the master key makes tenant
# signing keys unusable; changing the pepper invalidates every API key.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
D=secrets
mkdir -p "$D"
chmod 0700 "$D"

rand_hex() { openssl rand -hex "$1"; }
put() { # name value — write once
  [ -e "$D/$1" ] && return 0
  printf '%s' "$2" > "$D/$1"
  echo "created $D/$1"
}
derive() { # name value — always rewritten from the sources above
  printf '%s' "$2" > "$D/$1"
}

# ---- Postgres TLS: private CA + server cert for the in-network name "postgres"
if [ ! -e "$D/ca.crt" ]; then
  openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=AuditTrail internal CA" -keyout "$D/ca.key" -out "$D/ca.crt" 2>/dev/null
  echo "created $D/ca.crt (keep $D/ca.key offline after setup)"
fi
if [ ! -e "$D/postgres.crt" ]; then
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=postgres" -keyout "$D/postgres.key" -out "$D/postgres.csr" 2>/dev/null
  printf 'subjectAltName=DNS:postgres\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n' > "$D/postgres.ext"
  openssl x509 -req -in "$D/postgres.csr" -CA "$D/ca.crt" -CAkey "$D/ca.key" -CAcreateserial \
    -days 825 -extfile "$D/postgres.ext" -out "$D/postgres.crt" 2>/dev/null
  rm -f "$D/postgres.csr" "$D/postgres.ext" "$D/ca.srl"
  echo "created $D/postgres.crt"
fi

# ---- Database roles (hex passwords: safe inside URLs without escaping)
put postgres_password "$(rand_hex 24)"
for role in app worker control purge; do put "${role}_db_password" "$(rand_hex 24)"; done
q="sslmode=verify-full&sslrootcert=/run/secrets/pg_ca_crt"
# Connection strings are derived from the passwords, so they are rewritten on
# every run: rotating a password is "delete it, rerun, docker compose up".
derive admin_db_url "postgres://postgres:$(cat $D/postgres_password)@postgres:5432/audittrail?$q"
for role in app worker control purge; do
  derive "${role}_db_url" "postgres://audittrail_${role}:$(cat $D/${role}_db_password)@postgres:5432/audittrail?$q"
done

# ---- Application secrets (see SECRETS.md)
put master_key "$(openssl rand -base64 32)"
put key_pepper "$(rand_hex 32)"
put admin_token "$(rand_hex 32)"
put dashboard_password "$(rand_hex 16)"
put session_secret "$(rand_hex 32)"          # dashboard SSO session cookies (compose.sso.yaml)

# Compose bind-mounts each secret file into containers that run as non-root
# users, so the files must be readable; the 0700 directory protects them on
# the host. The CA private key is not mounted anywhere.
chmod 0644 "$D"/*
chmod 0600 "$D/ca.key"
echo "secrets ready in $(pwd)/$D (dashboard password: $D/dashboard_password)"
