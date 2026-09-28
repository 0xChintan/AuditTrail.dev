#!/bin/sh
# Docker/Kubernetes secrets convention: for each X_FILE, export X from the file
# (unless X is already set), so secrets never sit in the container spec.
set -eu
for var in AUDITTRAIL_ADMIN_TOKEN DASHBOARD_PASSWORD OIDC_CLIENT_SECRET SESSION_SECRET; do
  file=$(printenv "${var}_FILE" 2>/dev/null || true)
  if [ -n "$file" ] && [ -z "$(printenv "$var" 2>/dev/null || true)" ]; then
    export "$var=$(cat "$file")"
  fi
done
exec "$@"
