#!/usr/bin/env bash
# One-time local setup: .env with fresh secrets, deps, builds, database.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f .env ]; then
  sed -e "s|^AUDITTRAIL_MASTER_KEY=.*|AUDITTRAIL_MASTER_KEY=$(head -c 32 /dev/urandom | base64)|" \
      -e "s|^AUDITTRAIL_ADMIN_TOKEN=.*|AUDITTRAIL_ADMIN_TOKEN=$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')|" \
      -e "s|^AUDITTRAIL_KEY_PEPPER=.*|AUDITTRAIL_KEY_PEPPER=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')|" \
      -e "s|^DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=$(head -c 12 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')|" \
      .env.example > .env
  echo "wrote .env with fresh secrets (see SECRETS.md)"
fi
pnpm install
pnpm -r --filter "./packages/*" build
(cd packages/ingestion-go && go build -o bin/ ./cmd/...)
packages/ingestion-go/bin/migrate
echo "done. Start everything with: scripts/dev.sh"
