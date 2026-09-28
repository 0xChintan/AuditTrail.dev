#!/usr/bin/env bash
# Run the whole stack locally: migrations, 1 API, checkpoint worker, dashboard.
#   scripts/dev.sh          (Ctrl-C stops everything)
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "No .env. Run: scripts/setup.sh"; exit 1; }
set -a; . ./.env; set +a
(cd packages/ingestion-go && go build -o bin/ ./cmd/...)
packages/ingestion-go/bin/migrate
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
packages/ingestion-go/bin/api & pids+=($!)
CHECKPOINT_INTERVAL=${CHECKPOINT_INTERVAL:-30s} packages/ingestion-go/bin/worker & pids+=($!)
[ -f apps/dashboard/.env.local ] || printf 'AUDITTRAIL_API_URL=http://localhost:8080\nAUDITTRAIL_ADMIN_TOKEN=%s\n' "$AUDITTRAIL_ADMIN_TOKEN" > apps/dashboard/.env.local
(cd apps/dashboard && pnpm dev) & pids+=($!)
echo "API http://localhost:8080 · dashboard http://localhost:3000 · worker every ${CHECKPOINT_INTERVAL:-30s}"
wait
