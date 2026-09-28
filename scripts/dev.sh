#!/usr/bin/env bash
# Run the whole stack locally: migrations, 1 API, 3 witnesses, checkpoint worker, dashboard.
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
# Three local witnesses (DEV ONLY: -tofu pins each log's key on first sight).
# Their public keys land in $WDIR/w*.vkey for `bin/verify --witness`.
WDIR=${WITNESS_DIR:-$HOME/.audittrail-dev/witnesses}
mkdir -p "$WDIR"
for i in 1 2 3; do
  packages/ingestion-go/bin/witness -name "witness.audittrail.local/w$i" -key "$WDIR/w$i.seed" -state "$WDIR/w$i.json" \
    -listen ":710$i" -tofu http://localhost:8080 > "$WDIR/w$i.vkey" & pids+=($!)
done
WITNESSES=${WITNESSES:-w1=http://localhost:7101,w2=http://localhost:7102,w3=http://localhost:7103} \
  CHECKPOINT_INTERVAL=${CHECKPOINT_INTERVAL:-30s} packages/ingestion-go/bin/worker & pids+=($!)
[ -f apps/dashboard/.env.local ] || printf 'AUDITTRAIL_API_URL=http://localhost:8080\nAUDITTRAIL_ADMIN_TOKEN=%s\nDASHBOARD_PASSWORD=%s\n' "$AUDITTRAIL_ADMIN_TOKEN" "${DASHBOARD_PASSWORD:-}" > apps/dashboard/.env.local
(cd apps/dashboard && pnpm dev) & pids+=($!)
echo "API http://localhost:8080 · witnesses :7101-7103 · dashboard http://localhost:3000 (password: DASHBOARD_PASSWORD in .env) · worker every ${CHECKPOINT_INTERVAL:-30s}"
wait
