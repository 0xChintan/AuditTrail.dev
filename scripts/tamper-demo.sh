#!/usr/bin/env bash
# Phase 5 DoD: edit the ledger directly in Postgres (as a superuser, i.e.
# bypassing every grant) and show that audittrail-verify detects and
# localizes the tampering from an exported bundle.
#
#   scripts/tamper-demo.sh      (API on :8080, migrated DB, .env present)
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
API=${API:-http://localhost:8080}
BIN=packages/ingestion-go/bin
DB=${DB:-audittrail}
WORK=$(mktemp -d)
H="Authorization: Bearer $AUDITTRAIL_ADMIN_TOKEN"
export WITNESSES=${WITNESSES:-w1=http://localhost:7101,w2=http://localhost:7102,w3=http://localhost:7103}

new_tenant() {
  curl -sf -XPOST "$API/v1/admin/tenants" -H "$H" -d "{\"name\":\"$1\"}"
}
ingest() { # key from to
  node scripts/lib/ingest-v2.mjs "$1" "$2" "$3" payments
}
export_bundle() { curl -sf "$API/v2/export" -H "Authorization: Bearer $1" > "$2"; }
verify() { # bundle label tenant
  echo; echo "── audittrail-verify: $2"
  local lk; lk=$(curl -sf "$API/v2/tenants/$3/log" | python3 -c 'import json,sys;print(json.load(sys.stdin)["vkeys"][0])')
  if "$BIN/verify" --log-key "$lk" "$1"; then echo "(exit 0)"; else echo "(exit $?)"; fi
}

scenario() { # name, sql-to-apply (uses :tid)
  local out key tid
  out=$(new_tenant "tamper-$1"); key=$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["api_key"])')
  tid=$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["tenant"]["id"])')
  ingest "$key" 1 30
  "$BIN/worker" -once -tenant "$tid" >/dev/null 2>&1   # signed (+ witnessed, anchored) tree head over rows 1..30
  ingest "$key" 31 35                            # tail 31..35, not yet under a tree head
  export_bundle "$key" "$WORK/$1-before.json"
  [ "$1" = "edit-outcome" ] && verify "$WORK/$1-before.json" "baseline (untouched)" "$tid"
  local sql=${2//:tid/\'$tid\'}
  psql -X -q "$DB" -c "$sql" >/dev/null
  echo; echo "▶ tampered as superuser: $sql"
  export_bundle "$key" "$WORK/$1-after.json"
  verify "$WORK/$1-after.json" "after tampering ($1)" "$tid"
  if [ "$1" = "edit-tail" ]; then
    echo; echo "── checkpoint worker on the tampered tenant (it re-verifies before signing):"
    "$BIN/worker" -once -tenant "$tid" 2>&1 | grep -oE 'INTEGRITY.*|level=ERROR.*' || true
  fi
}

scenario edit-outcome "UPDATE agent_events SET outcome='allowed' WHERE tenant_id=:tid AND seq=15"
scenario edit-tail    "UPDATE agent_events SET metadata='{\"amount_eur\":1}' WHERE tenant_id=:tid AND seq=33"
scenario delete-row   "DELETE FROM agent_events WHERE tenant_id=:tid AND seq=20"
echo; echo "bundles kept in $WORK"
