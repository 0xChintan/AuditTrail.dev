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

new_tenant() {
  curl -sf -XPOST "$API/v1/admin/tenants" -H "$H" -d "{\"name\":\"$1\"}"
}
ingest() { # key n
  for i in $(seq 1 "$2"); do
    outcome=allowed; [ $((i % 7)) -eq 0 ] && outcome=denied
    curl -sf -XPOST "$API/v1/events" -H "Authorization: Bearer $1" \
      -d "{\"human_principal_id\":\"alice\",\"agent_id\":\"payments-agent\",\"model_id\":\"claude-opus-5-5\",\"action\":\"payment.transfer\",\"target_resource\":\"account/$i\",\"outcome\":\"$outcome\",\"metadata\":{\"amount_eur\":$((i * 100))}}" >/dev/null
  done
}
export_bundle() { curl -sf "$API/v1/export?format=bundle" -H "Authorization: Bearer $1" > "$2"; }
verify() { # bundle label
  echo; echo "── audittrail-verify: $2"
  if "$BIN/verify" "$1"; then echo "(exit 0)"; else echo "(exit $?)"; fi
}

scenario() { # name, sql-to-apply (uses :tid)
  local out key tid
  out=$(new_tenant "tamper-$1"); key=$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["api_key"])')
  tid=$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["tenant"]["id"])')
  ingest "$key" 30
  "$BIN/worker" -once -tenant "$tid" >/dev/null 2>&1   # checkpoint + RFC 3161 anchor rows 1..31
  ingest "$key" 5                                # uncheckpointed tail 32..36
  export_bundle "$key" "$WORK/$1-before.json"
  [ "$1" = "edit-outcome" ] && verify "$WORK/$1-before.json" "baseline (untouched)"
  local sql=${2//:tid/\'$tid\'}
  psql -X -q "$DB" -c "$sql" >/dev/null
  echo; echo "▶ tampered as superuser: $sql"
  export_bundle "$key" "$WORK/$1-after.json"
  verify "$WORK/$1-after.json" "after tampering ($1)"
  if [ "$1" = "edit-tail" ]; then
    echo; echo "── checkpoint worker on the tampered tenant (it re-verifies before signing):"
    "$BIN/worker" -once -tenant "$tid" 2>&1 | grep -o 'INTEGRITY.*' || true
  fi
}

scenario edit-outcome "UPDATE agent_events SET outcome='allowed' WHERE tenant_id=:tid AND seq=15"
scenario edit-tail    "UPDATE agent_events SET metadata='{\"amount_eur\":1}' WHERE tenant_id=:tid AND seq=34"
scenario delete-row   "DELETE FROM agent_events WHERE tenant_id=:tid AND seq=20"
echo; echo "bundles kept in $WORK"
