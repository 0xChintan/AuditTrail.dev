#!/usr/bin/env bash
# Task 6.3: retention window + legal hold. Simulates time passing by
# backdating one checkpoint (test harness only, as DB superuser), then shows:
#   - retention below 183 days is refused
#   - a legal hold blocks the purge regardless of retention
#   - after release, only whole anchored checkpoint ranges are purged
#   - the surviving chain still verifies from the checkpoint's signed head
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
API=${API:-http://localhost:8080}; BIN=packages/ingestion-go/bin; DB=${DB:-audittrail}
H="Authorization: Bearer $AUDITTRAIL_ADMIN_TOKEN"
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }

out=$(curl -sf -XPOST "$API/v1/admin/tenants" -H "$H" -d '{"name":"retention-demo"}')
KEY=$(echo "$out" | j 'd["api_key"]'); TID=$(echo "$out" | j 'd["tenant"]["id"]')
post() { curl -sf -XPOST "$API/v1/events" -H "Authorization: Bearer $KEY" -d "{\"agent_id\":\"etl-agent\",\"action\":\"record.read\",\"target_resource\":\"patient/$1\",\"outcome\":\"allowed\"}" >/dev/null; }
for i in $(seq 1 20); do post $i; done
"$BIN/worker" -once -tenant "$TID" >/dev/null 2>&1
for i in $(seq 21 25); do post $i; done
"$BIN/worker" -once -tenant "$TID" >/dev/null 2>&1
psql -X -q -At "$DB" -c "SELECT 'checkpoint '||first_seq||'..'||last_seq||' anchor='||anchor_status FROM checkpoints WHERE tenant_id='$TID' ORDER BY first_seq"

echo; echo "1) retention below the six-month minimum is refused:"
curl -s -XPATCH "$API/v1/admin/tenants/$TID" -H "$H" -d '{"retention_days":30}'; echo
echo "   ...and the app DB role cannot delete ledger rows at all:"
psql -X -q "postgres://audittrail_app:audittrail_app@localhost:5432/$DB" -c "DELETE FROM agent_events WHERE tenant_id='$TID'" 2>&1 | head -1 || true

echo; echo "2) simulate 200 days passing for the first checkpoint (test harness, superuser)"
psql -X -q "$DB" -c "UPDATE checkpoints SET created_at = now() - interval '200 days' WHERE tenant_id='$TID' AND first_seq=1"

echo; echo "3) set a legal hold, then run the purge job:"
curl -sf -XPATCH "$API/v1/admin/tenants/$TID" -H "$H" -d '{"legal_hold":true,"legal_hold_reason":"Litigation hold: case 2026-CV-0142"}' | j '"   legal_hold="+str(d["legal_hold"])+" reason="+d["legal_hold_reason"]'
"$BIN/purge" -tenant "$TID" || echo "   (purge exited non-zero: blocked)"

echo; echo "4) release the hold and purge again:"
curl -sf -XPATCH "$API/v1/admin/tenants/$TID" -H "$H" -d '{"legal_hold":false}' >/dev/null
"$BIN/purge" -tenant "$TID"
psql -X -q -At "$DB" -c "SELECT '   rows remaining: '||count(*)||' (seq '||min(seq)||'..'||max(seq)||')' FROM agent_events WHERE tenant_id='$TID'"
curl -sf "$API/v1/purges" -H "Authorization: Bearer $KEY" | j '"   purge_log: "+str([(p["purged_through_seq"],p["rows_deleted"],p["performed_by"]) for p in d["purges"]])'

echo; echo "5) the surviving chain verifies from the purged checkpoint's signed head hash:"
curl -sf "$API/v1/export?format=bundle" -H "Authorization: Bearer $KEY" > /tmp/retention-bundle.json
"$BIN/verify" /tmp/retention-bundle.json | grep -E "records|RESULT"
echo; echo "6) setting and releasing the hold are themselves ledger events (the purge is in purge_log):"
curl -sf "$API/v1/events?action=tenant.settings_changed" -H "Authorization: Bearer $KEY" | j '"\n".join("   seq %d %s legal_hold %s -> %s" % (e["seq"], e["action"], e["metadata"]["before"]["legal_hold"], e["metadata"]["after"]["legal_hold"]) for e in d["events"])'
