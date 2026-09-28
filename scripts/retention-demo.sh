#!/usr/bin/env bash
# Task 6.3: retention window + legal hold. Simulates time passing by
# backdating one witnessed tree head (test harness only, as DB superuser), then shows:
#   - retention below 183 days is refused
#   - a legal hold blocks the purge regardless of retention
#   - after release, only rows under an anchored/witnessed tree head are purged
#   - leaf hashes are kept, so the surviving log still verifies against the signed heads
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
API=${API:-http://localhost:8080}; BIN=packages/ingestion-go/bin; DB=${DB:-audittrail}
H="Authorization: Bearer $AUDITTRAIL_ADMIN_TOKEN"
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }

out=$(curl -sf -XPOST "$API/v1/admin/tenants" -H "$H" -d '{"name":"retention-demo"}')
KEY=$(echo "$out" | j 'd["api_key"]'); TID=$(echo "$out" | j 'd["tenant"]["id"]')
export WITNESSES=${WITNESSES:-w1=http://localhost:7101,w2=http://localhost:7102,w3=http://localhost:7103}
node scripts/lib/ingest-v2.mjs "$KEY" 1 20 reads
"$BIN/worker" -once -tenant "$TID" >/dev/null 2>&1
node scripts/lib/ingest-v2.mjs "$KEY" 21 25 reads
"$BIN/worker" -once -tenant "$TID" >/dev/null 2>&1
psql -X -q -At "$DB" -c "SELECT 'tree head size '||tree_size||' anchor='||tsa_status||' witnesses='||array_to_string(witnesses,',') FROM tree_heads WHERE tenant_id='$TID' ORDER BY tree_size"
FIRST=$(psql -X -q -At "$DB" -c "SELECT min(tree_size) FROM tree_heads WHERE tenant_id='$TID'")

echo; echo "1) retention below the six-month minimum is refused:"
curl -s -XPATCH "$API/v1/admin/tenants/$TID" -H "$H" -d '{"retention_days":30}'; echo
echo "   ...and the app DB role cannot delete ledger rows at all:"
psql -X -q "postgres://audittrail_app:audittrail_app@localhost:5432/$DB" -c "DELETE FROM agent_events WHERE tenant_id='$TID'" 2>&1 | head -1 || true

echo; echo "2) simulate 200 days passing for the first tree head (size $FIRST) (test harness, superuser)"
psql -X -q "$DB" -c "UPDATE tree_heads SET created_at = now() - interval '200 days' WHERE tenant_id='$TID' AND tree_size=$FIRST"

echo; echo "3) set a legal hold, then run the purge job:"
curl -sf -XPATCH "$API/v1/admin/tenants/$TID" -H "$H" -d '{"legal_hold":true,"legal_hold_reason":"Litigation hold: case 2026-CV-0142"}' | j '"   legal_hold="+str(d["legal_hold"])+" reason="+d["legal_hold_reason"]'
"$BIN/purge" -tenant "$TID" || echo "   (purge exited non-zero: blocked)"

echo; echo "4) release the hold and purge again:"
curl -sf -XPATCH "$API/v1/admin/tenants/$TID" -H "$H" -d '{"legal_hold":false}' >/dev/null
"$BIN/purge" -tenant "$TID"
psql -X -q -At "$DB" -c "SELECT '   rows remaining: '||count(*)||' (seq '||min(seq)||'..'||max(seq)||')' FROM agent_events WHERE tenant_id='$TID'"
curl -sf "$API/v1/purges" -H "Authorization: Bearer $KEY" | j '"   purge_log: "+str([(p["purged_through_seq"],p["rows_deleted"],p["performed_by"]) for p in d["purges"]])'

echo; echo "5) the surviving log still verifies against the signed tree heads (purged leaves keep their hashes):"
BUNDLE=$(mktemp)
curl -sf "$API/v2/export" -H "Authorization: Bearer $KEY" > "$BUNDLE"
LK=$(curl -sf "$API/v2/tenants/$TID/log" | j 'd["vkeys"][0]')
"$BIN/verify" --log-key "$LK" "$BUNDLE" | grep -E "rows|tree heads|RESULT"
echo; echo "6) setting and releasing the hold are themselves ledger events (the purge is in purge_log):"
curl -sf "$API/v1/events?action=tenant.settings_changed" -H "Authorization: Bearer $KEY" | j '"\n".join("   seq %d %s legal_hold %s -> %s" % (e["seq"], e["action"], e["metadata"]["before"]["legal_hold"], e["metadata"]["after"]["legal_hold"]) for e in d["events"])'
