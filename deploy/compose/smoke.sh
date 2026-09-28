#!/usr/bin/env bash
# End-to-end smoke test of a deployed stack, through the TLS edge:
# admin API -> tenant, signed SDK ingest, tree head, export, offline verify.
#
#   API=https://api.localhost CA=<edge root.crt> ADMIN_TOKEN_FILE=secrets/admin_token \
#   WORKER="docker compose run --rm worker -once" deploy/compose/smoke.sh
#
# Needs: node + packages/sdk/dist, packages/ingestion-go/bin/verify, python3.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${API:?API base URL}" "${ADMIN_TOKEN_FILE:?}" "${WORKER:?command that runs one worker pass}"
CURL=(curl -sSf)
[ -n "${CA:-}" ] && CURL+=(--cacert "$CA") && export NODE_EXTRA_CA_CERTS="$CA"
[ -n "${RESOLVE:-}" ] && CURL+=(--resolve "$RESOLVE")
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
ok() { echo "ok: $*"; }

"${CURL[@]}" "$API/healthz" >/dev/null && ok "API healthy over TLS"
hsts=$("${CURL[@]}" -D - -o /dev/null "$API/healthz" | grep -ci '^strict-transport-security:' || true)
[ "$hsts" -ge 1 ] && ok "HSTS header present" || { echo "FAIL: no HSTS"; exit 1; }

out=$("${CURL[@]}" -X POST "$API/v1/admin/tenants" -H "Authorization: Bearer $(cat "$ADMIN_TOKEN_FILE")" -d '{"name":"deploy-smoke"}')
KEY=$(echo "$out" | j 'd["api_key"]'); TID=$(echo "$out" | j 'd["tenant"]["id"]')
ok "tenant $TID"

API="$API" node scripts/lib/ingest-v2.mjs "$KEY" 1 25 payments
ok "25 signed events ingested"

$WORKER -tenant "$TID" >/dev/null 2>&1 || $WORKER >/dev/null 2>&1
heads=$("${CURL[@]}" "$API/v2/tree-heads" -H "Authorization: Bearer $KEY" | j 'len(d["tree_heads"]) if isinstance(d,dict) else len(d)')
[ "$heads" -ge 1 ] && ok "$heads signed tree head(s)" || { echo "FAIL: no tree head"; exit 1; }

B=$(mktemp)
"${CURL[@]}" "$API/v2/export" -H "Authorization: Bearer $KEY" > "$B"
LK=$("${CURL[@]}" "$API/v2/tenants/$TID/log" | j 'd["vkeys"][0]')
packages/ingestion-go/bin/verify --log-key "$LK" --require-covered "$B" | grep -E "rows|tree heads|RESULT"
echo "PASS: deploy smoke"
