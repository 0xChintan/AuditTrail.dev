#!/usr/bin/env bash
# Security baseline (v2 task 0.3). Fails on any high finding.
#   scripts/security.sh          run everything
#   SKIP_RACE=1 scripts/security.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:$(go env GOPATH)/bin"
export GOTOOLCHAIN=${GOTOOLCHAIN:-local}
mkdir -p build/sbom
fail=0
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
check() { if [ "$1" -ne 0 ]; then echo "FAILED: $2"; fail=1; else echo "ok: $2"; fi; }

step "gosec (high severity)"
gosec -quiet -severity high -confidence medium ./...; check $? gosec

step "govulncheck"
govulncheck ./...; check $? govulncheck

step "semgrep (Go, TS, React, Next.js, secrets)"
semgrep scan --metrics=off --error --severity ERROR --quiet \
  --config p/golang --config p/typescript --config p/react --config p/nextjs --config p/secrets \
  --exclude node_modules --exclude .next --exclude dist --exclude 'schemas/**/vectors.json' .
check $? semgrep

step "osv-scanner (Go + npm lockfiles)"
osv-scanner scan source -r --lockfile pnpm-lock.yaml --lockfile go.mod . >/tmp/osv.out 2>&1
rc=$?; grep -E "Total|No issues" /tmp/osv.out; check $rc osv-scanner

step "gitleaks (committed history)"
gitleaks git --no-banner --config .gitleaks.toml . ; check $? "gitleaks history"

step "gitleaks canary (a seeded fake secret MUST be caught)"
canary=$(mktemp -d)
printf 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\nAPI="at2_0123456789ab_%s"\n' "$(printf 'Q%.0s' $(seq 43))" > "$canary/leak.env"
gitleaks dir --no-banner --config .gitleaks.toml "$canary" >/dev/null 2>&1
if [ $? -eq 1 ]; then echo "ok: canary secret detected"; else echo "FAILED: gitleaks did not catch the canary"; fail=1; fi
rm -rf "$canary"

if [ -z "${SKIP_RACE:-}" ]; then
  step "go test -race"
  go test -race -count=1 ./...; check $? "go test -race"
fi

step "SBOM (CycloneDX)"
cyclonedx-gomod mod -json -licenses -output build/sbom/go.cdx.json . >/dev/null 2>&1; check $? "Go SBOM"
if command -v npx >/dev/null; then
  npx --yes @cyclonedx/cdxgen@11 -t js -o build/sbom/js.cdx.json --no-recurse . >/dev/null 2>&1; check $? "JS SBOM"
fi
ls -la build/sbom 2>/dev/null

echo
if [ $fail -ne 0 ]; then echo "SECURITY BASELINE: FAIL"; exit 1; fi
echo "SECURITY BASELINE: PASS"
