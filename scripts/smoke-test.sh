#!/usr/bin/env bash
# Smoke-test a running Basilisk instance.
# Exits non-zero on the first failure; intended for post-deploy CI verification.
#
# Usage:
#   BASE_URL=https://keys.b1tninja.com bash scripts/smoke-test.sh
#   BASE_URL=http://localhost:8080      bash scripts/smoke-test.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
# Timeout per request (seconds).  Long enough for a cold Azure Function start
# (Flex Consumption can take 20-30 s) but short enough to fail CI promptly.
TIMEOUT="${SMOKE_TIMEOUT:-60}"

FAIL=0

# Check that a URL returns a 2xx HTTP status.
check_status() {
  local label="$1" url="$2"
  printf '  %-48s' "$label"
  local http curl_exit=0
  http=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "$url") || curl_exit=$?
  if [[ $curl_exit -ne 0 ]]; then
    echo "FAIL (curl exit $curl_exit)"
    FAIL=1
  elif [[ "$http" == 2* ]]; then
    echo "HTTP $http"
  else
    echo "HTTP $http (unexpected — expected 2xx)"
    FAIL=1
  fi
}

# Check that a URL returns a 2xx status AND that the body contains a fixed string.
check_body() {
  local label="$1" url="$2" pattern="$3"
  printf '  %-48s' "$label"
  local body curl_exit=0
  body=$(curl -sS --max-time "$TIMEOUT" --compressed "$url") || curl_exit=$?
  if [[ $curl_exit -ne 0 ]]; then
    echo "FAIL (curl exit $curl_exit)"
    FAIL=1
  elif echo "$body" | grep -qF "$pattern"; then
    echo "OK"
  else
    echo "FAIL (expected string not found in response body)"
    FAIL=1
  fi
}

echo "Smoke testing $BASE_URL ..."
echo ""

# 1. Health endpoint — confirms the function host is running.
check_status "/health"                         "$BASE_URL/health"

# 2. HKP stats — confirms the keystore backend is reachable and responsive.
#    A full table scan on Azure Table Storage can be slow; TIMEOUT covers it.
check_status "/pks/lookup?op=stats"            "$BASE_URL/pks/lookup?op=stats"

# 3. Static homepage — confirms the blob CDN is serving the portal.
#    We match on the HTML <title> text, not a string inside the JS bundle,
#    so this check is valid for both the static-site and local dev deployments.
check_body   "/ (HTML title)"                  "$BASE_URL/" "Basilisk"

# 4. Clean-URL page aliases — derived from web/*.html so new pages are covered.
#    index.html → /search; every other page → /<name>.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
check_status "/search"                         "$BASE_URL/search"
shopt -s nullglob
for html in "${REPO_ROOT}/web"/*.html; do
  page="$(basename "$html" .html)"
  [[ "$page" == "index" ]] && continue
  check_status "/$page"                        "$BASE_URL/$page"
done

# 5. Search API — confirms the API route is live (result set is not validated).
check_status "/api/v1/search?q=test"           "$BASE_URL/api/v1/search?q=test%40example.com"

echo ""
if [[ "$FAIL" -eq 0 ]]; then
  echo "Smoke test OK: $BASE_URL"
else
  echo "Smoke test FAILED: one or more checks failed (see above)"
  exit 1
fi
