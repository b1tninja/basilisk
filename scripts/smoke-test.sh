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
# Front Door purge is async (~2 min). Retry static HTML checks that can see
# a stale PoP immediately after deploy-static.sh queues a purge.
SMOKE_HTML_RETRIES="${SMOKE_HTML_RETRIES:-12}"
SMOKE_HTML_RETRY_SLEEP="${SMOKE_HTML_RETRY_SLEEP:-10}"

FAIL=0
# HTML CDN rule uses UseQueryString — bust PoP cache so we are not stuck on
# pre-deploy HTML while purge is still propagating.
SMOKE_QS="_smoke=$(date +%s)"

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

# Fetch homepage (cache-busted) until SRI + external importmap are present, then
# confirm the referenced importmap JSON is itself reachable.
wait_for_sri_html() {
  local url="$1"
  local attempt=1
  local body="" map_path="" http=""
  printf '  %-48s' "/ (SRI + external importmap)"
  while (( attempt <= SMOKE_HTML_RETRIES )); do
    body=$(curl -sS --max-time "$TIMEOUT" --compressed "$url") || true
    if echo "$body" | grep -qF 'integrity=' \
      && echo "$body" | grep -qE 'src="/importmaps/importmap-[0-9a-f]+\.json"'; then
      map_path=$(echo "$body" | grep -oE '/importmaps/importmap-[0-9a-f]+\.json' | head -n1)
      http=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "${BASE_URL}${map_path}?${SMOKE_QS}") || http="000"
      if [[ "$http" == 2* ]]; then
        echo "OK (${map_path}, attempt ${attempt})"
        return 0
      fi
    fi
    if (( attempt == SMOKE_HTML_RETRIES )); then
      break
    fi
    sleep "$SMOKE_HTML_RETRY_SLEEP"
    attempt=$((attempt + 1))
    # New bust token each retry (UseQueryString → fresh origin fetch).
    SMOKE_QS="_smoke=$(date +%s)-${attempt}"
    url="${BASE_URL}/?${SMOKE_QS}"
  done
  echo "FAIL (stale CDN HTML or missing /importmaps/*.json after ${SMOKE_HTML_RETRIES} attempts)"
  FAIL=1
  return 1
}

# The two halves of the policy a browser actually computes, compared.
#
# A document carries a `<meta http-equiv="Content-Security-Policy">` and the
# response arrives with a header, and the browser enforces the **intersection**.
# So a source in one and not the other is a source that does not exist — and
# neither side looks wrong on its own, which is exactly how this deployment
# shipped with signalling switched off: Front Door's header named the Web PubSub
# host, the uploaded pages' meta did not, shared sessions could not open a
# socket, and every configuration file was correct.
#
# This is the check that catches it from the outside, against the bytes actually
# being served, after the upload and the purge. Nothing else in this repo can:
# the unit tests see the artifact and the browser suite sees a harness, but only
# this sees what a visitor gets.
check_csp_meta_allows_header() {
  local label="$1" url="$2"
  printf '  %-48s' "$label"
  local raw curl_exit=0
  raw=$(curl -sS -D - --max-time "$TIMEOUT" --compressed "$url") || curl_exit=$?
  if [[ $curl_exit -ne 0 ]]; then
    echo "FAIL (curl exit $curl_exit)"
    FAIL=1
    return
  fi

  # `connect-src …` up to the next `;`, from the header and from the meta tag.
  local header meta
  header=$(printf '%s' "$raw" | tr -d '\r' \
    | grep -i '^content-security-policy:' | head -n1 \
    | grep -oE 'connect-src [^;]*' || true)
  meta=$(printf '%s' "$raw" \
    | grep -oE '<meta http-equiv="Content-Security-Policy" content="[^"]*"' | head -n1 \
    | grep -oE 'connect-src [^;]*' || true)

  if [[ -z "$header" ]]; then
    echo "FAIL (no connect-src in the response header)"
    FAIL=1
    return
  fi
  if [[ -z "$meta" ]]; then
    # Not "allow everything" — with `default-src 'none'` a missing connect-src
    # denies everything, so an absent directive is a harder failure than a
    # mismatched one.
    echo "FAIL (page carries no connect-src meta)"
    FAIL=1
    return
  fi

  local missing=""
  local source
  for source in ${header#connect-src }; do
    case " ${meta#connect-src } " in
      *" $source "*) ;;
      *) missing="${missing} ${source}" ;;
    esac
  done

  if [[ -n "$missing" ]]; then
    echo "FAIL (header allows, page refuses:${missing})"
    echo "      The browser enforces the intersection, so those sources are unreachable."
    echo "      Re-run scripts/deploy-static.sh with BASILISK_SIGNALING_WSS_ORIGIN resolved."
    FAIL=1
  else
    echo "OK"
  fi
}

echo "Smoke testing $BASE_URL ..."
echo ""

# 1. Health endpoint — confirms the function host is running.
check_status "/health"                         "$BASE_URL/health"

# 2. HKP stats — confirms the keystore backend is reachable and responsive.
#    A full table scan on Azure Table Storage can be slow; TIMEOUT covers it.
check_status "/pks/lookup?op=stats"            "$BASE_URL/pks/lookup?op=stats"

# 3. Static homepage — title + SRI pin (retries through Front Door purge lag).
check_body   "/ (HTML title)"                  "$BASE_URL/?${SMOKE_QS}" "Basilisk"
wait_for_sri_html "$BASE_URL/?${SMOKE_QS}" || true

# 4. Clean-URL page aliases — product pages only (Vite rollup inputs).
#    index.html → /search; every other built page → /<name>.
#    Dev/snapshot fixtures under web/ (e.g. tool-card-preview.html) are not
#    in vite.config.js and are not deployed — skip them.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VITE_CONFIG="${REPO_ROOT}/web/vite.config.js"
check_status "/search"                         "$BASE_URL/search?${SMOKE_QS}"
shopt -s nullglob
for html in "${REPO_ROOT}/web"/*.html; do
  page="$(basename "$html" .html)"
  [[ "$page" == "index" ]] && continue
  if ! grep -qE "${page}\\.html" "$VITE_CONFIG"; then
    continue
  fi
  check_status "/$page"                        "$BASE_URL/${page}?${SMOKE_QS}"
done

# 5. Search API — confirms the API route is live (result set is not validated).
check_status "/api/v1/search?q=test"           "$BASE_URL/api/v1/search?q=test%40example.com"

# 6. The policy a browser computes. `/toolkit` because it is the page that opens
#    the signalling socket, so it is the one where a header-only source costs a
#    feature rather than nothing.
check_csp_meta_allows_header "/toolkit (meta allows header CSP)" "$BASE_URL/toolkit?${SMOKE_QS}"

echo ""
if [[ "$FAIL" -eq 0 ]]; then
  echo "Smoke test OK: $BASE_URL"
else
  echo "Smoke test FAILED: one or more checks failed (see above)"
  exit 1
fi
