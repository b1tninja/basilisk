#!/usr/bin/env bash
# Smoke-test a running Basilisk instance.
# Exits non-zero on the first failure; intended for post-deploy CI verification.
#
# Usage:
#   BASE_URL=https://keys.b1tninja.com bash scripts/smoke-test.sh
#   BASE_URL=http://localhost:8080      bash scripts/smoke-test.sh
#
# Two of the checks compare the served bytes against the ones the deploy staged
# in `web/dist`, so a run from a checkout that has not been built refuses rather
# than skipping. Say `SMOKE_STAGE_DIR=none` to run the rest without them.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

BASE_URL="${BASE_URL:-http://localhost:8080}"
# Timeout per request (seconds).  Long enough for a cold Azure Function start
# (Flex Consumption can take 20-30 s) but short enough to fail CI promptly.
TIMEOUT="${SMOKE_TIMEOUT:-60}"
# Front Door purge is async (~2 min). Retry static HTML checks that can see
# a stale PoP immediately after deploy-static.sh queues a purge.
SMOKE_HTML_RETRIES="${SMOKE_HTML_RETRIES:-12}"
SMOKE_HTML_RETRY_SLEEP="${SMOKE_HTML_RETRY_SLEEP:-10}"
# The directory whose bytes were uploaded — `scripts/package-static.sh` prints
# this path and `scripts/deploy-static.sh` uploads from it, so after a deploy it
# is still on disk beside this script. `none` declines the comparison the way
# `BASILISK_SIGNALING_WSS_ORIGIN=none` declines signalling: somebody said so,
# rather than a lookup coming back empty.
STAGE_DIR="${SMOKE_STAGE_DIR:-${REPO_ROOT}/web/dist}"

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

# ── What the deploy built, against what the site is serving ──────────────────
#
# Every other check in this file asks whether the site answers. The two below
# ask whether it is answering with the bytes this deploy produced, and nothing
# else in the repository is in a position to ask that. The unit tests read
# `web/dist` before it is uploaded. `IntegrityPanel` and the power-on self-test
# read the page they are running in, which is why `deployment-check.js` says in
# its own words that a server serving tampered code can serve a tampered
# checker with it. This runs on the machine that made the artifact, fetches over
# the network, and compares — the one vantage point where "served" and "built"
# are two separate things.
#
# It runs post-purge and a failure exits non-zero, so a bad release stops here
# rather than becoming the thing every visitor's browser is checking against.

# Fetch a URL into `_fetch_body` / `_fetch_status`; non-zero on a transport error.
#
# The status matters here in a way it does not for the checks above. `curl`
# succeeds on a 404, and a 404 body compared against a staged file reads as "the
# served copy differs from the built one" when what is true is "there is nothing
# at that path". Those are different failures with different fixes, and a
# refusal has to name the one that happened.
_fetch_body=""
_fetch_status=""
fetch_with_status() {
  local url="$1" raw
  _fetch_body=""
  _fetch_status=""
  raw=$(curl -sS --max-time "$TIMEOUT" --compressed -w $'\n%{http_code}' "$url") || return $?
  _fetch_status="${raw##*$'\n'}"
  # `$( )` drops trailing newlines from both sides of every comparison below, so
  # the served bytes and the staged file are compared on the same footing.
  _fetch_body=$(printf '%s' "${raw%$'\n'*}")
  return 0
}

# "page<TAB>root" pairs from a module-roots pin document on stdin.
#
# The document is written by `web/scripts/write-module-integrity-pin.mjs` with
# `JSON.stringify(doc, null, 2)`, so the indentation is a property of the writer
# and not of a formatter that might change its mind.
pin_roots() {
  awk '
    /^    "[^"]+": \{/ { page = $1; gsub(/^"|":$/, "", page); next }
    /^      "root":/ {
      root = $2
      gsub(/^"|",?$/, "", root)
      if (page != "") print page "\t" root
      page = ""
    }
  '
}

# The pin document, served, against the pin document as built.
#
# `/integrity/module-roots.json` is what every visitor's power-on self-test
# compares its live module root against (`verifyModuleRootAgainstPins`), so it
# is the one file on the site whose job is to be an independent statement about
# the others. A served copy that is not the built one means one of two things,
# and a deploy has to stop for both: the upload or the Front Door purge did not
# take, in which case the pin describes a previous deploy and every visitor's
# POST fails closed on a site that is otherwise fine; or something between the
# storage account and the reader is rewriting the attestation, which is the case
# the whole mechanism exists for and the one an in-page check cannot see.
#
# Byte equality rather than a semantic comparison: the same file was uploaded
# and is being read back, `builtAt` included, and a comparison that tolerated a
# difference would have to decide which differences are benign. None of them are.
check_served_pin_matches_staged() {
  local url="$1" staged="$2"
  printf '  %-48s' "/integrity/module-roots.json (= staged)"

  local want attempt=1 body="" status="" curl_exit=0
  want="$(cat "$staged")"
  while (( attempt <= SMOKE_HTML_RETRIES )); do
    curl_exit=0
    fetch_with_status "${url}?_smoke=$(date +%s)-${attempt}" || curl_exit=$?
    body="$_fetch_body"
    status="$_fetch_status"
    if [[ $curl_exit -eq 0 && "$status" == 2* && "$body" == "$want" ]]; then
      echo "OK (attempt ${attempt})"
      return 0
    fi
    (( attempt == SMOKE_HTML_RETRIES )) && break
    sleep "$SMOKE_HTML_RETRY_SLEEP"
    attempt=$((attempt + 1))
  done

  FAIL=1
  if [[ $curl_exit -ne 0 ]]; then
    echo "FAIL (curl exit $curl_exit — the pin document could not be fetched)"
    echo "      The site is serving pages whose integrity claim cannot be reached, so every"
    echo "      visitor's startup check will report an unreachable pin rather than a match."
    return 1
  fi
  if [[ "$status" != 2* ]]; then
    echo "FAIL (HTTP $status — the site is serving no pin document)"
    echo "      The pages carry a basilisk-integrity-pins meta naming this path. Nothing is"
    echo "      there, so every visitor's startup check refuses rather than verifies."
    echo "      Re-run scripts/deploy-static.sh — it uploads integrity/module-roots*.json."
    return 1
  fi
  echo "FAIL (the served pin is not the one this deploy built)"
  # `builtAt` first: it separates "an edge is still serving the previous
  # deploy" from "this is not a pin we ever wrote", and those want different
  # responses from whoever reads this output.
  echo "      staged  $(grep -oE '"builtAt": "[^"]*"' "$staged" | head -n1)"
  echo "      served  $(printf '%s\n' "$body" | grep -oE '"builtAt": "[^"]*"' | head -n1)"
  local page staged_root served_root
  while IFS=$'\t' read -r page staged_root; do
    served_root="$(printf '%s\n' "$body" | pin_roots | awk -F'\t' -v p="$page" '$1 == p { print $2 }')"
    [[ "$served_root" == "$staged_root" ]] && continue
    # Roots in full. This is the number a person compares against another
    # machine; a truncated one is decorative.
    echo "      ${page}"
    echo "        staged  ${staged_root}"
    echo "        served  ${served_root:-<absent from the served pin>}"
  done < <(pin_roots < "$staged")
  echo "      Re-run scripts/deploy-static.sh — it re-uploads the pin and re-purges Front Door."
  return 1
}

# The set of module hashes a served page pins, against the staged page's.
#
# Comparing `integrity=` tokens rather than folding them into a Merkle root and
# comparing that: the fold already exists in `web/src/lib/module-integrity.js`,
# and this repo's rule about it — stated in `deployment-check.js` — is that two
# implementations of one security check drift, and the one that drifts is the
# one nobody reads. The token set is the *input* to that fold, so an equal set
# is an equal root, and no arithmetic happens twice.
#
# The set covers more than the entry scripts. The external importmap carrying
# the lazy chunks, dynamic imports and module workers is itself one of these
# tokens, and its filename is content-addressed, so the whole module graph rides
# on the sha384 in this list.
check_served_sri_matches_staged() {
  local label="$1" url="$2" staged="$3"
  printf '  %-48s' "$label"
  local curl_exit=0
  fetch_with_status "$url" || curl_exit=$?
  if [[ $curl_exit -ne 0 ]]; then
    echo "FAIL (curl exit $curl_exit)"
    FAIL=1
    return
  fi
  if [[ "$_fetch_status" != 2* ]]; then
    echo "FAIL (HTTP $_fetch_status — this page was staged and is not being served)"
    FAIL=1
    return
  fi

  # `|| true` on both: `grep` exits 1 on no match, and under `set -e` an
  # assignment from a failing substitution ends the script — which is how the
  # empty-set case below, the one that says a comparison would have been
  # vacuous, managed to abort the run silently instead of printing itself.
  local want got
  want=$(grep -oE 'integrity="[^"]*"' "$staged" | sort -u || true)
  got=$(printf '%s\n' "$_fetch_body" | grep -oE 'integrity="[^"]*"' | sort -u || true)

  if [[ -z "$want" ]]; then
    # Not a pass. A staged page with no SRI would make every comparison below
    # trivially true, which is the shape of a check that has stopped checking.
    echo "FAIL (the staged page carries no integrity= attributes)"
    FAIL=1
    return
  fi
  if [[ "$want" == "$got" ]]; then
    echo "OK ($(printf '%s\n' "$want" | wc -l | tr -d ' ') hashes)"
    return
  fi

  FAIL=1
  echo "FAIL (the served page pins different modules than the staged one)"
  local only_staged only_served
  only_staged=$(comm -23 <(printf '%s\n' "$want") <(printf '%s\n' "$got") || true)
  only_served=$(comm -13 <(printf '%s\n' "$want") <(printf '%s\n' "$got") || true)
  # Hashes in full, never a prefix: this is the value someone pastes into a
  # search across the build output to find out which chunk moved.
  if [[ -n "$only_staged" ]]; then printf '      staged only: %s\n' $only_staged; fi
  if [[ -n "$only_served" ]]; then printf '      served only: %s\n' $only_served; fi
  echo "      The browser enforces these hashes, so a served page holding any of them is a"
  echo "      page whose modules refuse to run — or one built from something else."
  echo "      Re-run scripts/deploy-static.sh; if it repeats, the edge is not serving the blob."
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

# 4. The served bytes against the staged ones. After wait_for_sri_html, so the
#    purge has already been waited out once and a mismatch here is a mismatch
#    rather than propagation lag.
STAGED_PIN="${STAGE_DIR}/integrity/module-roots.json"
if [[ "$STAGE_DIR" == "none" ]]; then
  printf '  %-48s' "served bytes = staged bytes"
  echo "DECLINED (SMOKE_STAGE_DIR=none)"
  echo "      This run has nothing to say about whether the site is serving what was built."
elif [[ ! -f "$STAGED_PIN" ]]; then
  # Refusing rather than skipping. A missing staged pin is indistinguishable
  # from a build that did not run the integrity step, and the deploy path
  # always has one — `deploy-static.sh` uploads from this directory minutes
  # earlier. Silence here would retire the check the first time a build layout
  # changed, and nothing would say so.
  printf '  %-48s' "served bytes = staged bytes"
  echo "FAIL (no staged pin at ${STAGED_PIN})"
  echo "      Nothing on this machine says what the deploy built, so the served pin and the"
  echo "      served pages cannot be checked against anything."
  echo "      Run scripts/package-static.sh, point SMOKE_STAGE_DIR at the uploaded directory,"
  echo "      or set SMOKE_STAGE_DIR=none to run the remaining checks without these two."
  FAIL=1
else
  check_served_pin_matches_staged "${BASE_URL}/integrity/module-roots.json" "$STAGED_PIN" || true
  shopt -s nullglob
  staged_pages=("${STAGE_DIR}"/*.html)
  if (( ${#staged_pages[@]} == 0 )); then
    printf '  %-48s' "served pages = staged pages"
    echo "FAIL (no HTML staged in ${STAGE_DIR})"
    FAIL=1
  fi
  for staged_html in "${staged_pages[@]}"; do
    page="$(basename "$staged_html" .html)"
    # `/` is index.html; every other page is served by the extensionless blob
    # that package-static.sh copies beside it, which is the URL a reader uses.
    if [[ "$page" == "index" ]]; then
      served_path="/"
    else
      served_path="/${page}"
    fi
    check_served_sri_matches_staged \
      "${served_path} (SRI set = staged)" \
      "${BASE_URL}${served_path}?${SMOKE_QS}" \
      "$staged_html"
  done
fi

# 5. Clean-URL page aliases — product pages only (Vite rollup inputs).
#    index.html → /search; every other built page → /<name>.
#    Dev/snapshot fixtures under web/ (e.g. tool-card-preview.html) are not
#    in vite.config.js and are not deployed — skip them.
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

# 6. Search API — confirms the API route is live (result set is not validated).
check_status "/api/v1/search?q=test"           "$BASE_URL/api/v1/search?q=test%40example.com"

# 7. The policy a browser computes. `/toolkit` because it is the page that opens
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
