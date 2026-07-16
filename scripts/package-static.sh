#!/usr/bin/env bash
# Stage static portal files for Azure $web upload (clean URLs without .html suffix).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-${REPO_ROOT}/dist/static}"

rm -rf "$OUT"
mkdir -p "$OUT/css" "$OUT/js" "$OUT/assets"

cp "${REPO_ROOT}/web/static/index.html" "$OUT/index.html"
cp "${REPO_ROOT}/web/static/index.html" "$OUT/search"
cp "${REPO_ROOT}/web/static/my-keys.html" "$OUT/my-keys"
cp "${REPO_ROOT}/web/static/key.html" "$OUT/key"
cp "${REPO_ROOT}/web/static/stats.html" "$OUT/stats"
cp "${REPO_ROOT}/web/static/css/site.css" "$OUT/css/site.css"
cp "${REPO_ROOT}/web/static/js/portal.js" "$OUT/js/portal.js"

if compgen -G "${REPO_ROOT}/docs/assets/basilisk-wordmark*.png" >/dev/null; then
  cp "${REPO_ROOT}"/docs/assets/basilisk-wordmark*.png "$OUT/assets/" 2>/dev/null || true
fi

echo "$OUT"
