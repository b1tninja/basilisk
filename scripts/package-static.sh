#!/usr/bin/env bash
# Build the Vite portal and print the dist directory path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WEB_DIR="${REPO_ROOT}/web"
OUT="${WEB_DIR}/dist"

if [[ ! -f "${WEB_DIR}/package.json" ]]; then
  echo "Missing web/package.json" >&2
  exit 1
fi

if [[ ! -d "${WEB_DIR}/node_modules" ]]; then
  (cd "$WEB_DIR" && npm ci) >&2
fi

(cd "$WEB_DIR" && npm run build) >&2

# Strip inline importmap scripts so CSP can stay script-src 'self' (no unsafe-inline).
# Script/link integrity attributes from vite-plugin-sri-gen remain intact.
python - "$OUT" >&2 <<'PY'
from pathlib import Path
import re
import sys
dist = Path(sys.argv[1])
pat = re.compile(r'<script type="importmap">\{.*?\}</script>', re.DOTALL)
for html in dist.glob("*.html"):
    text = html.read_text(encoding="utf-8")
    cleaned = pat.sub("", text)
    if cleaned != text:
        html.write_text(cleaned, encoding="utf-8")
        print(f"stripped importmap: {html.name}")
PY

# Clean URL aliases without .html suffix (Azure static website / Front Door).
# index.html is served at / and also aliased as /search; every other *.html
# page gets a matching extensionless blob so /page resolves without a 404.
cp "${OUT}/index.html" "${OUT}/search"
shopt -s nullglob
for html in "${OUT}"/*.html; do
  base="$(basename "$html" .html)"
  [[ "$base" == "index" ]] && continue
  cp "$html" "${OUT}/${base}"
done

# Only the dist path is printed to stdout — callers capture it with $().
echo "$OUT"
