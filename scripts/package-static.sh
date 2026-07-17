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
cp "${OUT}/index.html" "${OUT}/search"
cp "${OUT}/my-keys.html" "${OUT}/my-keys"
cp "${OUT}/key.html" "${OUT}/key"
cp "${OUT}/stats.html" "${OUT}/stats"
cp "${OUT}/compose.html" "${OUT}/compose"
cp "${OUT}/decrypt.html" "${OUT}/decrypt"

# Only the dist path is printed to stdout — callers capture it with $().
echo "$OUT"
