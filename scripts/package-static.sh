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

# Integrity contract (do not weaken):
#   - Entry scripts/styles/modulepreloads carry integrity= from vite-plugin-sri-gen.
#   - Module-graph / worker SRI lives in an *external* importmap JSON under
#     /importmaps/ (see web/scripts/externalize-importmaps.js). CSP is
#     script-src 'self' — never strip those maps; browsers refuse to load a
#     module whose bytes ≠ the hash (CDN cache skew or tampering). Mixing old
#     and new chunks must fail closed.
python - "$OUT" >&2 <<'PY'
from pathlib import Path
import sys

dist = Path(sys.argv[1])
errors = []
html_files = list(dist.glob("*.html"))
if not html_files:
    errors.append("no HTML files in dist/")

for html in html_files:
    text = html.read_text(encoding="utf-8")
    if 'type="importmap"' not in text and "type='importmap'" not in text:
        errors.append(f"{html.name}: missing importmap (module-graph SRI)")
    if "<script type=\"importmap\">{" in text:
        errors.append(
            f"{html.name}: inline importmap still present — "
            "externalize-importmaps plugin did not run"
        )
    if "integrity=" not in text:
        errors.append(f"{html.name}: missing integrity= attributes")

importmaps = list((dist / "importmaps").glob("importmap-*.json")) if (dist / "importmaps").is_dir() else []
if not importmaps:
    errors.append("no /importmaps/importmap-*.json files written")

if errors:
    print("Integrity packaging checks FAILED:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)

print(
    f"integrity OK: {len(html_files)} HTML page(s), "
    f"{len(importmaps)} external importmap(s)"
)
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
