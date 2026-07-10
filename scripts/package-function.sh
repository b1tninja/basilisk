#!/usr/bin/env bash
# Build a zip package for az functionapp deploy (Flex Consumption / zip deploy).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-${REPO_ROOT}/basilisk-fn.zip}"

cd "$REPO_ROOT"

if [[ -f "$OUT" ]]; then
  rm -f "$OUT"
fi

zip -r "$OUT" . \
  -x './.git/*' \
  -x './.github/*' \
  -x './.venv/*' \
  -x './tests/*' \
  -x './docker/*' \
  -x './docs/*' \
  -x './scripts/*' \
  -x './infra/*' \
  -x './terraform/*' \
  -x './marketplace/*' \
  -x './web/static/*' \
  -x './dist/*' \
  -x './data/*' \
  -x './*.md' \
  -x './pytest.ini' \
  -x './Makefile' \
  -x './docker-compose*.yml' \
  -x './.env' \
  -x './.env.*' \
  -x './local.settings.json' \
  -x './basilisk-fn.zip' \
  -x './.pytest_cache/*' \
  -x './**/__pycache__/*' \
  >/dev/null

echo "$OUT"
