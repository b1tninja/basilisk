#!/usr/bin/env bash
# Build a zip package for az functionapp deploy (Flex Consumption / zip deploy).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-${REPO_ROOT}/basilisk-fn.zip}"

cd "$REPO_ROOT"

if [[ -f "$OUT" ]]; then
  rm -f "$OUT"
fi

# web/dist ships INSIDE the package. It was excluded while Front Door routed
# everything outside /pks, /api, /claim, /.auth and /health to the blob $web
# container, so the portal never came from here. Without Front Door nothing
# merges those two origins under one hostname: a portal on the storage
# endpoint would be a different origin from the API it calls and from the
# Easy Auth cookie it needs. Flask serves it instead, which also restores the
# security headers on it -- blob storage cannot add a response header, and
# the Front Door rule that used to add them goes away with the profile.
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
  -x './web/node_modules/*' \
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
