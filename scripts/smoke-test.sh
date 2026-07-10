#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${BASE_URL:-http://localhost:8080}"
curl -fsS "$BASE_URL/health" >/dev/null
curl -fsS "$BASE_URL/pks/lookup?op=stats" >/dev/null
echo "Smoke test OK: $BASE_URL"
