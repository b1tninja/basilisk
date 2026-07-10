#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
path="${1:-marketplace/package}"
[[ -d "$path" ]] || ./scripts/package-marketplace.sh
az deployment group validate -g basilisk-sandbox -f "$path/mainTemplate.json" -p "@$path/test-params.json"
