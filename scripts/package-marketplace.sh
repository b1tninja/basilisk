#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=marketplace/package
rm -rf "$out"
mkdir -p "$out"
az bicep build --file infra/main.bicep --outfile "$out/mainTemplate.json"
cp marketplace/createUiDefinition.json marketplace/test-params.json "$out/"
(cd "$out" && zip -r ../basilisk-marketplace.zip .)
echo "Packaged marketplace/basilisk-marketplace.zip"
