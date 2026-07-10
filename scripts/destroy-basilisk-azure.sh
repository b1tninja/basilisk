#!/usr/bin/env bash
# Delete Basilisk Azure resource group and all contained resources.
set -euo pipefail

NAME_PREFIX="${NAME_PREFIX:-basilisk-dev}"
FORCE="${FORCE:-false}"
RG_NAME="${NAME_PREFIX}-rg"

if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI ('az') not found."
  exit 1
fi

if [[ "$(az group exists --name "$RG_NAME" -o tsv)" != "true" ]]; then
  echo "Resource group not found: $RG_NAME"
  exit 0
fi

echo "Resources in $RG_NAME:"
az resource list -g "$RG_NAME" --query "[].{name:name,type:type}" -o table

if [[ "$FORCE" != "true" ]]; then
  read -r -p "Delete resource group '$RG_NAME' and all contents? [y/N] " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
  fi
fi

echo "Deleting $RG_NAME ..."
az group delete --name "$RG_NAME" --yes --no-wait
echo "Delete initiated. Wait a minute, then re-run terraform apply."
