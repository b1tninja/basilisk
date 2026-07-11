#!/usr/bin/env bash
# GitHub Actions entrypoint: Terraform apply (optional) + function zip deploy + smoke test.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform/cloudshell"

NAME_PREFIX="${NAME_PREFIX:-basilisk-dev}"
LOCATION="${LOCATION:-}"
MAIL_PROVIDER="${MAIL_PROVIDER:-office365}"
AUTO_APPROVE="${AUTO_APPROVE:-true}"
SKIP_TERRAFORM="${SKIP_TERRAFORM:-false}"

resolve_deploy_targets() {
  cd "$TF_DIR"
  if terraform output -raw resource_group_name >/dev/null 2>&1; then
    RG="$(terraform output -raw resource_group_name)"
    FN="$(terraform output -raw function_app_name)"
    FD_URL="$(terraform output -raw public_url 2>/dev/null || terraform output -raw front_door_url)"
    STORAGE_ACCOUNT="$(terraform output -raw storage_account_name 2>/dev/null || true)"
    return
  fi

  RG="${BASILISK_RESOURCE_GROUP:-${NAME_PREFIX}-rg}"
  FN="${BASILISK_FUNCTION_APP_NAME:-${NAME_PREFIX}-fn}"
  FD_URL="${BASILISK_FRONT_DOOR_URL:-}"
  STORAGE_ACCOUNT="${BASILISK_STORAGE_ACCOUNT:-}"

  if [[ -z "$FD_URL" ]]; then
    FD_HOST="$(az functionapp show -g "$RG" -n "$FN" --query "defaultHostName" -o tsv 2>/dev/null || true)"
    if [[ -n "$FD_HOST" ]]; then
      echo "Warning: using function hostname for smoke test; set BASILISK_FRONT_DOOR_URL for Front Door." >&2
      FD_URL="https://${FD_HOST}"
    fi
  fi

  if [[ -z "$FD_URL" ]]; then
    echo "Could not resolve deploy targets. Run Terraform first or set BASILISK_* secrets." >&2
    exit 1
  fi
}

if [[ "$SKIP_TERRAFORM" != "true" ]]; then
  AUTO_APPROVE="$AUTO_APPROVE" \
    NAME_PREFIX="$NAME_PREFIX" \
    LOCATION="$LOCATION" \
    MAIL_PROVIDER="$MAIL_PROVIDER" \
    bash "${REPO_ROOT}/scripts/deploy-terraform-cloudshell.sh"
else
  echo "Skipping Terraform (SKIP_TERRAFORM=true)"
fi

resolve_deploy_targets

echo "Publishing function package to $FN ..."
ZIP="$(bash "${REPO_ROOT}/scripts/package-function.sh")"
# Flex Consumption uses One Deploy; config-zip with remote build is the supported CLI path.
az functionapp deployment source config-zip \
  --resource-group "$RG" \
  --name "$FN" \
  --src "$ZIP" \
  --build-remote true \
  --timeout 600 \
  --output none

if [[ -n "${STORAGE_ACCOUNT:-}" ]]; then
  echo "Deploying static portal to $STORAGE_ACCOUNT ..."
  STORAGE_ACCOUNT="$STORAGE_ACCOUNT" RESOURCE_GROUP="$RG" bash "${REPO_ROOT}/scripts/deploy-static.sh"
else
  echo "Skipping static deploy (storage account unknown)."
fi

echo "Smoke testing $FD_URL ..."
BASE_URL="$FD_URL" bash "${REPO_ROOT}/scripts/smoke-test.sh"

echo ""
echo "Deploy complete."
echo "  Resource group:  $RG"
echo "  Function app:    $FN"
echo "  Front Door URL:  $FD_URL"
