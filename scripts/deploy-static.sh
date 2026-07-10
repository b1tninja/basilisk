#!/usr/bin/env bash
# Upload staged static portal to Azure Storage static website ($web container).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform/cloudshell"

STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-}"
RESOURCE_GROUP="${RESOURCE_GROUP:-}"

if [[ -z "$STORAGE_ACCOUNT" ]] && [[ -f "${TF_DIR}/terraform.tfstate" ]]; then
  STORAGE_ACCOUNT="$(cd "$TF_DIR" && terraform output -raw storage_account_name 2>/dev/null || true)"
fi

if [[ -z "$RESOURCE_GROUP" ]] && [[ -f "${TF_DIR}/terraform.tfstate" ]]; then
  RESOURCE_GROUP="$(cd "$TF_DIR" && terraform output -raw resource_group_name 2>/dev/null || true)"
fi

if [[ -z "$STORAGE_ACCOUNT" ]]; then
  echo "Set STORAGE_ACCOUNT or run from a Terraform-applied workspace." >&2
  exit 1
fi

STAGE="$(bash "${REPO_ROOT}/scripts/package-static.sh")"

echo "Uploading static site to ${STORAGE_ACCOUNT}/\$web ..."

# HTML pages without extension
for blob in search my-keys key; do
  az storage blob upload \
    --account-name "$STORAGE_ACCOUNT" \
    --container-name '$web' \
    --name "$blob" \
    --file "${STAGE}/${blob}" \
    --content-type "text/html; charset=utf-8" \
    --overwrite \
    --auth-mode login \
    --only-show-errors
done

az storage blob upload-batch \
  --account-name "$STORAGE_ACCOUNT" \
  --destination '$web' \
  --source "$STAGE" \
  --pattern "index.html" \
  --content-type "text/html; charset=utf-8" \
  --overwrite \
  --auth-mode login \
  --only-show-errors

az storage blob upload-batch \
  --account-name "$STORAGE_ACCOUNT" \
  --destination '$web' \
  --source "$STAGE" \
  --pattern "css/*" \
  --content-type "text/css" \
  --overwrite \
  --auth-mode login \
  --only-show-errors

az storage blob upload-batch \
  --account-name "$STORAGE_ACCOUNT" \
  --destination '$web' \
  --source "$STAGE" \
  --pattern "js/*" \
  --content-type "application/javascript" \
  --overwrite \
  --auth-mode login \
  --only-show-errors

if [[ -d "${STAGE}/assets" ]] && [[ -n "$(ls -A "${STAGE}/assets" 2>/dev/null || true)" ]]; then
  az storage blob upload-batch \
    --account-name "$STORAGE_ACCOUNT" \
    --destination '$web' \
    --source "$STAGE/assets" \
    --destination-path "assets" \
    --overwrite \
    --auth-mode login \
    --only-show-errors
fi

echo "Static site deployed to https://${STORAGE_ACCOUNT}.z.web.core.windows.net/"
