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

storage_args=(--account-name "$STORAGE_ACCOUNT")
if [[ -n "${RESOURCE_GROUP:-}" ]]; then
  key="$(az storage account keys list -g "$RESOURCE_GROUP" -n "$STORAGE_ACCOUNT" --query "[0].value" -o tsv)"
  storage_args+=(--account-key "$key")
  az storage blob service-properties update \
    "${storage_args[@]}" \
    --static-website \
    --index-document index.html \
    --404-document index.html \
    --only-show-errors
else
  storage_args+=(--auth-mode login)
fi

echo "Uploading static site to ${STORAGE_ACCOUNT}/\$web ..."

# HTML pages without extension
for blob in search my-keys key; do
  az storage blob upload \
    "${storage_args[@]}" \
    --container-name '$web' \
    --name "$blob" \
    --file "${STAGE}/${blob}" \
    --content-type "text/html; charset=utf-8" \
    --overwrite \
    --only-show-errors
done

az storage blob upload \
  "${storage_args[@]}" \
  --container-name '$web' \
  --name index.html \
  --file "${STAGE}/index.html" \
  --content-type "text/html; charset=utf-8" \
  --overwrite \
  --only-show-errors

az storage blob upload \
  "${storage_args[@]}" \
  --container-name '$web' \
  --name css/site.css \
  --file "${STAGE}/css/site.css" \
  --content-type "text/css" \
  --overwrite \
  --only-show-errors

az storage blob upload \
  "${storage_args[@]}" \
  --container-name '$web' \
  --name js/portal.js \
  --file "${STAGE}/js/portal.js" \
  --content-type "application/javascript" \
  --overwrite \
  --only-show-errors

if [[ -d "${STAGE}/assets" ]] && [[ -n "$(ls -A "${STAGE}/assets" 2>/dev/null || true)" ]]; then
  az storage blob upload-batch \
    "${storage_args[@]}" \
    --destination '$web' \
    --source "$STAGE/assets" \
    --destination-path "assets" \
    --overwrite \
    --only-show-errors
fi

static_host="$(az storage account show -n "$STORAGE_ACCOUNT" ${RESOURCE_GROUP:+-g "$RESOURCE_GROUP"} --query primaryEndpoints.web -o tsv | sed 's#https://##;s#/$##')"
echo "Static site deployed to https://${static_host}/"
