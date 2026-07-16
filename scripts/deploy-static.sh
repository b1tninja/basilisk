#!/usr/bin/env bash
# Upload Vite-built static portal to Azure Storage static website ($web container).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform/cloudshell"

STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-}"
RESOURCE_GROUP="${RESOURCE_GROUP:-}"

if [[ -z "$STORAGE_ACCOUNT" ]]; then
  STORAGE_ACCOUNT="$(cd "$TF_DIR" && terraform output -raw storage_account_name 2>/dev/null || true)"
fi

if [[ -z "$RESOURCE_GROUP" ]]; then
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

az storage blob upload-batch \
  "${storage_args[@]}" \
  --destination '$web' \
  --source "$STAGE" \
  --overwrite \
  --only-show-errors

# Ensure HTML content-types for clean URL blobs and root pages.
for blob in index.html search my-keys key stats; do
  if [[ -f "${STAGE}/${blob}" ]] || [[ -f "${STAGE}/${blob}.html" ]]; then
    src="${STAGE}/${blob}"
    [[ -f "$src" ]] || src="${STAGE}/${blob}.html"
    az storage blob upload \
      "${storage_args[@]}" \
      --container-name '$web' \
      --name "$blob" \
      --file "$src" \
      --content-type "text/html; charset=utf-8" \
      --overwrite \
      --only-show-errors
  fi
done

static_host="$(az storage account show -n "$STORAGE_ACCOUNT" ${RESOURCE_GROUP:+-g "$RESOURCE_GROUP"} --query primaryEndpoints.web -o tsv | sed 's#https://##;s#/$##')"
echo "Static site deployed to https://${static_host}/"
