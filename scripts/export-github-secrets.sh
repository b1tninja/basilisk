#!/usr/bin/env bash
# Set GitHub Actions secrets from Terraform outputs (run after terraform apply).
# Never prints the token secret to the terminal.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform/cloudshell"

if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform not found" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found" >&2
  exit 1
fi

cd "$TF_DIR"

if ! terraform output -json github_actions_secrets >/dev/null 2>&1; then
  echo "No Terraform state / outputs in $TF_DIR — run deploy first." >&2
  exit 1
fi

SECRETS_JSON="$(terraform output -json github_actions_secrets)"
KV_NAME="$(terraform output -raw key_vault_name 2>/dev/null || true)"
RG="$(echo "$SECRETS_JSON" | jq -r '.BASILISK_RESOURCE_GROUP')"
FN="$(echo "$SECRETS_JSON" | jq -r '.BASILISK_FUNCTION_APP_NAME')"
PUBLIC_URL="$(terraform output -raw public_url 2>/dev/null || true)"

echo "# Basilisk GitHub secrets helper"
echo "# Resource group: $RG  Function: $FN  Public URL: $PUBLIC_URL"
echo ""

if [[ -n "$KV_NAME" && "$KV_NAME" != "null" ]] && command -v az >/dev/null 2>&1; then
  if command -v gh >/dev/null 2>&1; then
    echo "Setting BASILISK_TOKEN_SECRET from Key Vault '$KV_NAME' via gh (value not printed)…"
    TOKEN="$(az keyvault secret show --vault-name "$KV_NAME" --name basilisk-token-secret --query value -o tsv)"
    printf '%s' "$TOKEN" | gh secret set BASILISK_TOKEN_SECRET
    unset TOKEN
    echo "BASILISK_TOKEN_SECRET updated in GitHub."
  else
    echo "Install GitHub CLI (gh) and run:"
    echo "  az keyvault secret show --vault-name $KV_NAME --name basilisk-token-secret --query value -o tsv | gh secret set BASILISK_TOKEN_SECRET"
  fi
else
  echo "Key Vault name unavailable or az missing. Fetch the secret manually:"
  echo "  az keyvault secret show --vault-name <kv> --name basilisk-token-secret --query value -o tsv | gh secret set BASILISK_TOKEN_SECRET"
fi

echo ""
echo "Also set AZURE_CREDENTIALS (OIDC federated credentials preferred — see docs/CI.md)."
echo "Optional AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for Route53 custom domain."
echo "Done."
