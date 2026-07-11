#!/usr/bin/env bash
# Deploy Basilisk with Terraform from Azure Cloud Shell (or any host with az + terraform).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform/cloudshell"

NAME_PREFIX="${NAME_PREFIX:-basilisk-dev}"
LOCATION="${LOCATION:-}"
MAIL_PROVIDER="${MAIL_PROVIDER:-office365}"
AUTO_APPROVE="${AUTO_APPROVE:-false}"
SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-}"

resolve_deploy_location() {
  local prefix="$1"
  local requested="$2"
  local rg_name="${prefix}-rg"
  local existing configured

  if [[ -n "$requested" ]]; then
    printf '%s' "$requested"
    return
  fi

  existing="$(az group show --name "$rg_name" --query location -o tsv 2>/dev/null || true)"
  if [[ -n "$existing" ]]; then
    echo "Using location from existing resource group: $rg_name -> $existing" >&2
    printf '%s' "$existing"
    return
  fi

  configured="$(az config get defaults.location -o tsv 2>/dev/null || true)"
  if [[ -n "$configured" ]]; then
    echo "Using az config defaults.location: $configured" >&2
    printf '%s' "$configured"
    return
  fi

  echo "No location specified; falling back to eastus (override with LOCATION=...)" >&2
  printf '%s' "eastus"
}

if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI ('az') not found."
  exit 1
fi

if ! command -v terraform >/dev/null 2>&1; then
  echo "Terraform not found."
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "Not logged in to Azure. Run: az login"
  exit 1
fi

if [[ -n "$SUBSCRIPTION_ID" ]]; then
  az account set --subscription "$SUBSCRIPTION_ID"
fi

LOCATION="$(resolve_deploy_location "$NAME_PREFIX" "$LOCATION")"
TENANT_ID="$(az account show --query tenantId -o tsv)"
SUB_NAME="$(az account show --query name -o tsv)"

echo "Subscription: $SUB_NAME"
echo "Tenant:       $TENANT_ID"
echo "Name prefix:  $NAME_PREFIX"
echo "Location:     $LOCATION"

export TF_VAR_name_prefix="$NAME_PREFIX"
export TF_VAR_location="$LOCATION"
export TF_VAR_mail_provider="$MAIL_PROVIDER"

cd "$TF_DIR"
terraform init -input=false

RG_NAME="${NAME_PREFIX}-rg"
HAS_RG_STATE=false
if terraform state show -no-color "module.basilisk.azurerm_resource_group.basilisk" >/dev/null 2>&1; then
  HAS_RG_STATE=true
fi

if [[ "$HAS_RG_STATE" != "true" ]] && az group show --name "$RG_NAME" >/dev/null 2>&1; then
  echo "Existing Azure resource group $RG_NAME found without Terraform state — importing ..."
  IMPORT_TERRAFORM="${IMPORT_TERRAFORM:-true}"
  if [[ "$IMPORT_TERRAFORM" == "true" ]]; then
    NAME_PREFIX="$NAME_PREFIX" LOCATION="$LOCATION" MAIL_PROVIDER="$MAIL_PROVIDER" \
      SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-}" \
      bash "${REPO_ROOT}/scripts/import-terraform-existing.sh"
  else
    echo "Set IMPORT_TERRAFORM=true to adopt existing resources, or SKIP_TERRAFORM=true to deploy code only." >&2
    exit 1
  fi
fi

FN_NAME="${NAME_PREFIX}-fn"
if [[ -z "${TF_VAR_existing_token_secret:-}" ]] && az functionapp show -g "$RG_NAME" -n "$FN_NAME" >/dev/null 2>&1; then
  TOKEN_SECRET="$(az functionapp config appsettings list -g "$RG_NAME" -n "$FN_NAME" \
    --query "[?name=='BASILISK_TOKEN_SECRET'].value | [0]" -o tsv 2>/dev/null || true)"
  if [[ -n "$TOKEN_SECRET" && "$TOKEN_SECRET" != "null" ]]; then
    export TF_VAR_existing_token_secret="$TOKEN_SECRET"
    echo "Using existing BASILISK_TOKEN_SECRET from $FN_NAME"
  fi
fi

adopt_missing_terraform_resources() {
  local mod="module.basilisk"
  local sub storage_name sa_id storage_key

  sub="$(az account show --query id -o tsv)"
  storage_name="$(echo "${NAME_PREFIX}store" | tr '[:upper:]' '[:lower:]' | tr -d '-' | cut -c1-24)"
  sa_id="/subscriptions/${sub}/resourceGroups/${RG_NAME}/providers/Microsoft.Storage/storageAccounts/${storage_name}"

  if ! terraform state show -no-color "${mod}.azurerm_storage_container_immutability_policy.certs[0]" >/dev/null 2>&1; then
    storage_key="$(az storage account keys list -g "$RG_NAME" -n "$storage_name" --query "[0].value" -o tsv 2>/dev/null || true)"
    if [[ -n "$storage_key" ]] && az storage container immutability-policy show \
      --account-name "$storage_name" \
      --account-key "$storage_key" \
      --container-name certs >/dev/null 2>&1; then
      echo "Adopting existing certs immutability policy into Terraform state ..."
      terraform import -input=false "${mod}.azurerm_storage_container_immutability_policy.certs[0]" \
        "${sa_id}/blobServices/default/containers/certs/immutabilityPolicies/default"
    fi
  fi
}

adopt_missing_terraform_resources

PLAN_ARGS=(-input=false -out=tfplan)
if [[ -f terraform.tfvars ]]; then
  PLAN_ARGS+=(-var-file=terraform.tfvars)
fi

terraform plan "${PLAN_ARGS[@]}"

if [[ "$AUTO_APPROVE" == "true" ]]; then
  terraform apply -input=false -auto-approve tfplan
else
  terraform apply -input=false tfplan
fi

RG="$(terraform output -raw resource_group_name)"
FN="$(terraform output -raw function_app_name)"
FD_URL="$(terraform output -raw front_door_url)"
STORAGE="$(terraform output -raw storage_account_name 2>/dev/null || true)"

az functionapp config appsettings set \
  --resource-group "$RG" \
  --name "$FN" \
  --settings "BASILISK_BASE_URL=$FD_URL" \
  --output none

if [[ -n "$STORAGE" ]] && [[ -f "${REPO_ROOT}/scripts/deploy-static.sh" ]]; then
  echo "Uploading static portal to $STORAGE ..."
  STORAGE_ACCOUNT="$STORAGE" RESOURCE_GROUP="$RG" bash "${REPO_ROOT}/scripts/deploy-static.sh"
fi

echo ""
echo "Terraform deployment complete."
echo "  Resource group:     $RG"
echo "  Function app:       $FN"
echo "  Front Door URL:     $FD_URL"
if [[ -n "$STORAGE" ]]; then
  STATIC_URL="$(terraform output -raw static_website_url 2>/dev/null || true)"
  echo "  Static website URL: ${STATIC_URL:-https://${STORAGE}.z.web.core.windows.net}"
fi
echo ""
echo "Next steps:"
echo "  1. Authorize Logic App mail connector ($MAIL_PROVIDER) in Azure Portal"
echo "  2. Publish function code (if not already): bash scripts/deploy-github-actions.sh with SKIP_TERRAFORM=true"
echo "  3. Smoke test: curl $FD_URL/health && curl $FD_URL/"
echo "  4. Export GitHub secrets: bash scripts/export-github-secrets.sh"
