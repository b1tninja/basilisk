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
