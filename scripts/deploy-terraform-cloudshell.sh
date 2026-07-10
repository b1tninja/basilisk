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

az functionapp config appsettings set \
  --resource-group "$RG" \
  --name "$FN" \
  --settings "BASILISK_BASE_URL=$FD_URL" \
  --output none

echo ""
echo "Terraform deployment complete."
echo "  Resource group:  $RG"
echo "  Function app:    $FN"
echo "  Front Door URL:  $FD_URL"
echo ""
echo "Next steps:"
echo "  1. Authorize Logic App mail connector ($MAIL_PROVIDER) in Azure Portal"
echo "  2. Publish function code: az functionapp deploy -g $RG -n $FN --src-path <zip> --type zip"
echo "  3. Smoke test: curl $FD_URL/health"
echo "  4. Export GitHub secrets: bash scripts/export-github-secrets.sh"
