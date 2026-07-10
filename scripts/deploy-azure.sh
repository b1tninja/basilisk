#!/usr/bin/env bash
# Deploy Basilisk Azure infrastructure. Tenant/subscription come from `az account show`.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME_PREFIX="${NAME_PREFIX:-basilisk-dev}"
LOCATION="${LOCATION:-}"
MAIL_PROVIDER="${MAIL_PROVIDER:-office365}"
REQUIRE_MANAGER_APPROVAL="${REQUIRE_MANAGER_APPROVAL:-false}"
PARAM="${PARAM:-}"
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
  echo "Azure CLI ('az') not found. Install: https://learn.microsoft.com/cli/azure/install-azure-cli"
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "Not logged in to Azure. Run: az login"
  exit 1
fi

if [[ -n "$SUBSCRIPTION_ID" ]]; then
  az account set --subscription "$SUBSCRIPTION_ID"
fi

TENANT_ID="$(az account show --query tenantId -o tsv)"
SUB_NAME="$(az account show --query name -o tsv)"
SUB_ID="$(az account show --query id -o tsv)"
LOCATION="$(resolve_deploy_location "$NAME_PREFIX" "$LOCATION")"
DEPLOYMENT_NAME="basilisk-$(date +%Y%m%d%H%M%S)"

echo "Subscription: $SUB_NAME ($SUB_ID)"
echo "Tenant:       $TENANT_ID"
echo "Deploying:    $NAME_PREFIX -> ${NAME_PREFIX}-rg ($LOCATION)"

DEPLOY_ARGS=(
  deployment sub create
  --name "$DEPLOYMENT_NAME"
  --location "$LOCATION"
  --template-file infra/main.bicep
)

if [[ -n "$PARAM" ]]; then
  DEPLOY_ARGS+=(--parameters "$PARAM")
else
  DEPLOY_ARGS+=(
    --parameters
    "namePrefix=$NAME_PREFIX"
    "location=$LOCATION"
    "entraTenantId=$TENANT_ID"
    "mailProvider=$MAIL_PROVIDER"
    "requireManagerApproval=$REQUIRE_MANAGER_APPROVAL"
  )
fi

az "${DEPLOY_ARGS[@]}"

RG="$(az deployment sub show --name "$DEPLOYMENT_NAME" --query properties.outputs.resourceGroupName.value -o tsv)"
FN="$(az deployment sub show --name "$DEPLOYMENT_NAME" --query properties.outputs.functionAppName.value -o tsv)"
FD="$(az deployment sub show --name "$DEPLOYMENT_NAME" --query properties.outputs.frontDoorHostName.value -o tsv)"

echo ""
echo "Deployment complete: $DEPLOYMENT_NAME"
echo "  Resource group:  $RG"
echo "  Function app:    $FN"
echo "  Front Door host: $FD"
echo ""
echo "Next steps:"
echo "  1. Authorize Logic App mail connector ($MAIL_PROVIDER) in Azure Portal"
echo "  2. Set Function App BASILISK_BASE_URL to https://$FD"
echo "  3. Publish function code (az functionapp deploy or azd deploy)"
