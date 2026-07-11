#!/usr/bin/env bash
# One-time setup for durable Terraform remote state (GitHub Actions + local).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME_PREFIX="${NAME_PREFIX:-basilisk-dev}"
LOCATION="${LOCATION:-eastus}"
USE_APP_STORAGE=false
DEDICATED_SA="${TFSTATE_STORAGE_ACCOUNT:-basilisktfstate}"
RG_DEDICATED="${TFSTATE_RESOURCE_GROUP:-basilisk-tfstate-rg}"
CONTAINER="${TFSTATE_CONTAINER:-tfstate}"
CLOUDSHELL_SHARE="${CLOUDSHELL_SHARE:-cloudshell}"
GITHUB_SP_CLIENT_ID="${GITHUB_SP_CLIENT_ID:-}"
MOUNT_CLOUDDRIVE=false

usage() {
  cat <<EOF
Usage: bootstrap-tfstate.sh [--use-app-storage] [--name-prefix PREFIX] [--mount-clouddrive]

Options:
  --use-app-storage   Store state in the existing app storage account ({prefix}store).
                      Recommended when infrastructure already exists.
  --name-prefix       Resource prefix (default: basilisk-dev)
  --mount-clouddrive  In Azure Cloud Shell, mount \$HOME to this storage account (file share).

Dedicated mode (default): creates $RG_DEDICATED + $DEDICATED_SA
App storage mode: creates tfstate container on {prefix}store in {prefix}-rg

After bootstrap, migrate local state (if any):
  NAME_PREFIX=$NAME_PREFIX bash scripts/terraform-init.sh

GitHub Actions and Cloud Shell then share the same blob: {prefix}.tfstate
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --use-app-storage) USE_APP_STORAGE=true; shift ;;
    --name-prefix) NAME_PREFIX="$2"; shift 2 ;;
    --mount-clouddrive) MOUNT_CLOUDDRIVE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if ! command -v az >/dev/null 2>&1; then
  echo "Requires Azure CLI (az login)." >&2
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "Run: az login" >&2
  exit 1
fi

SUB="$(az account show --query id -o tsv)"
APP_RG="${NAME_PREFIX}-rg"
APP_SA="$(echo "${NAME_PREFIX}store" | tr '[:upper:]' '[:lower:]' | tr -d '-' | cut -c1-24)"

if [[ "$USE_APP_STORAGE" == "true" ]]; then
  TFSTATE_RESOURCE_GROUP="$APP_RG"
  TFSTATE_STORAGE_ACCOUNT="$APP_SA"
  if ! az storage account show -g "$APP_RG" -n "$APP_SA" >/dev/null 2>&1; then
    echo "App storage account $APP_SA not found in $APP_RG. Deploy infrastructure first or use dedicated mode." >&2
    exit 1
  fi
  echo "Using app storage account: $APP_SA ($APP_RG)"
else
  TFSTATE_RESOURCE_GROUP="$RG_DEDICATED"
  TFSTATE_STORAGE_ACCOUNT="$DEDICATED_SA"
  if ! az group show --name "$RG_DEDICATED" >/dev/null 2>&1; then
    echo "Creating resource group $RG_DEDICATED ..."
    az group create --name "$RG_DEDICATED" --location "$LOCATION" --output none
  fi
  if ! az storage account show -g "$RG_DEDICATED" -n "$DEDICATED_SA" >/dev/null 2>&1; then
    echo "Creating storage account $DEDICATED_SA ..."
    az storage account create \
      --resource-group "$RG_DEDICATED" \
      --name "$DEDICATED_SA" \
      --location "$LOCATION" \
      --sku Standard_LRS \
      --encryption-services blob \
      --min-tls-version TLS1_2 \
      --allow-blob-public-access false \
      --output none
  fi
  echo "Dedicated tfstate storage: $DEDICATED_SA ($RG_DEDICATED)"
fi

SA_ID="/subscriptions/${SUB}/resourceGroups/${TFSTATE_RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/${TFSTATE_STORAGE_ACCOUNT}"

echo "Creating container $CONTAINER (if missing) ..."
az storage container create \
  --name "$CONTAINER" \
  --account-name "$TFSTATE_STORAGE_ACCOUNT" \
  --auth-mode login \
  --output none

echo "Creating Cloud Shell file share $CLOUDSHELL_SHARE (if missing) ..."
az storage share-rm create \
  --name "$CLOUDSHELL_SHARE" \
  --storage-account "$TFSTATE_STORAGE_ACCOUNT" \
  --quota 5 \
  --output none 2>/dev/null \
  || az storage share create \
    --name "$CLOUDSHELL_SHARE" \
    --account-name "$TFSTATE_STORAGE_ACCOUNT" \
    --quota 5 \
    --auth-mode login \
    --output none 2>/dev/null \
  || echo "  (file share skipped — may already exist or need Storage File Data SMB Contributor)"

grant_blob_contributor() {
  local assignee="$1"
  local label="$2"
  if [[ -z "$assignee" || "$assignee" == "null" ]]; then
    return 0
  fi
  if az role assignment list --scope "$SA_ID" --assignee "$assignee" \
    --query "[?roleDefinitionName=='Storage Blob Data Contributor'] | length(@)" -o tsv 2>/dev/null | grep -q '^[1-9]'; then
    echo "  $label already has Storage Blob Data Contributor"
    return 0
  fi
  echo "Granting Storage Blob Data Contributor to $label ..."
  az role assignment create \
    --role "Storage Blob Data Contributor" \
    --assignee "$assignee" \
    --scope "$SA_ID" \
    --output none
}

CALLER_OID="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
grant_blob_contributor "$CALLER_OID" "signed-in user"

if [[ -n "$GITHUB_SP_CLIENT_ID" ]]; then
  SP_OID="$(az ad sp show --id "$GITHUB_SP_CLIENT_ID" --query id -o tsv 2>/dev/null || true)"
  grant_blob_contributor "$SP_OID" "GitHub SP ($GITHUB_SP_CLIENT_ID)"
else
  echo ""
  echo "Tip: re-run with GITHUB_SP_CLIENT_ID=<clientId from AZURE_CREDENTIALS> to grant the deploy SP."
fi

export TFSTATE_RESOURCE_GROUP TFSTATE_STORAGE_ACCOUNT
export TFSTATE_CONTAINER="${CONTAINER}"
export TFSTATE_KEY="${NAME_PREFIX}.tfstate"
export NAME_PREFIX

echo ""
echo "Initializing Terraform with remote backend ..."
bash "${REPO_ROOT}/scripts/terraform-init.sh"

if [[ "$MOUNT_CLOUDDRIVE" == "true" ]] && command -v clouddrive >/dev/null 2>&1; then
  echo ""
  echo "Mounting Azure Cloud Shell home to $TFSTATE_STORAGE_ACCOUNT ..."
  if clouddrive mount -s "$TFSTATE_STORAGE_ACCOUNT" -g "$TFSTATE_RESOURCE_GROUP"; then
    echo "Cloud Shell drive mounted. Re-open Cloud Shell or cd ~ to use persistent \$HOME on basilisk storage."
  else
    echo "clouddrive mount failed — run manually (see below)." >&2
  fi
fi

cat <<EOF

Remote state ready (shared by GitHub Actions + Cloud Shell).

  Resource group:     $TFSTATE_RESOURCE_GROUP
  Storage account:    $TFSTATE_STORAGE_ACCOUNT
  Terraform state:    blob://$CONTAINER/${NAME_PREFIX}.tfstate
  Cloud Shell files:  file share $CLOUDSHELL_SHARE (optional \$HOME mount)

GitHub Actions (optional repository variables):
  TFSTATE_STORAGE_ACCOUNT = $TFSTATE_STORAGE_ACCOUNT
  TFSTATE_RESOURCE_GROUP  = $TFSTATE_RESOURCE_GROUP

Azure Cloud Shell — mount persistent \$HOME to the same account (one-time per user):
  clouddrive mount -s $TFSTATE_STORAGE_ACCOUNT -g $TFSTATE_RESOURCE_GROUP

Or re-run: bash scripts/bootstrap-tfstate.sh --use-app-storage --mount-clouddrive

If local terraform.tfstate exists, migrate once:
  cd terraform/cloudshell && terraform init -migrate-state -backend-config=backend.hcl -reconfigure

Then commit only code — state lives in Azure Blob, not the runner cache.
EOF
