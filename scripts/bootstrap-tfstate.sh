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
GITHUB_SP_NAME="${GITHUB_SP_NAME:-basilisk-github-deploy}"
MOUNT_CLOUDDRIVE=false

resolve_github_sp_client_id() {
  if [[ -n "${GITHUB_SP_CLIENT_ID:-}" ]]; then
    printf '%s' "$GITHUB_SP_CLIENT_ID"
    return 0
  fi
  local app_id
  app_id="$(az ad sp list --display-name "$GITHUB_SP_NAME" --query "[0].appId" -o tsv 2>/dev/null || true)"
  if [[ -z "$app_id" || "$app_id" == "null" ]]; then
    app_id="$(az ad app list --display-name "$GITHUB_SP_NAME" --query "[0].appId" -o tsv 2>/dev/null || true)"
  fi
  if [[ -z "$app_id" || "$app_id" == "null" ]]; then
    return 1
  fi
  printf '%s' "$app_id"
}

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

if GITHUB_SP_CLIENT_ID="$(resolve_github_sp_client_id)"; then
  echo "GitHub deploy SP: $GITHUB_SP_NAME ($GITHUB_SP_CLIENT_ID)"
  SP_OID="$(az ad sp show --id "$GITHUB_SP_CLIENT_ID" --query id -o tsv 2>/dev/null || true)"
  grant_blob_contributor "$SP_OID" "GitHub SP ($GITHUB_SP_CLIENT_ID)"
else
  echo ""
  echo "Tip: create the deploy SP (see docs/CI.md), or set GITHUB_SP_CLIENT_ID explicitly:"
  echo "  clientId=\$(az ad sp list --display-name $GITHUB_SP_NAME --query \"[0].appId\" -o tsv)"
  echo "  GITHUB_SP_CLIENT_ID=\$clientId bash scripts/bootstrap-tfstate.sh --use-app-storage"
fi

export TFSTATE_RESOURCE_GROUP TFSTATE_STORAGE_ACCOUNT
export TFSTATE_CONTAINER="${CONTAINER}"
export TFSTATE_KEY="${NAME_PREFIX}.tfstate"
export NAME_PREFIX

echo ""
echo "Waiting 30s for RBAC role assignments to propagate ..."
sleep 30

echo "Initializing Terraform with remote backend ..."
bash "${REPO_ROOT}/scripts/terraform-init.sh"

if [[ "$MOUNT_CLOUDDRIVE" == "true" ]]; then
  echo ""
  if command -v clouddrive >/dev/null 2>&1; then
    echo "Mounting Cloud Shell \$HOME to $TFSTATE_STORAGE_ACCOUNT (share: $CLOUDSHELL_SHARE) ..."
    # clouddrive mount: -s=subscription -g=resource-group -n=storage-account -f=file-share
    if clouddrive mount \
        -s "$SUB" \
        -g "$TFSTATE_RESOURCE_GROUP" \
        -n "$TFSTATE_STORAGE_ACCOUNT" \
        -f "$CLOUDSHELL_SHARE"; then
      echo "Mounted. Re-open Cloud Shell to start using \$HOME on $TFSTATE_STORAGE_ACCOUNT."
    else
      echo "clouddrive mount failed — run manually:" >&2
      echo "  clouddrive mount -s $SUB -g $TFSTATE_RESOURCE_GROUP -n $TFSTATE_STORAGE_ACCOUNT -f $CLOUDSHELL_SHARE" >&2
    fi
  else
    echo "Not in Azure Cloud Shell — skipping clouddrive mount."
    echo "To mount from Cloud Shell, run:"
    echo "  clouddrive mount -s $SUB -g $TFSTATE_RESOURCE_GROUP -n $TFSTATE_STORAGE_ACCOUNT -f $CLOUDSHELL_SHARE"
  fi
fi

cat <<EOF

Done. One storage account now serves everything:

  Storage account:  $TFSTATE_STORAGE_ACCOUNT  ($TFSTATE_RESOURCE_GROUP)
  ├── \$web          static portal (managed by Terraform)
  ├── tfstate/      Terraform state blob — shared by GitHub Actions + Cloud Shell
  │   └── ${NAME_PREFIX}.tfstate
  └── $CLOUDSHELL_SHARE/      Cloud Shell \$HOME file share

GitHub Actions:  state auto-detected from $TFSTATE_STORAGE_ACCOUNT (no extra secrets needed)
Cloud Shell:     persistent \$HOME via clouddrive mount (one-time per user)

To mount Cloud Shell \$HOME (if not done above):
  clouddrive mount -s $SUB -g $TFSTATE_RESOURCE_GROUP -n $TFSTATE_STORAGE_ACCOUNT -f $CLOUDSHELL_SHARE

After mounting, re-open Cloud Shell, clone the repo into \$HOME, and deploy:
  git clone https://github.com/b1tninja/basilisk.git ~/basilisk && cd ~/basilisk
  AUTO_APPROVE=true bash scripts/deploy-terraform-cloudshell.sh

GitHub Actions (optional repository variables to override auto-detect):
  TFSTATE_STORAGE_ACCOUNT = $TFSTATE_STORAGE_ACCOUNT
  TFSTATE_RESOURCE_GROUP  = $TFSTATE_RESOURCE_GROUP
EOF
