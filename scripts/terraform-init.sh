#!/usr/bin/env bash
# terraform init with optional Azure Blob remote state (durable across GitHub Actions runners).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform/cloudshell"

NAME_PREFIX="${NAME_PREFIX:-basilisk-dev}"
TFSTATE_RESOURCE_GROUP="${TFSTATE_RESOURCE_GROUP:-}"
TFSTATE_STORAGE_ACCOUNT="${TFSTATE_STORAGE_ACCOUNT:-}"
TFSTATE_CONTAINER="${TFSTATE_CONTAINER:-tfstate}"
TFSTATE_KEY="${TFSTATE_KEY:-${NAME_PREFIX}.tfstate}"
TFSTATE_USE_AZUREAD_AUTH="${TFSTATE_USE_AZUREAD_AUTH:-true}"

storage_name_from_prefix() {
  local prefix="$1"
  echo "${prefix}store" | tr '[:upper:]' '[:lower:]' | tr -d '-' | cut -c1-24
}

# GitHub Actions and Azure Cloud Shell should share the same remote state when possible.
is_cloud_shell() {
  [[ -n "${ACC_CLOUD:-}" ]] \
    || [[ "${AZUREPS_HOST_ENVIRONMENT:-}" == *cloud* ]] \
    || [[ -f /usr/bin/cloud-shell-entry ]] \
    || grep -qi 'cloud shell' /etc/motd 2>/dev/null
}

is_durable_state_host() {
  [[ -n "${GITHUB_ACTIONS:-}" ]] || is_cloud_shell
}

resolve_remote_backend() {
  local prefix="$1"
  local rg="${TFSTATE_RESOURCE_GROUP:-${prefix}-rg}"
  local storage="${TFSTATE_STORAGE_ACCOUNT:-$(storage_name_from_prefix "$prefix")}"

  if [[ -z "${TFSTATE_STORAGE_ACCOUNT:-}" ]] && is_durable_state_host; then
    if ! az storage account show -g "$rg" -n "$storage" >/dev/null 2>&1; then
      echo "Remote state: storage account $storage not found in $rg (first deploy?). Using local state for this run." >&2
      return 1
    fi
    local host="shared host"
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
      host="GitHub Actions"
    elif is_cloud_shell; then
      host="Cloud Shell"
    fi
    echo "Remote state ($host): using $storage in $rg" >&2
  elif [[ -z "${TFSTATE_STORAGE_ACCOUNT:-}" ]]; then
    return 1
  fi

  TFSTATE_RESOURCE_GROUP="$rg"
  TFSTATE_STORAGE_ACCOUNT="$storage"
  return 0
}

ensure_tfstate_container() {
  if ! az storage container show \
    --name "$TFSTATE_CONTAINER" \
    --account-name "$TFSTATE_STORAGE_ACCOUNT" \
    --auth-mode login >/dev/null 2>&1; then
    echo "Creating blob container $TFSTATE_CONTAINER on $TFSTATE_STORAGE_ACCOUNT ..."
    az storage container create \
      --name "$TFSTATE_CONTAINER" \
      --account-name "$TFSTATE_STORAGE_ACCOUNT" \
      --auth-mode login \
      --output none
  fi
}

write_backend_hcl() {
  local path="${TF_DIR}/backend.hcl"
  if [[ -n "${GITHUB_ACTIONS:-}" ]] && [[ -z "${ARM_CLIENT_ID:-}" ]]; then
    # Service principal via azure/login cannot use CLI auth for the backend; use account key.
    local access_key
    access_key="$(az storage account keys list \
      --resource-group "$TFSTATE_RESOURCE_GROUP" \
      --account-name "$TFSTATE_STORAGE_ACCOUNT" \
      --query "[0].value" -o tsv)"
    cat >"$path" <<EOF
resource_group_name  = "${TFSTATE_RESOURCE_GROUP}"
storage_account_name = "${TFSTATE_STORAGE_ACCOUNT}"
container_name       = "${TFSTATE_CONTAINER}"
key                  = "${TFSTATE_KEY}"
access_key           = "${access_key}"
EOF
    echo "Wrote $path (key=${TFSTATE_KEY}, auth=access_key)"
    return
  fi

  cat >"$path" <<EOF
resource_group_name  = "${TFSTATE_RESOURCE_GROUP}"
storage_account_name = "${TFSTATE_STORAGE_ACCOUNT}"
container_name       = "${TFSTATE_CONTAINER}"
key                  = "${TFSTATE_KEY}"
use_azuread_auth     = ${TFSTATE_USE_AZUREAD_AUTH}
EOF
  echo "Wrote $path (key=${TFSTATE_KEY}, auth=azuread)"
}

cd "$TF_DIR"

INIT_ARGS=(-input=false)
if [[ -f terraform.tfvars ]]; then
  INIT_ARGS+=(-var-file=terraform.tfvars)
fi

if resolve_remote_backend "$NAME_PREFIX"; then
  ensure_tfstate_container
  write_backend_hcl
  if [[ -f terraform.tfstate ]]; then
    echo "Migrating local state to Azure Blob backend ..."
    INIT_ARGS+=(-migrate-state)
  fi
  terraform init "${INIT_ARGS[@]}" -backend-config=backend.hcl -reconfigure
else
  echo "Local state mode (-backend=false). Run scripts/bootstrap-tfstate.sh for durable CI state." >&2
  terraform init "${INIT_ARGS[@]}" -backend=false
fi
