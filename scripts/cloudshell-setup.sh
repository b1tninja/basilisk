#!/usr/bin/env bash
# Azure Cloud Shell entrypoint: clone repo, shared remote state, deploy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME_PREFIX="${NAME_PREFIX:-basilisk-dev}"
REPO_URL="${REPO_URL:-}"
WORK_DIR="${WORK_DIR:-$HOME/basilisk}"
MOUNT_CLOUDDRIVE="${MOUNT_CLOUDDRIVE:-false}"

is_cloud_shell() {
  [[ -n "${ACC_CLOUD:-}" ]] \
    || [[ "${AZUREPS_HOST_ENVIRONMENT:-}" == *cloud* ]] \
    || [[ -f /usr/bin/cloud-shell-entry ]] \
    || grep -qi 'cloud shell' /etc/motd 2>/dev/null
}

usage() {
  cat <<EOF
Usage: cloudshell-setup.sh [options]

Prepare Azure Cloud Shell to deploy Basilisk with the same remote Terraform state as GitHub Actions.

Options (environment variables):
  REPO_URL=https://github.com/you/basilisk.git   Clone if \$WORK_DIR missing
  WORK_DIR=\$HOME/basilisk                         Project directory
  NAME_PREFIX=basilisk-dev
  MOUNT_CLOUDDRIVE=true                            Mount \$HOME to app storage (one-time)

Typical first-time flow in https://shell.azure.com :

  git clone https://github.com/you/basilisk.git ~/basilisk && cd ~/basilisk
  GITHUB_SP_CLIENT_ID=<clientId> bash scripts/bootstrap-tfstate.sh --use-app-storage --mount-clouddrive
  AUTO_APPROVE=true ./scripts/deploy-terraform-cloudshell.sh

Subsequent Cloud Shell sessions (same shared state as CI):

  cd ~/basilisk && git pull
  AUTO_APPROVE=true ./scripts/deploy-terraform-cloudshell.sh
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if ! is_cloud_shell; then
  echo "Warning: not running in Azure Cloud Shell — continuing anyway." >&2
fi

if ! az account show >/dev/null 2>&1; then
  echo "Run: az login" >&2
  exit 1
fi

if [[ ! -f "${REPO_ROOT}/scripts/deploy-terraform-cloudshell.sh" ]]; then
  if [[ -n "$REPO_URL" ]]; then
    echo "Cloning $REPO_URL -> $WORK_DIR ..."
    git clone "$REPO_URL" "$WORK_DIR"
    cd "$WORK_DIR"
    REPO_ROOT="$WORK_DIR"
  else
    echo "Not inside basilisk repo. Set REPO_URL or cd to a clone." >&2
    exit 1
  fi
fi

APP_RG="${NAME_PREFIX}-rg"
APP_SA="$(echo "${NAME_PREFIX}store" | tr '[:upper:]' '[:lower:]' | tr -d '-' | cut -c1-24)"

if az storage account show -g "$APP_RG" -n "$APP_SA" >/dev/null 2>&1; then
  echo "App storage $APP_SA exists — bootstrapping shared remote state ..."
  export NAME_PREFIX
  BOOT_ARGS=(--use-app-storage --name-prefix "$NAME_PREFIX")
  [[ "$MOUNT_CLOUDDRIVE" == "true" ]] && BOOT_ARGS+=(--mount-clouddrive)
  bash "${REPO_ROOT}/scripts/bootstrap-tfstate.sh" "${BOOT_ARGS[@]}"
else
  echo "Storage $APP_SA not found yet — first deploy will create it (local state), then re-run:"
  echo "  GITHUB_SP_CLIENT_ID=<clientId> bash scripts/bootstrap-tfstate.sh --use-app-storage --mount-clouddrive"
fi

cat <<EOF

Cloud Shell ready.

  Repo:        $REPO_ROOT
  State blob:  $APP_SA / tfstate / ${NAME_PREFIX}.tfstate (after bootstrap)

Deploy:
  cd $REPO_ROOT
  AUTO_APPROVE=true ./scripts/deploy-terraform-cloudshell.sh

Export GitHub secrets:
  bash scripts/export-github-secrets.sh
EOF
