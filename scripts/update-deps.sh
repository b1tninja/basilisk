#!/usr/bin/env bash
# Regenerate pinned dependency lockfiles and Docker image digest pins.
# Run this script whenever you want to update dependencies to their latest
# allowed versions (within the constraints in *.in files).
#
# Prerequisites:
#   pip install pip-tools
#   docker (for refreshing image digest comments)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Regenerating Python lockfiles..."
pip-compile requirements.in \
  --generate-hashes \
  --output-file requirements.txt \
  --strip-extras \
  --upgrade

pip-compile requirements-dev.in \
  --generate-hashes \
  --output-file requirements-dev.txt \
  --strip-extras \
  --upgrade

echo "==> Updating npm lockfile..."
(cd web && npm update && npm install)

echo "==> Refreshing Docker base image digest comments..."

refresh_digest() {
  local image="$1"
  local file="$2"
  local tag="${3:-}"
  local full="${image}${tag:+:$tag}"
  echo "  Pulling $full..."
  docker pull "$full" >/dev/null 2>&1 || { echo "  WARNING: could not pull $full, skipping"; return; }
  local digest
  digest=$(docker inspect "$full" --format='{{index .RepoDigests 0}}' 2>/dev/null | grep -oP 'sha256:[a-f0-9]+' || true)
  if [[ -n "$digest" ]]; then
    # Replace the @sha256:... in FROM lines
    sed -i "s|FROM ${image}[^ ]*|FROM ${full%:*}${tag:+:$tag}@${digest}|" "$file"
    echo "  $full -> $digest"
  fi
}

refresh_digest "python" "docker/basilisk/Dockerfile" "3.13-slim"
refresh_digest "debian" "docker/gpg-tester/Dockerfile" "bookworm-slim"

echo ""
echo "Done. Review changes with 'git diff', then commit."
echo "Note: also update Azurite version in docker-compose*.yml when a new release ships."
