#!/usr/bin/env bash
# Upload Vite-built static portal to Azure Storage static website ($web container).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform/cloudshell"

STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-}"
RESOURCE_GROUP="${RESOURCE_GROUP:-}"

if [[ -z "$STORAGE_ACCOUNT" ]]; then
  STORAGE_ACCOUNT="$(cd "$TF_DIR" && terraform output -raw storage_account_name 2>/dev/null || true)"
fi

if [[ -z "$RESOURCE_GROUP" ]]; then
  RESOURCE_GROUP="$(cd "$TF_DIR" && terraform output -raw resource_group_name 2>/dev/null || true)"
fi

if [[ -z "$STORAGE_ACCOUNT" ]]; then
  echo "Set STORAGE_ACCOUNT or run from a Terraform-applied workspace." >&2
  exit 1
fi

# ── The signalling origin the uploaded pages must allow ──────────────────────
# Front Door puts this value in the CSP response header and the browser enforces
# the intersection of that header with each document's own `<meta>` policy — so
# pages uploaded without it ship a site where shared sessions cannot open a
# socket, while every configuration file still looks right. The packaging step
# merges it in; this resolves it.
#
# **Empty is a failure, not a warning.** It was a warning, and that is how this
# shipped: `terraform output` is wrapped so any error yields an empty string, an
# uninitialised workspace or a renamed output produces one silently, the warning
# lands on stderr among hundreds of CI lines, and Front Door then caches the
# result for 24 hours. A deploy that disables a headline feature has to stop.
#
# `none` is the deliberate way to say a deployment has no signalling — a
# keyserver-only install. It is spelled the way the rest of this codebase spells
# the same idea: `rtc.ice stun=none` is a user declining every third party, and
# `NO_ICE_SERVERS` exists precisely so "nobody said" and "somebody said none"
# cannot be confused. Same distinction, same word, and the silent path is the
# one that fails.
if [[ -z "${BASILISK_SIGNALING_WSS_ORIGIN:-}" ]]; then
  BASILISK_SIGNALING_WSS_ORIGIN="$(cd "$TF_DIR" && terraform output -raw signaling_wss_origin 2>/dev/null || true)"
fi
export BASILISK_SIGNALING_WSS_ORIGIN

if [[ -z "$BASILISK_SIGNALING_WSS_ORIGIN" ]]; then
  cat >&2 <<'MSG'
ERROR: the signalling origin could not be resolved, and nothing has been uploaded.

  Front Door's CSP header names this deployment's Web PubSub host. A browser
  enforces the intersection of that header and each page's own <meta> policy, so
  pages uploaded without it refuse the signalling socket and shared sessions
  cannot start — silently, with every config file looking correct.

  Fix one of these:
    · `terraform output -raw signaling_wss_origin` in the deploy workspace
      (this is what the deploy reads; check the workspace is initialised and
      applied, and that AZURE_WEBPUBSUB_CONNECTION_STRING is set)
    · export BASILISK_SIGNALING_WSS_ORIGIN=wss://<host>.webpubsub.azure.com

  If this deployment genuinely has no signalling — a keyserver-only install —
  say so explicitly:
    · export BASILISK_SIGNALING_WSS_ORIGIN=none
MSG
  exit 1
fi

if [[ "$BASILISK_SIGNALING_WSS_ORIGIN" == "none" ]]; then
  echo "Signalling: explicitly none — uploading pages with no signalling socket." >&2
fi

STAGE="$(bash "${REPO_ROOT}/scripts/package-static.sh")"

storage_args=(--account-name "$STORAGE_ACCOUNT")
if [[ -n "${RESOURCE_GROUP:-}" ]]; then
  key="$(az storage account keys list -g "$RESOURCE_GROUP" -n "$STORAGE_ACCOUNT" --query "[0].value" -o tsv)"
  storage_args+=(--account-key "$key")
  az storage blob service-properties update \
    "${storage_args[@]}" \
    --static-website \
    --index-document index.html \
    --404-document index.html \
    --only-show-errors
else
  storage_args+=(--auth-mode login)
fi

echo "Uploading static site to ${STORAGE_ACCOUNT}/\$web ..."

az storage blob upload-batch \
  "${storage_args[@]}" \
  --destination '$web' \
  --source "$STAGE" \
  --overwrite \
  --only-show-errors

# Ensure HTML content-types for clean URL blobs and root pages.
# Derived from staged *.html plus any extensionless aliases (e.g. search).
# Cache 1 day at the origin; Front Door OverrideAlways also uses 1 day for
# HTML. Post-deploy purge (required below) drops stale pins immediately.
shopt -s nullglob
html_blobs=()
for html in "${STAGE}"/*.html; do
  html_blobs+=("$(basename "$html")")
done
for alias in "${STAGE}"/*; do
  [[ -f "$alias" ]] || continue
  name="$(basename "$alias")"
  [[ "$name" == *.* ]] && continue
  html_blobs+=("$name")
done
# Deduplicate while preserving order.
declare -A seen=()
for blob in "${html_blobs[@]}"; do
  [[ -n "${seen[$blob]+x}" ]] && continue
  seen[$blob]=1
  src="${STAGE}/${blob}"
  [[ -f "$src" ]] || src="${STAGE}/${blob}.html"
  [[ -f "$src" ]] || continue
  az storage blob upload \
    "${storage_args[@]}" \
    --container-name '$web' \
    --name "$blob" \
    --file "$src" \
    --content-type "text/html; charset=utf-8" \
    --content-cache-control "public, max-age=86400" \
    --overwrite \
    --only-show-errors
done

# External importmaps are content-hashed filenames — cache like other static
# pins; HTML references a specific importmap-* name per deploy.
for imap in "${STAGE}"/importmaps/importmap-*.json; do
  [[ -f "$imap" ]] || continue
  az storage blob upload \
    "${storage_args[@]}" \
    --container-name '$web' \
    --name "importmaps/$(basename "$imap")" \
    --file "$imap" \
    --content-type "application/importmap+json" \
    --content-cache-control "public, max-age=604800, immutable" \
    --overwrite \
    --only-show-errors
done

# Merkle integrity pins — short TTL so edges cannot keep a stale expected root
# after HTML/assets rotate (runtime also uses cache: no-store).
for pin in "${STAGE}"/integrity/module-roots*.json; do
  [[ -f "$pin" ]] || continue
  az storage blob upload \
    "${storage_args[@]}" \
    --container-name '$web' \
    --name "integrity/$(basename "$pin")" \
    --file "$pin" \
    --content-type "application/json; charset=utf-8" \
    --content-cache-control "public, max-age=60, must-revalidate" \
    --overwrite \
    --only-show-errors
done

static_host="$(az storage account show -n "$STORAGE_ACCOUNT" ${RESOURCE_GROUP:+-g "$RESOURCE_GROUP"} --query primaryEndpoints.web -o tsv | sed 's#https://##;s#/$##')"
echo "Static site deployed to https://${static_host}/"

# ── Purge Azure Front Door cache ─────────────────────────────────────────────
# HTML / importmaps keep stable paths across deploys; hashed /assets/* chunks
# are cache-busted by filename. Purge is required so PoPs drop stale HTML that
# would otherwise pin old SRI hashes (or mix with a new deploy).
#
# FD profile/endpoint names come from Terraform outputs when available;
# fall back to env vars BASILISK_FD_PROFILE and BASILISK_FD_ENDPOINT, or
# derive from the storage account name convention.
FD_RG="${RESOURCE_GROUP:-}"
FD_PROFILE="${BASILISK_FD_PROFILE:-}"
FD_ENDPOINT="${BASILISK_FD_ENDPOINT:-}"

if [[ -z "$FD_PROFILE" ]] && [[ -n "${TF_DIR:-}" ]] && terraform -chdir="$TF_DIR" output -raw front_door_profile_name >/dev/null 2>&1; then
  FD_PROFILE="$(terraform -chdir="$TF_DIR" output -raw front_door_profile_name 2>/dev/null || true)"
  FD_ENDPOINT="$(terraform -chdir="$TF_DIR" output -raw front_door_endpoint_name 2>/dev/null || true)"
fi

if [[ -n "$FD_PROFILE" && -n "$FD_ENDPOINT" && -n "$FD_RG" ]]; then
  echo "Purging Front Door cache (${FD_PROFILE} / ${FD_ENDPOINT}) …"
  if az afd endpoint purge \
    --resource-group "$FD_RG" \
    --profile-name   "$FD_PROFILE" \
    --endpoint-name  "$FD_ENDPOINT" \
    --content-paths  "/*" \
    --no-wait \
    --only-show-errors; then
    echo "Cache purge queued (async — propagates to all PoPs within ~2 min)."
  else
    echo "ERROR: Front Door cache purge failed — refusing to leave stale HTML/SRI pins in CDN." >&2
    exit 1
  fi
else
  echo "Skipping Front Door cache purge (FD_PROFILE/FD_ENDPOINT/RESOURCE_GROUP not set)." >&2
  echo "  Set BASILISK_FD_PROFILE, BASILISK_FD_ENDPOINT, and RESOURCE_GROUP to enable." >&2
fi
