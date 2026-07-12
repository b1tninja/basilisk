#!/usr/bin/env bash
# Resolve Easy Auth Terraform vars from workflow mode (auto|on|off) and secret presence.
# In GitHub Actions, writes TF_VAR_* to GITHUB_ENV. Locally, prints export statements.
set -euo pipefail

emit() {
  local key="$1"
  local value="$2"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    {
      echo "${key}<<EOF"
      echo "$value"
      echo "EOF"
    } >> "$GITHUB_ENV"
  else
    printf 'export %s=%q\n' "$key" "$value"
  fi
}

normalize_signin_mode() {
  local mode="${1:-auto}"
  case "${mode,,}" in
    auto|on|off) printf '%s' "$mode" ;;
    true) printf '%s' 'on' ;;
    false) printf '%s' 'off' ;;
    *)
      echo "Error: unknown sign-in mode: $mode (use auto, on, or off)" >&2
      exit 1
      ;;
  esac
}

resolve_tri_state() {
  local label="$1"
  local mode="$2"
  local secrets_ok="$3"

  case "$mode" in
    on)
      if [[ "$secrets_ok" != true ]]; then
        echo "Error: ${label} sign-in is 'on' but required secrets are missing." >&2
        exit 1
      fi
      echo true
      ;;
    off)
      echo false
      ;;
    auto|"")
      if [[ "$secrets_ok" == true ]]; then
        echo true
      else
        echo false
      fi
      ;;
    *)
      echo "Error: unknown ${label} sign-in mode: $mode (use auto, on, or off)" >&2
      exit 1
      ;;
  esac
}

microsoft_ok=false
if [[ -n "${AZURE_CREDENTIALS:-}" || -n "${ARM_CLIENT_ID:-}" ]]; then
  microsoft_ok=true
fi

google_ok=false
if [[ -n "${GOOGLE_CLIENT_ID:-}" && -n "${GOOGLE_CLIENT_SECRET:-}" ]]; then
  google_ok=true
fi

# Microsoft is on unless explicitly off (deploy always has AZURE_CREDENTIALS via azure/login).
MICROSOFT_SIGNIN_MODE="$(normalize_signin_mode "${MICROSOFT_SIGNIN_MODE:-auto}")"
GOOGLE_SIGNIN_MODE="$(normalize_signin_mode "${GOOGLE_SIGNIN_MODE:-auto}")"

if [[ "$MICROSOFT_SIGNIN_MODE" == "off" ]]; then
  enable_microsoft=false
elif [[ "$MICROSOFT_SIGNIN_MODE" == "on" && "$microsoft_ok" != true ]]; then
  echo "Error: Microsoft sign-in is 'on' but AZURE_CREDENTIALS is missing." >&2
  exit 1
else
  enable_microsoft=true
fi

enable_google="$(resolve_tri_state "Google" "$GOOGLE_SIGNIN_MODE" "$google_ok")"

if [[ "$enable_microsoft" != true && "$enable_google" != true ]]; then
  echo "Error: at least one sign-in provider must be enabled." >&2
  exit 1
fi

echo "Sign-in: microsoft=${enable_microsoft} (mode=${MICROSOFT_SIGNIN_MODE}), google=${enable_google} (mode=${GOOGLE_SIGNIN_MODE})" >&2

emit "TF_VAR_enable_microsoft_auth" "$enable_microsoft"
emit "TF_VAR_enable_google_auth" "$enable_google"

if [[ "$enable_google" == true ]]; then
  emit "TF_VAR_google_client_id" "${GOOGLE_CLIENT_ID}"
  emit "TF_VAR_google_client_secret" "${GOOGLE_CLIENT_SECRET}"
else
  emit "TF_VAR_google_client_id" ""
  emit "TF_VAR_google_client_secret" ""
fi
