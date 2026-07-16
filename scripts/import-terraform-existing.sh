#!/usr/bin/env bash
# Import an existing Basilisk Azure stack into Terraform state (one-time bootstrap).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform/cloudshell"

NAME_PREFIX="${NAME_PREFIX:-basilisk-dev}"
LOCATION="${LOCATION:-}"
SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-}"

RG="${NAME_PREFIX}-rg"
STORAGE_NAME="$(echo "${NAME_PREFIX}store" | tr '[:upper:]' '[:lower:]' | tr -d '-' | cut -c1-24)"
PLAN="${NAME_PREFIX}-plan"
FN="${NAME_PREFIX}-fn"
BUS="${NAME_PREFIX}-bus"
FD_PROFILE="${NAME_PREFIX}-fd"
FD_ENDPOINT="${NAME_PREFIX}-endpoint"
WAF_NAME="$(echo "${NAME_PREFIX}waf" | tr -d '-')"
LOGIC_APP="${NAME_PREFIX}-approval-la"

MOD="module.basilisk"

import_if_missing() {
  local addr="$1"
  local id="$2"
  if terraform state show -no-color "$addr" >/dev/null 2>&1; then
    echo "  skip (already in state): $addr"
    return 0
  fi
  echo "  import: $addr"
  terraform import -input=false "$addr" "$id"
}

# Import only when the Azure resource exists; Terraform apply creates missing ones.
import_if_exists() {
  local check_cmd="$1"
  local addr="$2"
  local id="$3"
  if ! eval "$check_cmd" >/dev/null 2>&1; then
    echo "  skip (not in Azure): $addr"
    return 0
  fi
  import_if_missing "$addr" "$id"
}

resolve_deploy_location() {
  local requested="$1"
  if [[ -n "$requested" ]]; then
    printf '%s' "$requested"
    return
  fi
  local existing
  existing="$(az group show --name "$RG" --query location -o tsv 2>/dev/null || true)"
  if [[ -n "$existing" ]]; then
    printf '%s' "$existing"
    return
  fi
  printf '%s' "eastus"
}

if ! command -v az >/dev/null 2>&1 || ! command -v terraform >/dev/null 2>&1; then
  echo "Requires az and terraform." >&2
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "Not logged in. Run: az login" >&2
  exit 1
fi

if [[ -n "$SUBSCRIPTION_ID" ]]; then
  az account set --subscription "$SUBSCRIPTION_ID"
fi

if ! az group show --name "$RG" >/dev/null 2>&1; then
  echo "Resource group $RG not found. Deploy infrastructure first or set NAME_PREFIX." >&2
  exit 1
fi

SUB="$(az account show --query id -o tsv)"
LOCATION="$(resolve_deploy_location "$LOCATION")"
TOKEN_SECRET="$(az functionapp config appsettings list -g "$RG" -n "$FN" --query "[?name=='BASILISK_TOKEN_SECRET'].value | [0]" -o tsv 2>/dev/null || true)"

export TF_VAR_name_prefix="$NAME_PREFIX"
export TF_VAR_location="$LOCATION"
export TF_VAR_mail_provider="${MAIL_PROVIDER:-office365}"
if [[ -n "$TOKEN_SECRET" && "$TOKEN_SECRET" != "null" ]]; then
  export TF_VAR_existing_token_secret="$TOKEN_SECRET"
  echo "Using existing BASILISK_TOKEN_SECRET from $FN"
else
  echo "Warning: BASILISK_TOKEN_SECRET not found on function app; Terraform will generate a new one." >&2
fi

RG_ID="/subscriptions/${SUB}/resourceGroups/${RG}"
SA_ID="${RG_ID}/providers/Microsoft.Storage/storageAccounts/${STORAGE_NAME}"
BUS_ID="${RG_ID}/providers/Microsoft.ServiceBus/namespaces/${BUS}"
FD_ID="${RG_ID}/providers/Microsoft.Cdn/profiles/${FD_PROFILE}"
FD_EP_ID="${FD_ID}/afdEndpoints/${FD_ENDPOINT}"
FN_OG_ID="${FD_ID}/originGroups/basilisk-origins"
STATIC_OG_ID="${FD_ID}/originGroups/basilisk-static-origins"
WAF_ID="${RG_ID}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/${WAF_NAME}"
LOGIC_ID="${RG_ID}/providers/Microsoft.Logic/workflows/${LOGIC_APP}"

echo "Importing $RG into Terraform state ..."
cd "$TF_DIR"
bash "${REPO_ROOT}/scripts/terraform-init.sh"

# Remove duplicate manual route if present (terraform static-route covers / and /*).
if az afd route show -g "$RG" --profile-name "$FD_PROFILE" --endpoint-name "$FD_ENDPOINT" --route-name static-index >/dev/null 2>&1; then
  echo "Removing duplicate Front Door route static-index (superseded by static-route) ..."
  az afd route delete -g "$RG" --profile-name "$FD_PROFILE" --endpoint-name "$FD_ENDPOINT" --route-name static-index --yes --output none || true
fi

import_if_missing "${MOD}.azurerm_resource_group.basilisk" "$RG_ID"
import_if_missing "${MOD}.azurerm_storage_account.basilisk" "$SA_ID"
import_if_missing "${MOD}.azurerm_storage_account_static_website.portal" "$SA_ID"
import_if_missing "${MOD}.azurerm_storage_container.certs" "${SA_ID}/blobServices/default/containers/certs"
import_if_missing "${MOD}.azurerm_storage_container.deployments" "${SA_ID}/blobServices/default/containers/deployments"

if az storage account keys list -g "$RG" -n "$STORAGE_NAME" --query "[0].value" -o tsv >/dev/null 2>&1; then
  IMMUT_ID="${SA_ID}/blobServices/default/containers/certs/immutabilityPolicies/default"
  import_if_exists \
    "az resource show --ids '$IMMUT_ID'" \
    "${MOD}.azurerm_storage_container_immutability_policy.certs[0]" \
    "$IMMUT_ID"
fi

import_if_missing "${MOD}.azurerm_service_plan.basilisk" "${RG_ID}/providers/Microsoft.Web/serverFarms/${PLAN}"
import_if_missing "${MOD}.azurerm_function_app_flex_consumption.basilisk" "${RG_ID}/providers/Microsoft.Web/sites/${FN}"
import_if_missing "${MOD}.azurerm_servicebus_namespace.basilisk" "$BUS_ID"

for queue in key-events key-approved sendtoken-events; do
  case "$queue" in
    key-events) addr="${MOD}.azurerm_servicebus_queue.key_events" ;;
    key-approved) addr="${MOD}.azurerm_servicebus_queue.key_approved" ;;
    sendtoken-events) addr="${MOD}.azurerm_servicebus_queue.sendtoken_events" ;;
  esac
  import_if_exists \
    "az servicebus queue show --namespace-name '$BUS' --resource-group '$RG' --name '$queue'" \
    "$addr" \
    "${BUS_ID}/queues/${queue}"
done

import_if_exists \
  "az cdn profile show --name '$FD_PROFILE' --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_profile.basilisk" \
  "$FD_ID"
import_if_exists \
  "az network front-door waf-policy show --name '$WAF_NAME' --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_firewall_policy.basilisk" \
  "$WAF_ID"
import_if_exists \
  "az afd endpoint show --profile-name '$FD_PROFILE' --endpoint-name '$FD_ENDPOINT' --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_endpoint.basilisk" \
  "$FD_EP_ID"
import_if_exists \
  "az afd origin-group show --profile-name '$FD_PROFILE' --origin-group-name basilisk-origins --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_origin_group.function" \
  "$FN_OG_ID"
import_if_exists \
  "az afd origin show --profile-name '$FD_PROFILE' --origin-group-name basilisk-origins --origin-name function-origin --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_origin.function" \
  "${FN_OG_ID}/origins/function-origin"
import_if_exists \
  "az afd origin-group show --profile-name '$FD_PROFILE' --origin-group-name basilisk-static-origins --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_origin_group.static" \
  "$STATIC_OG_ID"
import_if_exists \
  "az afd origin show --profile-name '$FD_PROFILE' --origin-group-name basilisk-static-origins --origin-name static-origin --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_origin.static" \
  "${STATIC_OG_ID}/origins/static-origin"
import_if_exists \
  "az afd route show --profile-name '$FD_PROFILE' --endpoint-name '$FD_ENDPOINT' --route-name api-route --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_route.api" \
  "${FD_EP_ID}/routes/api-route"
import_if_exists \
  "az afd route show --profile-name '$FD_PROFILE' --endpoint-name '$FD_ENDPOINT' --route-name static-route --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_route.static" \
  "${FD_EP_ID}/routes/static-route"
import_if_exists \
  "az afd security-policy show --profile-name '$FD_PROFILE' --security-policy-name basilisk-waf --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_security_policy.basilisk" \
  "${FD_ID}/securityPolicies/basilisk-waf"
import_if_exists \
  "az afd rule-set show --profile-name '$FD_PROFILE' --rule-set-name StaticCache --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_rule_set.static_cache" \
  "${FD_ID}/ruleSets/StaticCache"
import_if_exists \
  "az resource show --ids '${FD_ID}/ruleSets/StaticCache/rules/CacheStaticAssets'" \
  "${MOD}.azurerm_cdn_frontdoor_rule.static_assets_cache" \
  "${FD_ID}/ruleSets/StaticCache/rules/CacheStaticAssets"
import_if_exists \
  "az resource show --ids '${FD_ID}/ruleSets/StaticCache/rules/CacheStaticHtml'" \
  "${MOD}.azurerm_cdn_frontdoor_rule.static_html_cache" \
  "${FD_ID}/ruleSets/StaticCache/rules/CacheStaticHtml"
import_if_exists \
  "az afd rule-set show --profile-name '$FD_PROFILE' --rule-set-name SecurityHeaders --resource-group '$RG'" \
  "${MOD}.azurerm_cdn_frontdoor_rule_set.security" \
  "${FD_ID}/ruleSets/SecurityHeaders"
import_if_exists \
  "az resource show --ids '${FD_ID}/ruleSets/SecurityHeaders/rules/AddSecurityHeaders1'" \
  "${MOD}.azurerm_cdn_frontdoor_rule.security_headers" \
  "${FD_ID}/ruleSets/SecurityHeaders/rules/AddSecurityHeaders1"
import_if_exists \
  "az resource show --ids '${FD_ID}/ruleSets/SecurityHeaders/rules/AddSecurityHeaders2'" \
  "${MOD}.azurerm_cdn_frontdoor_rule.security_headers_extra" \
  "${FD_ID}/ruleSets/SecurityHeaders/rules/AddSecurityHeaders2"

import_route53_if_exists() {
  local zone_id="$1"
  local record_name="$2"
  local record_type="$3"
  local addr="$4"
  if ! command -v aws >/dev/null 2>&1; then
    echo "  skip (no aws cli): $addr"
    return 0
  fi
  if [[ -z "${AWS_ACCESS_KEY_ID:-}" ]]; then
    echo "  skip (no AWS credentials): $addr"
    return 0
  fi
  local zone_name="${TF_VAR_route53_zone_name:-b1tninja.com}"
  local fqdn="${record_name}.${zone_name}."
  if ! aws route53 list-resource-record-sets \
    --hosted-zone-id "$zone_id" \
    --query "ResourceRecordSets[?Name=='${fqdn}' && Type=='${record_type}'] | length(@)" \
    --output text 2>/dev/null | grep -qE '^[1-9]'; then
    echo "  skip (not in Route53): $addr"
    return 0
  fi
  import_if_missing "$addr" "${zone_id}_${record_name}_${record_type}"
}

CUSTOM_DOMAIN="${TF_VAR_custom_domain:-keys.b1tninja.com}"
if [[ -n "$CUSTOM_DOMAIN" ]]; then
  CUSTOM_DOMAIN_RNAME="${CUSTOM_DOMAIN//./-}"
  FD_CD_ID="${FD_ID}/customDomains/${CUSTOM_DOMAIN_RNAME}"
  FD_CD_ASSOC_ID="${FD_ID}/associations/${CUSTOM_DOMAIN_RNAME}"
  import_if_exists \
    "az afd custom-domain show --profile-name '$FD_PROFILE' --custom-domain-name '$CUSTOM_DOMAIN_RNAME' --resource-group '$RG'" \
    "${MOD}.azurerm_cdn_frontdoor_custom_domain.public[0]" \
    "$FD_CD_ID"
  import_if_exists \
    "az resource show --ids '$FD_CD_ASSOC_ID'" \
    "${MOD}.azurerm_cdn_frontdoor_custom_domain_association.public[0]" \
    "$FD_CD_ASSOC_ID"

  ROUTE53_ZONE_ID="${TF_VAR_route53_zone_id:-Z026512234X4JPOD7PZH1}"
  CUSTOM_HOSTNAME="${CUSTOM_DOMAIN%%.*}"
  import_route53_if_exists \
    "$ROUTE53_ZONE_ID" \
    "_dnsauth.${CUSTOM_HOSTNAME}" \
    "TXT" \
    "${MOD}.aws_route53_record.afd_validation[0]"
  import_route53_if_exists \
    "$ROUTE53_ZONE_ID" \
    "$CUSTOM_HOSTNAME" \
    "CNAME" \
    "${MOD}.aws_route53_record.afd_cname[0]"
fi

import_if_exists \
  "az logic workflow show --resource-group '$RG' --name '$LOGIC_APP'" \
  "${MOD}.azapi_resource.approval_logic_app" \
  "$LOGIC_ID"

BLOB_RA="$(az role assignment list --scope "$SA_ID" --query "[?roleDefinitionName=='Storage Blob Data Contributor'].id | [0]" -o tsv 2>/dev/null || true)"
TABLE_RA="$(az role assignment list --scope "$SA_ID" --query "[?roleDefinitionName=='Storage Table Data Contributor'].id | [0]" -o tsv 2>/dev/null || true)"
if [[ -n "$BLOB_RA" && "$BLOB_RA" != "null" ]]; then
  import_if_missing "${MOD}.azurerm_role_assignment.function_blob_contributor" "$BLOB_RA"
fi
if [[ -n "$TABLE_RA" && "$TABLE_RA" != "null" ]]; then
  import_if_missing "${MOD}.azurerm_role_assignment.function_table_contributor" "$TABLE_RA"
fi

echo ""
echo "Import complete. Review drift:"
terraform plan -input=false -no-color || true
echo ""
echo "When satisfied, run: terraform apply -auto-approve"
echo "Or re-run the GitHub deploy workflow (state is in Azure Blob after bootstrap-tfstate.sh)."
