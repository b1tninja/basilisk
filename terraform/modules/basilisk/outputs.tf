output "resource_group_name" {
  value = azurerm_resource_group.basilisk.name
}

output "resource_group_id" {
  value = azurerm_resource_group.basilisk.id
}

output "location" {
  value = azurerm_resource_group.basilisk.location
}

output "storage_account_name" {
  value = azurerm_storage_account.basilisk.name
}

output "function_app_name" {
  value = azurerm_function_app_flex_consumption.basilisk.name
}

output "function_app_hostname" {
  value = azurerm_function_app_flex_consumption.basilisk.default_hostname
}

# Every front_door_* output is null when enable_front_door is false. Null, not
# "" -- a consumer that interpolates one gets the literal "null" and notices,
# where an empty string builds a plausible-looking "https://" and does not.
#
# The consumer that matters is scripts/deploy-static.sh, which purges the edge
# cache after every static deploy and exits 1 if the purge fails. It probes
# `terraform output -raw front_door_profile_name` inside an `if`, and -raw
# exits non-zero on a null value, so with Front Door off the probe fails,
# FD_PROFILE stays empty, and the script takes its existing "Skipping Front
# Door cache purge" branch. There is no cache to purge in that configuration.
output "front_door_hostname" {
  value = local.front_door_enabled ? azurerm_cdn_frontdoor_endpoint.basilisk[0].host_name : null
}

output "front_door_url" {
  value = local.front_door_enabled ? "https://${azurerm_cdn_frontdoor_endpoint.basilisk[0].host_name}" : null
}

output "public_url" {
  description = "Primary user-facing URL (custom domain when configured, otherwise Front Door default hostname)."
  value       = local.public_url
}

output "custom_domain" {
  description = "Custom domain hostname when configured."
  value       = local.custom_domain_enabled ? var.custom_domain : null
}

output "logic_app_name" {
  description = "Approval Logic App name, or null when enable_approval_workflow is false and it is not deployed."
  # Read off the resource rather than re-deriving the condition from a variable.
  # This said `var.require_manager_approval ? ...[0].name`, which stopped being
  # the condition that governs the resource and became a way to index an empty
  # tuple: approval required, workflow not deployed, plan fails. one() answers
  # null for an empty list and cannot disagree with the count beside it.
  value = one(azapi_resource.approval_logic_app[*].name)
}

output "service_bus_namespace" {
  value = azurerm_servicebus_namespace.basilisk.name
}

# token_secret is intentionally not exported — read from Key Vault.

output "key_vault_name" {
  value = azurerm_key_vault.basilisk.name
}

output "key_vault_id" {
  value = azurerm_key_vault.basilisk.id
}

output "kv_uaa_grant_command" {
  description = "One-time command: grant the deploy SP User Access Administrator scoped to this vault so Terraform can assign Key Vault RBAC roles."
  value       = "az role assignment create --assignee ${data.azurerm_client_config.current.object_id} --role 'User Access Administrator' --scope ${azurerm_key_vault.basilisk.id}"
}

output "front_door_id" {
  description = "Front Door profile resource GUID (X-Azure-FDID). Null when Front Door is disabled, in which case the Function App has no BASILISK_AFD_ID and accepts direct requests."
  value       = local.front_door_enabled ? azurerm_cdn_frontdoor_profile.basilisk[0].resource_guid : null
}

output "front_door_profile_name" {
  description = "AFD profile name — used by az afd endpoint purge after static deploys. Null when Front Door is disabled; there is no edge cache to purge."
  value       = local.front_door_enabled ? azurerm_cdn_frontdoor_profile.basilisk[0].name : null
}

output "front_door_endpoint_name" {
  description = "AFD endpoint name — used by az afd endpoint purge after static deploys. Null when Front Door is disabled; there is no edge cache to purge."
  value       = local.front_door_enabled ? azurerm_cdn_frontdoor_endpoint.basilisk[0].name : null
}

output "signaling_wss_origin" {
  description = <<-EOT
    The signalling socket's `connect-src` source, for `scripts/deploy-static.sh`.

    The same value Front Door puts in the CSP response header. The portal HTML
    is served from blob storage, not by Flask, so the packaging step has to
    merge this origin into each page's `<meta>` policy before upload — the
    browser enforces the intersection of the two, and a header-only source is a
    source that does not exist.
  EOT
  value       = local.signaling_wss_origin
}

output "static_website_host" {
  value = azurerm_storage_account.basilisk.primary_web_host
}

output "static_website_url" {
  value = "https://${azurerm_storage_account.basilisk.primary_web_host}"
}

output "waf_policy_id" {
  description = "Front Door WAF policy ID. Null when Front Door is disabled — the rate limits are edge rules and have no origin-side equivalent."
  value       = local.front_door_enabled ? azurerm_cdn_frontdoor_firewall_policy.basilisk[0].id : null
}

locals {
  function_app_url = "https://${azurerm_function_app_flex_consumption.basilisk.default_hostname}"
  # With forward_proxy_convention=Standard, Easy Auth uses X-Forwarded-Host, so the
  # public hostname (custom domain or Front Door) is the OAuth callback host users hit.
  # Keep the Function App callback registered too for direct/debug access.
  google_oauth_redirect_uri    = "${local.public_url}/.auth/login/google/callback"
  google_oauth_redirect_uri_fn = "${local.function_app_url}/.auth/login/google/callback"
  aad_oauth_redirect_uri       = "${local.public_url}/.auth/login/aad/callback"
  aad_oauth_redirect_uri_fn    = "${local.function_app_url}/.auth/login/aad/callback"
}

output "oauth_setup" {
  description = <<-EOT
    OAuth redirect URIs for Google Cloud / Entra App Registration.
    Register ALL google_redirect_uris / aad_redirect_uris in the IdP.
    Prefer the public URL (custom domain) — that is what browsers use via Front Door.
    Google consent screen Authorized domains: only google_authorized_domain if you own it.
  EOT
  value = {
    function_app_hostname    = azurerm_function_app_flex_consumption.basilisk.default_hostname
    function_app_url         = local.function_app_url
    front_door_hostname      = local.front_door_enabled ? azurerm_cdn_frontdoor_endpoint.basilisk[0].host_name : null
    front_door_url           = local.front_door_enabled ? "https://${azurerm_cdn_frontdoor_endpoint.basilisk[0].host_name}" : null
    public_url               = local.public_url
    google_redirect_uri      = local.google_oauth_redirect_uri
    google_redirect_uris     = distinct([local.google_oauth_redirect_uri, local.google_oauth_redirect_uri_fn])
    aad_redirect_uri         = local.aad_oauth_redirect_uri
    aad_redirect_uris        = distinct([local.aad_oauth_redirect_uri, local.aad_oauth_redirect_uri_fn])
    google_authorized_domain = var.oauth_authorized_domain != "" ? var.oauth_authorized_domain : null
    gpg_keyserver_url        = local.public_url
  }
}
