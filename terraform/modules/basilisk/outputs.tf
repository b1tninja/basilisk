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

output "front_door_hostname" {
  value = azurerm_cdn_frontdoor_endpoint.basilisk.host_name
}

output "front_door_url" {
  value = "https://${azurerm_cdn_frontdoor_endpoint.basilisk.host_name}"
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
  value = azapi_resource.approval_logic_app.name
}

output "service_bus_namespace" {
  value = azurerm_servicebus_namespace.basilisk.name
}

output "token_secret" {
  description = "HMAC secret for HKP v2 bearer tokens (also in Function App settings)."
  value       = local.token_secret
  sensitive   = true
}

output "static_website_host" {
  value = azurerm_storage_account.basilisk.primary_web_host
}

output "static_website_url" {
  value = "https://${azurerm_storage_account.basilisk.primary_web_host}"
}

output "waf_policy_id" {
  value = azurerm_cdn_frontdoor_firewall_policy.basilisk.id
}

locals {
  function_app_url          = "https://${azurerm_function_app_flex_consumption.basilisk.default_hostname}"
  google_oauth_redirect_uri = "${local.function_app_url}/.auth/login/google/callback"
  aad_oauth_redirect_uri    = "${local.function_app_url}/.auth/login/aad/callback"
}

output "oauth_setup" {
  description = <<-EOT
    OAuth redirect URIs for Google Cloud / Entra App Registration.
    Google OAuth client: google_redirect_uri → Authorized redirect URIs.
    Entra App Registration: aad_redirect_uri → Redirect URI (Web).
    Google consent screen Authorized domains: only google_authorized_domain if you own it.
  EOT
  value = {
    function_app_hostname    = azurerm_function_app_flex_consumption.basilisk.default_hostname
    function_app_url         = local.function_app_url
    front_door_hostname      = azurerm_cdn_frontdoor_endpoint.basilisk.host_name
    front_door_url           = "https://${azurerm_cdn_frontdoor_endpoint.basilisk.host_name}"
    google_redirect_uri      = local.google_oauth_redirect_uri
    aad_redirect_uri         = local.aad_oauth_redirect_uri
    google_authorized_domain = var.oauth_authorized_domain != "" ? var.oauth_authorized_domain : null
    gpg_keyserver_url        = local.public_url
  }
}
