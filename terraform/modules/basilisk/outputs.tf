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

output "logic_app_name" {
  value = azapi_resource.approval_logic_app.name
}

output "service_bus_namespace" {
  value = azurerm_servicebus_namespace.basilisk.name
}

output "token_secret" {
  description = "HMAC secret for HKP v2 bearer tokens (also in Function App settings)."
  value       = random_password.token_secret.result
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
