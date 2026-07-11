output "resource_group_name" {
  value = module.basilisk.resource_group_name
}

output "location" {
  value = module.basilisk.location
}

output "function_app_name" {
  value = module.basilisk.function_app_name
}

output "front_door_hostname" {
  value = module.basilisk.front_door_hostname
}

output "front_door_url" {
  value = module.basilisk.front_door_url
}

output "public_url" {
  description = "Primary URL (custom domain when set, else Front Door default)."
  value       = module.basilisk.public_url
}

output "custom_domain" {
  value = module.basilisk.custom_domain
}

output "logic_app_name" {
  value = module.basilisk.logic_app_name
}

output "storage_account_name" {
  value = module.basilisk.storage_account_name
}

output "static_website_host" {
  value = module.basilisk.static_website_host
}

output "static_website_url" {
  value = module.basilisk.static_website_url
}

output "oauth_setup" {
  description = "OAuth redirect URIs and domain hints for IdP configuration."
  value       = module.basilisk.oauth_setup
}

output "service_bus_namespace" {
  value = module.basilisk.service_bus_namespace
}

output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "github_actions_secrets" {
  description = "Sensitive values to copy into GitHub Actions repository secrets after the first apply."
  sensitive   = true
  value = {
    BASILISK_TOKEN_SECRET      = module.basilisk.token_secret
    AZURE_SUBSCRIPTION_ID      = data.azurerm_client_config.current.subscription_id
    AZURE_TENANT_ID            = data.azurerm_client_config.current.tenant_id
    BASILISK_NAME_PREFIX       = var.name_prefix
    BASILISK_RESOURCE_GROUP    = module.basilisk.resource_group_name
    BASILISK_FUNCTION_APP_NAME = module.basilisk.function_app_name
    BASILISK_FRONT_DOOR_URL    = module.basilisk.public_url
    BASILISK_STORAGE_ACCOUNT   = module.basilisk.storage_account_name
  }
}

output "github_actions_setup" {
  description = "Non-sensitive deploy metadata and secret setup checklist."
  value = {
    secret_names = [
      "AZURE_CREDENTIALS",
      "BASILISK_TOKEN_SECRET",
    ]
    optional_secret_names = [
      "AZURE_SUBSCRIPTION_ID",
      "AZURE_TENANT_ID",
      "BASILISK_NAME_PREFIX",
      "BASILISK_RESOURCE_GROUP",
      "BASILISK_FUNCTION_APP_NAME",
      "BASILISK_FRONT_DOOR_URL",
      "BASILISK_STORAGE_ACCOUNT",
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
    ]
    azure_credentials_command = "az ad sp create-for-rbac --name basilisk-github-deploy --role contributor --scopes /subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${module.basilisk.resource_group_name} --sdk-auth"
    export_script             = "bash scripts/export-github-secrets.sh"
    subscription_id           = data.azurerm_client_config.current.subscription_id
    tenant_id                 = data.azurerm_client_config.current.tenant_id
    resource_group            = module.basilisk.resource_group_name
    function_app_name         = module.basilisk.function_app_name
    front_door_url            = module.basilisk.front_door_url
    public_url                = module.basilisk.public_url
    custom_domain             = module.basilisk.custom_domain
    storage_account_name      = module.basilisk.storage_account_name
    static_website_url        = module.basilisk.static_website_url
    oauth_setup               = module.basilisk.oauth_setup
  }
}
