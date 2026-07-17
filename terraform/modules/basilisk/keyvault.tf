data "azurerm_client_config" "current" {}

# Access policies (not RBAC) so a Contributor deploy SP can manage secrets
# without Microsoft.Authorization/roleAssignments/write (User Access Administrator).
resource "azurerm_key_vault" "basilisk" {
  name                       = substr(replace("${var.name_prefix}-kv", "-", ""), 0, 24)
  location                   = azurerm_resource_group.basilisk.location
  resource_group_name        = azurerm_resource_group.basilisk.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  rbac_authorization_enabled = false
  tags                       = var.tags
}

resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id = azurerm_key_vault.basilisk.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = [
    "Get",
    "List",
    "Set",
    "Delete",
    "Purge",
    "Recover",
  ]
}

# Function App managed identity — Get only (Key Vault references at runtime).
# Created after the Function App exists (no cycle with secret creation).
resource "azurerm_key_vault_access_policy" "function" {
  key_vault_id = azurerm_key_vault.basilisk.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_function_app_flex_consumption.basilisk.identity[0].principal_id

  secret_permissions = [
    "Get",
    "List",
  ]
}

resource "azurerm_key_vault_secret" "token_secret" {
  name         = "basilisk-token-secret"
  value        = local.token_secret
  key_vault_id = azurerm_key_vault.basilisk.id
  depends_on   = [azurerm_key_vault_access_policy.deployer]
}

resource "azurerm_key_vault_secret" "google_client_secret" {
  count        = var.enable_google_auth && var.google_client_secret != "" ? 1 : 0
  name         = "google-client-secret"
  value        = var.google_client_secret
  key_vault_id = azurerm_key_vault.basilisk.id
  depends_on   = [azurerm_key_vault_access_policy.deployer]
}
