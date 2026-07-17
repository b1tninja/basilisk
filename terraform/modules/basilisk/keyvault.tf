data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "basilisk" {
  name                       = substr(replace("${var.name_prefix}-kv", "-", ""), 0, 24)
  location                   = azurerm_resource_group.basilisk.location
  resource_group_name        = azurerm_resource_group.basilisk.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  rbac_authorization_enabled = true
  tags                       = var.tags
}

# Key Vault Secrets Management for the deploy identity.
# Requires the deploy SP to hold "User Access Administrator" scoped to this vault
# (Contributor alone cannot write roleAssignments). Grant once with:
#
#   KV_ID=$(az keyvault show -n <vault-name> -g <rg> --query id -o tsv)
#   az role assignment create \
#     --assignee <sp-object-id> \
#     --role "User Access Administrator" \
#     --scope "$KV_ID"
#
# The exact command is printed by `terraform output github_actions_setup` after the
# vault exists.
resource "azurerm_role_assignment" "kv_admin" {
  scope                = azurerm_key_vault.basilisk.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "kv_function_secrets" {
  scope                = azurerm_key_vault.basilisk.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_function_app_flex_consumption.basilisk.identity[0].principal_id
}

resource "azurerm_key_vault_secret" "token_secret" {
  name         = "basilisk-token-secret"
  value        = local.token_secret
  key_vault_id = azurerm_key_vault.basilisk.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "google_client_secret" {
  count        = var.enable_google_auth && var.google_client_secret != "" ? 1 : 0
  name         = "google-client-secret"
  value        = var.google_client_secret
  key_vault_id = azurerm_key_vault.basilisk.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}
