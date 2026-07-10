resource "azurerm_role_assignment" "function_blob_contributor" {
  scope                = azurerm_storage_account.basilisk.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_function_app_flex_consumption.basilisk.identity[0].principal_id
}

resource "azurerm_role_assignment" "function_table_contributor" {
  scope                = azurerm_storage_account.basilisk.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id         = azurerm_function_app_flex_consumption.basilisk.identity[0].principal_id
}
