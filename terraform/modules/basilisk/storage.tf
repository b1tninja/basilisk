resource "azurerm_storage_account" "basilisk" {
  name                     = local.storage_account_name
  resource_group_name      = azurerm_resource_group.basilisk.name
  location                 = azurerm_resource_group.basilisk.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  min_tls_version          = "TLS1_2"
  allow_nested_items_to_be_public = false

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
    versioning_enabled = var.enable_worm_immutability
  }

  tags = var.tags
}

resource "azurerm_storage_account_static_website" "portal" {
  storage_account_id = azurerm_storage_account.basilisk.id
  index_document     = "index.html"
  error_404_document = "index.html"
}

resource "azurerm_storage_container" "certs" {
  name                  = "certs"
  storage_account_id    = azurerm_storage_account.basilisk.id
  container_access_type = "private"

  depends_on = [
    azurerm_storage_account.basilisk,
    azurerm_storage_account_static_website.portal,
  ]
}

resource "azurerm_storage_container" "deployments" {
  name                  = "deployments"
  storage_account_id    = azurerm_storage_account.basilisk.id
  container_access_type = "private"

  depends_on = [
    azurerm_storage_account.basilisk,
    azurerm_storage_account_static_website.portal,
  ]
}

resource "azurerm_storage_container_immutability_policy" "certs" {
  count = var.enable_worm_immutability ? 1 : 0

  storage_container_resource_manager_id = azurerm_storage_container.certs.id
  immutability_period_in_days           = var.worm_retention_days
  protected_append_writes_all_enabled   = true
}
