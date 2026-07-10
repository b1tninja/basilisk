resource "azurerm_resource_group" "basilisk" {
  name     = "${var.name_prefix}-rg"
  location = var.location
  tags     = var.tags
}

locals {
  storage_account_name = substr(replace(lower("${var.name_prefix}store"), "-", ""), 0, 24)
}
