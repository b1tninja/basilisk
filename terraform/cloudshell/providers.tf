provider "azurerm" {
  features {}
}

provider "azapi" {}

data "azurerm_client_config" "current" {}
