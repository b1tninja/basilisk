provider "azurerm" {
  features {}
}

provider "azapi" {}

provider "aws" {
  region = var.aws_region
}

data "azurerm_client_config" "current" {}
