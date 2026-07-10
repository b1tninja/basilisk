locals {
  entra_tenant_id = data.azurerm_client_config.current.tenant_id
  location        = var.location != "" ? var.location : "eastus"
}

module "basilisk" {
  source = "../modules/basilisk"

  name_prefix                = var.name_prefix
  location                   = local.location
  entra_tenant_id            = local.entra_tenant_id
  mail_provider              = var.mail_provider
  require_manager_approval   = var.require_manager_approval
  tags                       = var.tags
  existing_token_secret      = var.existing_token_secret
}
