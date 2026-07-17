locals {
  entra_tenant_id = data.azurerm_client_config.current.tenant_id
  location        = var.location != "" ? var.location : "eastus"
}

module "basilisk" {
  source = "../modules/basilisk"

  name_prefix              = var.name_prefix
  location                 = local.location
  entra_tenant_id          = local.entra_tenant_id
  mail_provider            = var.mail_provider
  require_manager_approval = var.require_manager_approval
  tags                     = var.tags
  existing_token_secret    = var.existing_token_secret
  google_client_id         = var.google_client_id
  google_client_secret     = var.google_client_secret
  enable_microsoft_auth    = var.enable_microsoft_auth
  enable_google_auth       = var.enable_google_auth
  oauth_authorized_domain  = var.oauth_authorized_domain
  custom_domain            = var.custom_domain
  route53_zone_name        = var.route53_zone_name
  route53_zone_id          = var.route53_zone_id
  budget_contact_emails    = var.budget_contact_emails
}
