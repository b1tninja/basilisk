locals {
  entra_tenant_id = data.azurerm_client_config.current.tenant_id
  location        = var.location != "" ? var.location : "eastus"
}

module "basilisk" {
  source = "../modules/basilisk"

  name_prefix                              = var.name_prefix
  location                                 = local.location
  entra_tenant_id                          = local.entra_tenant_id
  mail_provider                            = var.mail_provider
  require_manager_approval                 = var.require_manager_approval
  upstream_enabled                         = var.upstream_enabled
  upstream_allowlist                       = var.upstream_allowlist
  upstream_default                         = var.upstream_default
  tags                                     = var.tags
  existing_token_secret                    = var.existing_token_secret
  google_client_id                         = var.google_client_id
  google_client_secret                     = var.google_client_secret
  enable_microsoft_auth                    = var.enable_microsoft_auth
  enable_google_auth                       = var.enable_google_auth
  oauth_authorized_domain                  = var.oauth_authorized_domain
  enable_front_door                        = var.enable_front_door
  front_door_health_probe_interval_seconds = var.front_door_health_probe_interval_seconds
  function_instance_memory_mb              = var.function_instance_memory_mb
  custom_domain                            = var.custom_domain
  route53_zone_name                        = var.route53_zone_name
  route53_zone_id                          = var.route53_zone_id
  budget_amount                            = var.budget_amount
  budget_contact_emails                    = var.budget_contact_emails

  enable_worm_immutability = var.enable_worm_immutability
  worm_retention_days      = var.worm_retention_days

  upload_rate_limit_per_minute    = var.upload_rate_limit_per_minute
  v2_upload_rate_limit_per_minute = var.v2_upload_rate_limit_per_minute
  sendtoken_rate_limit_per_minute = var.sendtoken_rate_limit_per_minute

  web_pubsub_sku = var.web_pubsub_sku
  web_pubsub_hub = var.web_pubsub_hub
  servicebus_sku = var.servicebus_sku

  function_maximum_instance_count = var.function_maximum_instance_count
  log_analytics_daily_quota_gb    = var.log_analytics_daily_quota_gb
}
