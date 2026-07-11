locals {
  custom_domain_enabled  = var.custom_domain != ""
  route53_enabled        = local.custom_domain_enabled && var.route53_zone_name != ""
  custom_domain_rname    = replace(var.custom_domain, ".", "-")
  custom_domain_hostname = split(".", var.custom_domain)[0]
  public_url             = local.custom_domain_enabled ? "https://${var.custom_domain}" : "https://${azurerm_cdn_frontdoor_endpoint.basilisk.host_name}"
}

resource "azurerm_cdn_frontdoor_custom_domain" "public" {
  count                    = local.custom_domain_enabled ? 1 : 0
  name                     = local.custom_domain_rname
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk.id
  host_name                = var.custom_domain

  tls {
    certificate_type = "ManagedCertificate"
    minimum_version  = "TLS12"
  }
}

resource "azurerm_cdn_frontdoor_custom_domain_association" "public" {
  count                          = local.custom_domain_enabled ? 1 : 0
  cdn_frontdoor_custom_domain_id = azurerm_cdn_frontdoor_custom_domain.public[0].id
  cdn_frontdoor_route_ids = [
    azurerm_cdn_frontdoor_route.api.id,
    azurerm_cdn_frontdoor_route.static.id,
  ]
}

data "aws_route53_zone" "public" {
  count        = local.route53_enabled ? 1 : 0
  name         = var.route53_zone_name
  private_zone = false
}

# Prove domain ownership to Azure Front Door (managed TLS).
resource "aws_route53_record" "afd_validation" {
  count   = local.route53_enabled ? 1 : 0
  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = "_dnsauth.${local.custom_domain_hostname}"
  type    = "TXT"
  ttl     = 60
  records = [azurerm_cdn_frontdoor_custom_domain.public[0].validation_token]
}

# Route user traffic to the Front Door endpoint.
resource "aws_route53_record" "afd_cname" {
  count   = local.route53_enabled ? 1 : 0
  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = local.custom_domain_hostname
  type    = "CNAME"
  ttl     = 300
  records = [azurerm_cdn_frontdoor_endpoint.basilisk.host_name]

  depends_on = [azurerm_cdn_frontdoor_custom_domain_association.public]
}
