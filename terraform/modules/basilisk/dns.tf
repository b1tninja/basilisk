locals {
  # A custom domain is a child of the Front Door profile: it holds the managed
  # certificate and is associated to the routes. With no profile there is
  # nothing to attach it to, so this requires both. var.custom_domain set while
  # Front Door is off is not silently downgraded to "no custom domain" -- see
  # terraform_data.custom_domain_requires_front_door at the foot of this file,
  # which fails the plan instead.
  custom_domain_enabled  = var.custom_domain != "" && local.front_door_enabled
  route53_zone_id        = trimspace(var.route53_zone_id)
  route53_lookup_by_name = local.route53_zone_id == "" && var.route53_zone_name != ""
  route53_enabled        = local.custom_domain_enabled && (local.route53_zone_id != "" || var.route53_zone_name != "")
  route53_zone_id_final  = local.route53_zone_id != "" ? local.route53_zone_id : data.aws_route53_zone.public[0].zone_id
  custom_domain_rname    = replace(var.custom_domain, ".", "-")
  custom_domain_hostname = split(".", var.custom_domain)[0]
  # Custom domain first, then the Front Door endpoint, then -- with no edge at
  # all -- the Function App's own hostname, which is what browsers actually hit
  # in that configuration. local.function_app_url (outputs.tf) is that same
  # expression; a second copy here would be a second thing to keep in step.
  public_url = local.custom_domain_enabled ? "https://${var.custom_domain}" : (
    local.front_door_enabled ? "https://${azurerm_cdn_frontdoor_endpoint.basilisk[0].host_name}" : local.function_app_url
  )
}

resource "azurerm_cdn_frontdoor_custom_domain" "public" {
  count                    = local.custom_domain_enabled ? 1 : 0
  name                     = local.custom_domain_rname
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk[0].id
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
    azurerm_cdn_frontdoor_route.api[0].id,
    azurerm_cdn_frontdoor_route.static[0].id,
  ]
}

data "aws_route53_zone" "public" {
  count        = local.custom_domain_enabled && local.route53_lookup_by_name ? 1 : 0
  name         = var.route53_zone_name
  private_zone = false
}

# Prove domain ownership to Azure Front Door (managed TLS).
resource "aws_route53_record" "afd_validation" {
  count   = local.route53_enabled ? 1 : 0
  zone_id = local.route53_zone_id_final
  name    = "_dnsauth.${local.custom_domain_hostname}"
  type    = "TXT"
  ttl     = 60
  records = [azurerm_cdn_frontdoor_custom_domain.public[0].validation_token]
}

# Route user traffic to the Front Door endpoint.
resource "aws_route53_record" "afd_cname" {
  count   = local.route53_enabled ? 1 : 0
  zone_id = local.route53_zone_id_final
  name    = local.custom_domain_hostname
  type    = "CNAME"
  ttl     = 300
  records = [azurerm_cdn_frontdoor_endpoint.basilisk[0].host_name]

  depends_on = [azurerm_cdn_frontdoor_custom_domain_association.public]
}

# The whole point of the AND above is that it can swallow a mistake: set
# custom_domain, forget enable_front_door, and every resource that would have
# served that hostname quietly drops to count = 0 while the plan comes back
# green. The only symptom is a public URL output that is not the hostname you
# asked for, in a plan nobody reads to the bottom of.
#
# This is where that becomes a plan-time error instead.
#
# `precondition`, not `check`: a check block reports a WARNING and lets the
# apply succeed, which is the same silent-drop failure with extra text. A
# failed precondition stops the plan.
#
# On `terraform_data` rather than one of the resources above, for two reasons.
# The resources this protects are exactly the ones that are not created in the
# failure case -- a check hung on a count = 0 resource never runs -- so it has
# to live on something unconditional. And terraform_data needs no provider, so
# the precondition is evaluated before, and independently of, any cloud
# credentials: it fails the plan on a laptop with no Azure login, which is
# where this mistake actually gets made. It creates nothing and costs nothing.
resource "terraform_data" "custom_domain_requires_front_door" {
  input = var.custom_domain

  lifecycle {
    precondition {
      condition     = var.custom_domain == "" || var.enable_front_door
      error_message = <<-EOT
        custom_domain is set, but enable_front_door is false.

        The custom domain is a child of the Azure Front Door profile: it holds the
        managed TLS certificate and is associated to the Front Door routes, so it
        cannot be deployed without one. Deploying anyway would silently serve the
        Function App's own hostname instead of the domain you configured.

        Either set enable_front_door = true, or clear custom_domain (and
        route53_zone_name / route53_zone_id with it) to accept the Function App
        hostname as the public URL.
      EOT
    }
  }
}
