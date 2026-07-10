resource "azurerm_cdn_frontdoor_profile" "basilisk" {
  name                = "${var.name_prefix}-fd"
  resource_group_name = azurerm_resource_group.basilisk.name
  sku_name            = "Standard_AzureFrontDoor"
  tags                = var.tags
}

resource "azurerm_cdn_frontdoor_firewall_policy" "basilisk" {
  name                = "${replace(var.name_prefix, "-", "")}waf"
  resource_group_name = azurerm_resource_group.basilisk.name
  sku_name            = "Standard_AzureFrontDoor"
  enabled             = true
  mode                = "Prevention"

  custom_rule {
    name                           = "UploadRateLimit"
    enabled                        = true
    priority                       = 100
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = var.upload_rate_limit_per_minute
    type                           = "RateLimitRule"
    action                         = "Block"

    match_condition {
      match_variable = "RequestUri"
      operator       = "Contains"
      match_values   = ["/pks/add"]
    }

    match_condition {
      match_variable = "RequestMethod"
      operator       = "Equal"
      match_values   = ["POST"]
    }
  }

  custom_rule {
    name                           = "V2UploadRateLimit"
    enabled                        = true
    priority                       = 110
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = var.v2_upload_rate_limit_per_minute
    type                           = "RateLimitRule"
    action                         = "Block"

    match_condition {
      match_variable = "RequestUri"
      operator       = "Contains"
      match_values   = ["/pks/v2/"]
    }

    match_condition {
      match_variable = "RequestMethod"
      operator       = "Equal"
      match_values   = ["POST", "PUT"]
    }
  }

  custom_rule {
    name                           = "SendtokenRateLimit"
    enabled                        = true
    priority                       = 120
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = var.sendtoken_rate_limit_per_minute
    type                           = "RateLimitRule"
    action                         = "Block"

    match_condition {
      match_variable = "RequestUri"
      operator       = "Contains"
      match_values   = ["/pks/v2/sendtoken"]
    }
  }

  tags = var.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "basilisk" {
  name                     = "${var.name_prefix}-endpoint"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk.id
  tags                     = var.tags
}

resource "azurerm_cdn_frontdoor_origin_group" "basilisk" {
  name                     = "basilisk-origins"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk.id

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/health"
    request_type        = "GET"
    protocol            = "Https"
    interval_in_seconds = 120
  }
}

resource "azurerm_cdn_frontdoor_origin" "function" {
  name                           = "function-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.basilisk.id
  enabled                        = true
  host_name                      = azurerm_function_app_flex_consumption.basilisk.default_hostname
  http_port                      = 80
  https_port                     = 443
  origin_host_header             = azurerm_function_app_flex_consumption.basilisk.default_hostname
  priority                       = 1
  weight                         = 1000
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_route" "basilisk" {
  name                          = "default-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.basilisk.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.basilisk.id
  supported_protocols           = ["Http", "Https"]
  patterns_to_match             = ["/*"]
  forwarding_protocol           = "HttpsOnly"
  link_to_default_domain        = true
  https_redirect_enabled        = true

  cache {
    query_string_caching_behavior = "IgnoreQueryString"
    compression_enabled           = true
    content_types_to_compress     = ["application/pgp-keys"]
  }

  depends_on = [azurerm_cdn_frontdoor_origin.function]
}

resource "azurerm_cdn_frontdoor_security_policy" "basilisk" {
  name                     = "basilisk-waf"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk.id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.basilisk.id

      association {
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.basilisk.id
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}
