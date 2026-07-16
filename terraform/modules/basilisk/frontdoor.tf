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

resource "azurerm_cdn_frontdoor_origin_group" "function" {
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
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.function.id
  enabled                        = true
  host_name                      = azurerm_function_app_flex_consumption.basilisk.default_hostname
  http_port                      = 80
  https_port                     = 443
  origin_host_header             = azurerm_function_app_flex_consumption.basilisk.default_hostname
  priority                       = 1
  weight                         = 1000
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_origin_group" "static" {
  name                     = "basilisk-static-origins"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk.id

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/index.html"
    request_type        = "GET"
    protocol            = "Https"
    interval_in_seconds = 240
  }
}

resource "azurerm_cdn_frontdoor_origin" "static" {
  name                           = "static-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.static.id
  enabled                        = true
  host_name                      = azurerm_storage_account.basilisk.primary_web_host
  http_port                      = 80
  https_port                     = 443
  origin_host_header             = azurerm_storage_account.basilisk.primary_web_host
  priority                       = 1
  weight                         = 1000
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_rule_set" "static_cache" {
  name                     = "StaticCache"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk.id
}

resource "azurerm_cdn_frontdoor_rule" "static_assets_cache" {
  name                      = "CacheStaticAssets"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.static_cache.id
  order                     = 1
  behavior_on_match         = "Continue"

  conditions {
    url_path_condition {
      operator     = "Contains"
      match_values = ["/css/", "/js/", "/assets/"]
    }
  }

  actions {
    route_configuration_override_action {
      cdn_frontdoor_origin_group_id   = azurerm_cdn_frontdoor_origin_group.static.id
      forwarding_protocol             = "HttpsOnly"
      cache_behavior                  = "OverrideAlways"
      cache_duration                  = "7.00:00:00"
      query_string_caching_behavior   = "IgnoreQueryString"
      compression_enabled             = true
    }
  }
}

resource "azurerm_cdn_frontdoor_rule" "static_html_cache" {
  name                      = "CacheStaticHtml"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.static_cache.id
  order                     = 2
  behavior_on_match         = "Continue"

  conditions {
    url_file_extension_condition {
      operator         = "Equal"
      match_values     = ["html"]
      negate_condition = true
    }
    url_path_condition {
      operator         = "Contains"
      match_values     = ["/pks/", "/api/", "/claim/", "/.auth/", "/health"]
      negate_condition = true
    }
  }

  actions {
    route_configuration_override_action {
      cdn_frontdoor_origin_group_id   = azurerm_cdn_frontdoor_origin_group.static.id
      forwarding_protocol             = "HttpsOnly"
      cache_behavior                  = "OverrideAlways"
      cache_duration                  = "1.00:00:00"
      query_string_caching_behavior   = "UseQueryString"
      compression_enabled             = true
    }
  }
}

resource "azurerm_cdn_frontdoor_route" "api" {
  name                          = "api-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.basilisk.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.function.id
  supported_protocols           = ["Http", "Https"]
  patterns_to_match             = ["/pks/*", "/api/*", "/claim/*", "/.auth/*", "/health"]
  forwarding_protocol           = "HttpsOnly"
  link_to_default_domain        = true
  https_redirect_enabled        = true
  cdn_frontdoor_custom_domain_ids = local.custom_domain_enabled ? [azurerm_cdn_frontdoor_custom_domain.public[0].id] : []

  # No cache block — API, auth, and HKP responses must never be cached.
  # Caching /.auth/* causes a redirect loop: Easy Auth's nonce cookie is never
  # set when the callback GET is served from cache (TCP_HIT), so the POST
  # has no valid state and Easy Auth restarts the OAuth flow indefinitely.

  depends_on = [azurerm_cdn_frontdoor_origin.function]
}

resource "azurerm_cdn_frontdoor_route" "static" {
  name                          = "static-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.basilisk.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.static.id
  cdn_frontdoor_rule_set_ids    = [azurerm_cdn_frontdoor_rule_set.static_cache.id]
  supported_protocols           = ["Http", "Https"]
  patterns_to_match             = ["/", "/*"]
  forwarding_protocol           = "HttpsOnly"
  link_to_default_domain        = true
  https_redirect_enabled        = true
  cdn_frontdoor_custom_domain_ids = local.custom_domain_enabled ? [azurerm_cdn_frontdoor_custom_domain.public[0].id] : []

  cache {
    query_string_caching_behavior = "UseQueryString"
    compression_enabled           = true
    content_types_to_compress     = ["text/html", "text/css", "application/javascript"]
  }

  depends_on = [
    azurerm_cdn_frontdoor_origin.static,
    azurerm_storage_account_static_website.portal,
  ]
}

resource "azurerm_cdn_frontdoor_security_policy" "basilisk" {
  name                     = "basilisk-waf"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk.id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.basilisk.id

      association {
        patterns_to_match = ["/*"]

        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.basilisk.id
        }

        dynamic "domain" {
          for_each = local.custom_domain_enabled ? [1] : []
          content {
            cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_custom_domain.public[0].id
          }
        }
      }
    }
  }
}
