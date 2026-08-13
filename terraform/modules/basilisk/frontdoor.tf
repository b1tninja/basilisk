# CSP must match basilisk/serve.py's `_CSP` and the `<meta>` the pages ship.
# The browser enforces the *intersection* of the meta policy and this header,
# and Front Door overwrites what the origin sent — so a source missing from any
# one of the three is a source that does not exist. Everything here is a
# build-time constant except the signalling socket, whose hostname is
# per-deployment.
#
# That one source has to reach the `<meta>` too, and this route never touches
# Flask: `/*` goes to the storage account's `$web` container, so the portal HTML
# is blob bytes with whatever policy was uploaded. `scripts/package-static.sh`
# merges `signaling_wss_origin` into every page before upload, reading it from
# the `signaling_wss_origin` output. It used to be merged per request by
# `basilisk/portal/static.py`, which is a path these documents do not take —
# the header carried `wss://` and the meta did not, and signalling was blocked
# on the deployed site while every configuration file looked right.
#
# 'wasm-unsafe-eval' is OpenPGP.js Argon2 WASM only, not JS eval; integrity of
# that WASM is SRI on the embedding chunk (see serve.py).
locals {
  content_security_policy = join(" ", [
    "default-src 'none';",
    "script-src 'self' 'wasm-unsafe-eval';",
    "style-src 'self';",
    "connect-src 'self' https://keys.openpgp.org https://keys.mailvelope.com ${local.signaling_wss_origin};",
    "img-src 'self' data:;",
    "font-src 'self';",
    "frame-ancestors 'none';",
    "object-src 'none';",
    "base-uri 'self';",
    "form-action 'self';",
  ])
}

# RESIDUAL RISK: Standard SKU supports custom rate-limit rules only.
# Microsoft Default Rule Set / Bot Manager require Premium_AzureFrontDoor.
# Upgrade path: change both sku_name values below to Premium_AzureFrontDoor and
# attach managed_rule { type = "Microsoft_DefaultRuleSet" version = "2.1" }.
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

resource "azurerm_cdn_frontdoor_rule_set" "security" {
  name                     = "SecurityHeaders"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.basilisk.id
}

resource "azurerm_cdn_frontdoor_rule" "security_headers" {
  name                      = "AddSecurityHeaders1"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.security.id
  order                     = 1
  behavior_on_match         = "Continue"

  actions {
    # CSP must match basilisk/serve.py. 'wasm-unsafe-eval' is required for
    # OpenPGP.js Argon2 WASM only — not JS eval. Integrity of that WASM is via
    # SRI on the embedding JS chunk (see comment on _CSP in serve.py).
    response_header_action {
      header_action = "Overwrite"
      header_name   = "Content-Security-Policy"
      value         = local.content_security_policy
    }
    response_header_action {
      header_action = "Overwrite"
      header_name   = "X-Content-Type-Options"
      value         = "nosniff"
    }
    response_header_action {
      header_action = "Overwrite"
      header_name   = "X-Frame-Options"
      value         = "DENY"
    }
    response_header_action {
      header_action = "Overwrite"
      header_name   = "Referrer-Policy"
      value         = "strict-origin-when-cross-origin"
    }
    response_header_action {
      header_action = "Overwrite"
      header_name   = "Strict-Transport-Security"
      value         = "max-age=31536000; includeSubDomains"
    }
  }
}

resource "azurerm_cdn_frontdoor_rule" "security_headers_extra" {
  name                      = "AddSecurityHeaders2"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.security.id
  order                     = 2
  behavior_on_match         = "Continue"

  actions {
    response_header_action {
      header_action = "Overwrite"
      header_name   = "Permissions-Policy"
      value         = "camera=(), geolocation=(), microphone=()"
    }
  }
}

# The four pages commit 4983e1e retired into the toolkit, and where each one's
# errand went. Written here because Flask's copy cannot fire on the deployed
# site: `static-route` below matches `/` and `/*` and sends them to the storage
# account's `$web` container — the same routing fact this file's header
# describes for CSP. Only /pks/*, /api/*, /claim/*, /.auth/* and /health reach
# the Function App, so `_RETIRED_PAGES` in basilisk/portal/static.py covers `docker
# compose`, `basilisk serve` and the test client, and on keys.b1tninja.com a
# bookmark to /my-keys was a blob 404 until these rules existed.
#
# THIS TABLE IS ONE OF THREE STATEMENTS OF ONE FACT. The others are
# `_RETIRED_PAGES` in basilisk/portal/static.py and `RETIRED_PAGES` in
# web/scripts/basilisk-dev-server.js. They cannot be collapsed into a shared file
# without this module reaching outside itself for repo content, so instead
# tests/unit/test_portal.py::test_a_retired_redirect_says_the_same_thing_in_all_three_places
# parses all three and fails when they disagree. Change one, change all three.
#
# The fragment is a separate field. `destination_path = "/toolkit#encrypt"` would
# be emitted as a literal %23; the `#` part is `destination_fragment`, given
# without the `#`. `/quorum` and `/my-keys` have no fragment (see static.py for
# why /quorum cannot address a room), so they pass "" — documented as "leave
# blank to preserve the incoming fragment", and a request never carries one,
# because browsers do not send the fragment to the server at all.
#
# `match_paths` HAS NO LEADING SLASH AND `destination_path` MUST HAVE ONE. Every
# other path in this file is written `/like/this`, so the asymmetry looks like a
# typo and is not. A Front Door request path "is the part of the URL after the
# hostname and a slash" and the configured value must match that form — "Don't
# include the leading slash (`/`)" (azurerm 4.81.0 docs, `url_path_condition`);
# `destination_path` is the opposite, "must be a string and include the leading
# `/`". Get this backwards and the rule silently never matches, which looks
# exactly like not having deployed it.
#
# `Equal`, never `Contains`: a redirect that over-matches is worse than the 404
# it replaces — `Contains "my-keys"` would swallow a future /my-keys-export, and
# nothing here may touch /pks/*, /api/*, /claim/*, /.auth/*, /health, /toolkit,
# /published or any other live page. `Equal` matches the whole path and nothing
# else. The trailing-slash variant is listed because blob storage 404s it, where
# Flask's router would have folded it onto the bare path first.
#
# No case transform: Flask matches these names case-sensitively, so a rule that
# also caught /Encrypt would be a behaviour the local server does not have.
locals {
  retired_pages = {
    encrypt = {
      name                 = "RetiredPageEncrypt"
      order                = 1
      match_paths          = ["encrypt", "encrypt/"]
      destination_path     = "/toolkit"
      destination_fragment = "encrypt"
    }
    decrypt = {
      name                 = "RetiredPageDecrypt"
      order                = 2
      match_paths          = ["decrypt", "decrypt/"]
      destination_path     = "/toolkit"
      destination_fragment = "decrypt"
    }
    quorum = {
      name                 = "RetiredPageQuorum"
      order                = 3
      match_paths          = ["quorum", "quorum/"]
      destination_path     = "/toolkit"
      destination_fragment = ""
    }
    my_keys = {
      name                 = "RetiredPageMyKeys"
      order                = 4
      match_paths          = ["my-keys", "my-keys/"]
      destination_path     = "/published"
      destination_fragment = ""
    }
  }
}

# In `static_cache` at orders 1-4, ahead of the two cache rules, rather than in a
# rule set of their own: `cdn_frontdoor_rule_set_ids` on a route is a set, so the
# order two rule sets are evaluated in is not something this configuration can
# state. Order *within* a rule set is, and the rule these must beat —
# `static_html_cache` — lives in this one. Putting them anywhere else would make
# correctness depend on whether a `url_redirect_action` outranks a
# `route_configuration_override_action` when both match, which is not documented.
#
# `Stop`, where the rules around them use `Continue`, because those are additive
# — headers and cache configuration that should all land on one request — and
# this one is terminal. The response is manufactured at the edge; there is no
# origin fetch left for `static_assets_cache` or `static_html_cache` to
# configure, and no body for a CSP to govern. The cost is that the `security`
# rule set's headers may not be applied to the 301 (whether they are depends on
# that same undefined rule-set order). That is acceptable: an empty redirect
# response has nothing for nosniff, X-Frame-Options or CSP to protect, and the
# destination is same-origin over https, where the full header set applies.
#
# `Moved` is Front Door's name for 301. The trap is `PermanentRedirect`, which
# reads like the right answer and is 308 — the status static.py explicitly did
# not pick, these being GET-only documents with no method to preserve. 301 is
# cached by browsers effectively forever, so it is deliberately hard to walk
# back: these retirements are permanent, the destinations are pages that already
# exist, and a 302 would ask every client to re-check a URL that is never
# coming back.
#
# `destination_hostname = ""` keeps the incoming host, so this works on both the
# *.azurefd.net endpoint and the custom domain. `query_string` is omitted, which
# preserves the incoming query string: nothing in these paths' history has a
# meaningful query, but dropping one would silently discard a UTM tag or a
# `?q=` that a reader pasted, and the toolkit ignores what it does not read.
resource "azurerm_cdn_frontdoor_rule" "retired_page" {
  for_each = local.retired_pages

  name                      = each.value.name
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.static_cache.id
  order                     = each.value.order
  behavior_on_match         = "Stop"

  conditions {
    url_path_condition {
      operator     = "Equal"
      match_values = each.value.match_paths
    }
  }

  actions {
    url_redirect_action {
      redirect_type        = "Moved"
      redirect_protocol    = "Https"
      destination_hostname = ""
      destination_path     = each.value.destination_path
      destination_fragment = each.value.destination_fragment
    }
  }
}

resource "azurerm_cdn_frontdoor_rule" "static_assets_cache" {
  name                      = "CacheStaticAssets"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.static_cache.id
  # Orders 1-4 are the retired-page redirects above; these two run after them.
  order             = 5
  behavior_on_match = "Continue"

  conditions {
    url_path_condition {
      operator     = "Contains"
      match_values = ["/css/", "/js/", "/assets/", "/importmaps/"]
    }
  }

  actions {
    route_configuration_override_action {
      cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.static.id
      forwarding_protocol           = "HttpsOnly"
      cache_behavior                = "OverrideAlways"
      cache_duration                = "7.00:00:00"
      query_string_caching_behavior = "IgnoreQueryString"
      compression_enabled           = true
    }
  }
}

resource "azurerm_cdn_frontdoor_rule" "static_html_cache" {
  name                      = "CacheStaticHtml"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.static_cache.id
  order                     = 6
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
      cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.static.id
      forwarding_protocol           = "HttpsOnly"
      # Portal HTML is static ($web blob), not the Function App — long CDN TTL
      # cuts origin fetches/egress. Integrity against mix-and-match comes from:
      #   · content-hashed /assets/* filenames
      #   · content-hashed /importmaps/importmap-*.json pins
      #   · mandatory Front Door purge on every static deploy
      # A short TTL is unnecessary cost; do not shrink this “for SRI”.
      cache_behavior                = "OverrideAlways"
      cache_duration                = "1.00:00:00"
      query_string_caching_behavior = "UseQueryString"
      compression_enabled           = true
    }
    # AFD allows max 5 actions/rule; headers here ensure CSP applies to cached HTML.
    # CSP must match basilisk/serve.py ('wasm-unsafe-eval' = OpenPGP Argon2 only; SRI pins embedding JS).
    response_header_action {
      header_action = "Overwrite"
      header_name   = "Content-Security-Policy"
      value         = local.content_security_policy
    }
    response_header_action {
      header_action = "Overwrite"
      header_name   = "X-Content-Type-Options"
      value         = "nosniff"
    }
    response_header_action {
      header_action = "Overwrite"
      header_name   = "X-Frame-Options"
      value         = "DENY"
    }
    response_header_action {
      header_action = "Overwrite"
      header_name   = "Referrer-Policy"
      value         = "strict-origin-when-cross-origin"
    }
  }
}

resource "azurerm_cdn_frontdoor_route" "api" {
  name                            = "api-route"
  cdn_frontdoor_endpoint_id       = azurerm_cdn_frontdoor_endpoint.basilisk.id
  cdn_frontdoor_origin_group_id   = azurerm_cdn_frontdoor_origin_group.function.id
  cdn_frontdoor_rule_set_ids      = [azurerm_cdn_frontdoor_rule_set.security.id]
  supported_protocols             = ["Http", "Https"]
  patterns_to_match               = ["/pks/*", "/api/*", "/claim/*", "/.auth/*", "/health"]
  forwarding_protocol             = "HttpsOnly"
  link_to_default_domain          = true
  https_redirect_enabled          = true
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
  cdn_frontdoor_rule_set_ids = [
    azurerm_cdn_frontdoor_rule_set.security.id,
    azurerm_cdn_frontdoor_rule_set.static_cache.id,
  ]
  supported_protocols             = ["Http", "Https"]
  patterns_to_match               = ["/", "/*"]
  forwarding_protocol             = "HttpsOnly"
  link_to_default_domain          = true
  https_redirect_enabled          = true
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
