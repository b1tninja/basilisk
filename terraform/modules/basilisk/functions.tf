resource "random_password" "token_secret" {
  count   = var.existing_token_secret == "" ? 1 : 0
  length  = 48
  special = false
}

locals {
  token_secret = var.existing_token_secret != "" ? var.existing_token_secret : random_password.token_secret[0].result
  auth_providers = join(",", compact([
    var.enable_microsoft_auth ? "microsoft" : "",
    var.enable_google_auth && var.google_client_id != "" ? "google" : "",
  ]))
}

resource "azurerm_service_plan" "basilisk" {
  name                = "${var.name_prefix}-plan"
  resource_group_name = azurerm_resource_group.basilisk.name
  location            = azurerm_resource_group.basilisk.location
  os_type             = "Linux"
  sku_name            = "FC1"
  tags                = var.tags
}

resource "azurerm_function_app_flex_consumption" "basilisk" {
  name                = "${var.name_prefix}-fn"
  resource_group_name = azurerm_resource_group.basilisk.name
  location            = azurerm_resource_group.basilisk.location
  service_plan_id     = azurerm_service_plan.basilisk.id

  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "${azurerm_storage_account.basilisk.primary_blob_endpoint}${azurerm_storage_container.deployments.name}"
  storage_authentication_type = "SystemAssignedIdentity"

  runtime_name    = "python"
  runtime_version = "3.13"

  # The cost stop. 100 was the platform default restated, so it constrained
  # nothing: a traffic spike or an abuse burst scaled out unbounded. No
  # always-ready instance is configured, so this app scales to zero and pays
  # a cold start on the first request after idle.
  maximum_instance_count = var.function_maximum_instance_count
  instance_memory_in_mb  = var.function_instance_memory_mb

  identity {
    type = "SystemAssigned"
  }

  site_config {}

  auth_settings_v2 {
    auth_enabled           = true
    runtime_version        = "~2"
    require_authentication = true
    unauthenticated_action = "AllowAnonymous"
    # Front Door sets X-Forwarded-Host to the public hostname (custom domain / *.azurefd.net).
    # Without Standard, Easy Auth builds OAuth callbacks from the origin Host
    # (*.azurewebsites.net), so users land on the Function App URL and the session
    # cookie never sticks on the public domain (repeated Google consent prompts).
    forward_proxy_convention = "Standard"

    dynamic "active_directory_v2" {
      for_each = var.enable_microsoft_auth ? [1] : []
      content {
        client_id            = "00000000-0000-0000-0000-000000000000"
        tenant_auth_endpoint = "https://login.microsoftonline.com/${var.entra_tenant_id}/v2.0/"
      }
    }

    dynamic "google_v2" {
      for_each = var.enable_google_auth && var.google_client_id != "" ? [1] : []
      content {
        client_id                  = var.google_client_id
        client_secret_setting_name = "GOOGLE_PROVIDER_AUTHENTICATION_SECRET"
        allowed_audiences          = []
      }
    }

    login {
      token_store_enabled = false
      # Not local.public_url, though the values are the same: with Front Door
      # off that local resolves to this app's own default_hostname, and a
      # resource may not reference itself. Same three URLs, built from inputs.
      allowed_external_redirect_urls = distinct(compact(concat(
        [local.custom_domain_enabled ? "https://${var.custom_domain}" : ""],
        local.front_door_enabled ? ["https://${azurerm_cdn_frontdoor_endpoint.basilisk[0].host_name}"] : [],
        ["https://${var.name_prefix}-fn.azurewebsites.net"],
      )))
    }
  }

  app_settings = merge(
    {
      AzureWebJobsStorage               = azurerm_storage_account.basilisk.primary_connection_string
      FUNCTIONS_EXTENSION_VERSION       = "~4"
      ServiceBusConnection              = azurerm_servicebus_namespace_authorization_rule.function.primary_connection_string
      AZURE_STORAGE_CONNECTION_STRING   = azurerm_storage_account.basilisk.primary_connection_string
      AZURE_WEBPUBSUB_CONNECTION_STRING = azurerm_web_pubsub.basilisk.primary_connection_string
      BASILISK_WEBPUBSUB_HUB            = azurerm_web_pubsub_hub.notebook.name
      BASILISK_CACHE_MODE               = "redirect"
      BASILISK_DEV_APPROVE              = "0"
      BASILISK_REQUIRE_MANAGER_APPROVAL = var.require_manager_approval ? "1" : "0"
      BASILISK_UPSTREAM_ENABLED         = var.upstream_enabled ? "1" : "0"
      BASILISK_UPSTREAM_ALLOWLIST       = var.upstream_allowlist
      BASILISK_UPSTREAM_DEFAULT         = var.upstream_default
      # Key Vault reference — secret value is not stored in app settings plaintext.
      BASILISK_TOKEN_SECRET     = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.token_secret.versionless_id})"
      BASILISK_AUTH_PROVIDERS   = local.auth_providers
      BASILISK_PENDING_TTL_DAYS = "30"
    },
    # Reject requests that bypass Front Door (must match the profile GUID).
    #
    # Merged in rather than set to null or "": this setting is a kill switch for
    # the app's own front door, and with no Front Door in front of it every
    # request is a bypass. basilisk/security/edge.py reads it with
    # os.environ.get(...).strip() and returns True when the result is falsy, so
    # an empty string does fail open -- but that leaves the app one accidental
    # non-empty value away from 403ing every request, and app settings are
    # visible and editable in the portal. Absent is the state that cannot be
    # half-set.
    local.front_door_enabled ? {
      BASILISK_AFD_ID = azurerm_cdn_frontdoor_profile.basilisk[0].resource_guid
    } : {},
    var.enable_google_auth && var.google_client_secret != "" ? {
      GOOGLE_PROVIDER_AUTHENTICATION_SECRET = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.google_client_secret[0].versionless_id})"
    } : {}
  )

  tags = var.tags

  # Do not depend_on kv_function_secrets — that role needs this app's identity (cycle).
  # Apply order: Key Vault secret → Function App → role assignment. KV refs resolve at runtime.
  depends_on = [
    azurerm_key_vault_secret.token_secret,
  ]
}
