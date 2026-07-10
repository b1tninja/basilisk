resource "random_password" "token_secret" {
  length  = 48
  special = false
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

  maximum_instance_count = 100
  instance_memory_in_mb  = 2048

  identity {
    type = "SystemAssigned"
  }

  site_config {}

  app_settings = {
    AzureWebJobsStorage             = azurerm_storage_account.basilisk.primary_connection_string
    FUNCTIONS_EXTENSION_VERSION     = "~4"
    ServiceBusConnection            = data.azurerm_servicebus_namespace_authorization_rule.root.primary_connection_string
    AZURE_STORAGE_CONNECTION_STRING = azurerm_storage_account.basilisk.primary_connection_string
    BASILISK_CACHE_MODE             = "redirect"
    BASILISK_DEV_APPROVE            = "0"
    BASILISK_TOKEN_SECRET           = random_password.token_secret.result
  }

  tags = var.tags
}

resource "azurerm_app_service_auth_settings_v2" "basilisk" {
  resource_id = azurerm_function_app_flex_consumption.basilisk.id

  auth_enabled           = true
  require_authentication = true
  unauthenticated_action = "AllowAnonymous"

  login {
    token_store_enabled = false
  }

  active_directory_v2 {
    client_id            = "00000000-0000-0000-0000-000000000000"
    tenant_id            = var.entra_tenant_id
    allowed_applications = []
    allowed_audiences    = []
  }
}
