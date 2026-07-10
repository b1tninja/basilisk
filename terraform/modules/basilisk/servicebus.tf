resource "azurerm_servicebus_namespace" "basilisk" {
  name                = "${var.name_prefix}-sb"
  location            = azurerm_resource_group.basilisk.location
  resource_group_name = azurerm_resource_group.basilisk.name
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_servicebus_queue" "key_events" {
  name         = "key-events"
  namespace_id = azurerm_servicebus_namespace.basilisk.id
}

resource "azurerm_servicebus_queue" "sendtoken_events" {
  name         = "sendtoken-events"
  namespace_id = azurerm_servicebus_namespace.basilisk.id
}

data "azurerm_servicebus_namespace_authorization_rule" "root" {
  name         = "RootManageSharedAccessKey"
  namespace_id = azurerm_servicebus_namespace.basilisk.id
}
