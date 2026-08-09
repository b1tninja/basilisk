locals {
  # Azure forbids namespace names ending in -sb, -mgmt, or a hyphen.
  servicebus_namespace_name = "${var.name_prefix}-bus"
}

# Basic bills per operation with no namespace base charge; Standard adds a fixed
# monthly fee for topics, sessions, duplicate detection and scheduled delivery.
# This namespace carries three plain queues and uses none of those, so Basic is
# the cheaper tier with no loss. Raise to Standard if a topic is ever introduced.
resource "azurerm_servicebus_namespace" "basilisk" {
  name                = local.servicebus_namespace_name
  location            = azurerm_resource_group.basilisk.location
  resource_group_name = azurerm_resource_group.basilisk.name
  sku                 = var.servicebus_sku
  tags                = var.tags
}

# Declared TTL, because the default is not portable between tiers. Left unset,
# these queues inherit Standard's default of TimeSpan.MaxValue
# (P10675199DT2H48M5.4775807S -- forever). Basic caps TTL at 14 days, so a
# namespace downgrade is refused with:
#
#   409 MessagingGatewayConflict: Namespace cannot be downgraded because at
#   least one queue 'key-approved' has DefaultMessageTimeToLive set with an
#   invalid value, the value need to be between 00:00:01 and 14.00:00:00
#
# 14 days is Basic's ceiling, so this is the smallest possible change to
# existing behaviour. These carry key-ingest and mail events that Logic Apps
# consume within seconds; a message still sitting here after two weeks is not
# one anybody wants delivered.
locals {
  # Queues must be at a tier-portable TTL *before* the namespace SKU moves --
  # they depend on the namespace, so a failing namespace update stops them from
  # ever being applied. See var.servicebus_sku.
  servicebus_queue_ttl = "P14D"
}

resource "azurerm_servicebus_queue" "key_events" {
  name                = "key-events"
  namespace_id        = azurerm_servicebus_namespace.basilisk.id
  default_message_ttl = local.servicebus_queue_ttl
}

resource "azurerm_servicebus_queue" "key_approved" {
  name                = "key-approved"
  namespace_id        = azurerm_servicebus_namespace.basilisk.id
  default_message_ttl = local.servicebus_queue_ttl
}

resource "azurerm_servicebus_queue" "sendtoken_events" {
  name                = "sendtoken-events"
  namespace_id        = azurerm_servicebus_namespace.basilisk.id
  default_message_ttl = local.servicebus_queue_ttl
}

# Least-privilege rule for the Function App (send + listen). Avoid RootManageSharedAccessKey.
resource "azurerm_servicebus_namespace_authorization_rule" "function" {
  name         = "basilisk-function"
  namespace_id = azurerm_servicebus_namespace.basilisk.id
  listen       = true
  send         = true
  manage       = false
}
