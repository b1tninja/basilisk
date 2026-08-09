# Quorum signalling.
#
# Signalling used to be a process-global dict in the Function App, which on a
# Consumption plan is per-instance and dies when the instance recycles: two
# peers met only when they happened to land on the same warm worker. The state
# lives here now. The app never stores a room — it mints a JWT scoped to one
# group and hands the client a URL.

resource "azurerm_web_pubsub" "basilisk" {
  name                = "${var.name_prefix}-wps"
  location            = var.location
  resource_group_name = azurerm_resource_group.basilisk.name

  # Free_F1 caps at 20 concurrent connections and 20 000 messages/day. That is
  # the honest limit of this design, not an oversight: one connection per peer
  # per session, and signalling moves onto the peer data channels as soon as a
  # pair meshes, so message count scales with peers rather than with how long
  # people talk. Raise `sku` to Standard_S1 for more; nothing in the app
  # changes.
  sku      = var.web_pubsub_sku
  capacity = 1

  # Clients authenticate with a token this app signed. There are no upstream
  # event handlers — the server is never in the message path — so there is
  # nothing for an anonymous connection to be useful for.
  public_network_access_enabled = true
  aad_auth_enabled              = true
  local_auth_enabled            = true
  tls_client_cert_enabled       = false

  tags = var.tags
}

resource "azurerm_web_pubsub_hub" "quorum" {
  name          = var.web_pubsub_hub
  web_pubsub_id = azurerm_web_pubsub.basilisk.id

  anonymous_connections_enabled = false
}

locals {
  # The one source the CSP cannot hardcode: a second deployment has a different
  # hostname, and a literal here would be the first deployment's.
  signaling_wss_origin = "wss://${azurerm_web_pubsub.basilisk.hostname}"
}
