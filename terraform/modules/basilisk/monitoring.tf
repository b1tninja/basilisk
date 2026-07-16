resource "azurerm_log_analytics_workspace" "basilisk" {
  name                = "${var.name_prefix}-logs"
  location            = azurerm_resource_group.basilisk.location
  resource_group_name = azurerm_resource_group.basilisk.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "frontdoor" {
  name                       = "${var.name_prefix}-fd-diag"
  target_resource_id         = azurerm_cdn_frontdoor_profile.basilisk.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.basilisk.id

  enabled_log {
    category = "FrontDoorAccessLog"
  }

  enabled_log {
    category = "FrontDoorWebApplicationFirewallLog"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_action_group" "ops" {
  name                = "${var.name_prefix}-ops"
  resource_group_name = azurerm_resource_group.basilisk.name
  short_name          = "basops"
  tags                = var.tags
}

resource "azurerm_consumption_budget_resource_group" "basilisk" {
  name              = "${var.name_prefix}-budget"
  resource_group_id = azurerm_resource_group.basilisk.id

  amount     = 100
  time_grain = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    threshold_type = "Actual"
    contact_emails = []
  }

  lifecycle {
    ignore_changes = [time_period]
  }
}
