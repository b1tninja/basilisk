# PerGB2018 bills per GB ingested. FrontDoorAccessLog below writes one record per
# request, so ingestion scales with public traffic and is the line item most able
# to surprise. daily_quota_gb is a hard stop: ingestion halts for the rest of the
# UTC day once the cap is hit (data already ingested is retained, and the cap
# resets daily). Losing the tail of a day's access logs is the intended trade.
resource "azurerm_log_analytics_workspace" "basilisk" {
  name                = "${var.name_prefix}-logs"
  location            = azurerm_resource_group.basilisk.location
  resource_group_name = azurerm_resource_group.basilisk.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = var.log_analytics_daily_quota_gb
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

  amount     = var.budget_amount
  time_grain = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
  }

  # Actual spend, early warning.
  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    threshold_type = "Actual"
    # Azure rejects budgets with no contacts. Owner role always receives the alert;
    # optional emails can be added via var.budget_contact_emails.
    contact_roles  = ["Owner"]
    contact_emails = var.budget_contact_emails
    contact_groups = [azurerm_monitor_action_group.ops.id]
  }

  # Actual spend, ceiling reached.
  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThan"
    threshold_type = "Actual"
    contact_roles  = ["Owner"]
    contact_emails = var.budget_contact_emails
    contact_groups = [azurerm_monitor_action_group.ops.id]
  }

  # Forecast, which is the one that arrives in time to act on. An actual-spend
  # alert says the money is already gone; a forecast alert fires while the month
  # still has room to change course.
  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThan"
    threshold_type = "Forecasted"
    contact_roles  = ["Owner"]
    contact_emails = var.budget_contact_emails
    contact_groups = [azurerm_monitor_action_group.ops.id]
  }

  lifecycle {
    ignore_changes = [time_period]
  }
}
