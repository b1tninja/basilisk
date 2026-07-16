locals {
  approval_workflow_definition = jsondecode(
    templatefile("${path.module}/files/approval-workflow.json.tpl", {
      mail_provider = var.mail_provider
    })
  )
}

resource "azapi_resource" "approval_logic_app" {
  type      = "Microsoft.Logic/workflows@2019-05-01"
  name      = "${var.name_prefix}-approval-la"
  parent_id = azurerm_resource_group.basilisk.id
  location  = azurerm_resource_group.basilisk.location

  body = {
    properties = {
      state      = "Enabled"
      definition = local.approval_workflow_definition
      parameters = {
        "$connections" = {
          value = {}
        }
      }
    }
  }

  tags = var.tags

  depends_on = [azurerm_servicebus_queue.key_events]
}