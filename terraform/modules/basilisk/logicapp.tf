locals {
  approval_workflow_definition = jsondecode(
    templatefile("${path.module}/files/approval-workflow.json.tpl", {
      mail_provider = var.mail_provider
    })
  )
}

# Gated on the feature it implements. The Service Bus trigger in the workflow
# definition is a Consumption-tier polling trigger -- it wakes on an interval
# and checks the queue whether or not a message is there, and the connector has
# no push variant to switch to -- so a deployed-but-idle workflow bills a fixed
# amount per month for polling a queue nothing is meant to read. With
# require_manager_approval false the function app publishes no approval requests
# and sets BASILISK_REQUIRE_MANAGER_APPROVAL=0, so the polling was the whole
# cost of the feature and none of its behaviour. Not deploying it is the fix.
#
# The module creates no API connection of its own: `$connections` is passed
# empty and the mail connector is wired up out of band, so there is nothing
# else here to gate.
resource "azapi_resource" "approval_logic_app" {
  count     = var.require_manager_approval ? 1 : 0
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