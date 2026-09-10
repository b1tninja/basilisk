locals {
  approval_workflow_definition = jsondecode(
    templatefile("${path.module}/files/approval-workflow.json.tpl", {
      mail_provider                  = var.mail_provider
      approval_poll_interval_minutes = var.approval_poll_interval_minutes
    })
  )
}

# Gated on its own switch rather than on require_manager_approval.
#
# The first version of this gate used that variable, which was wrong: one
# workflow serves two events, and only `claim.submitted` is the approval step.
# `key.pending` is the ordinary verification mail that `basilisk/hkp/add.py`
# enqueues on every accepted upload no matter what that setting says, so gating
# here on it silenced verification for a reason that had nothing to do with it.
#
# Deploying this is still not the same as making it work. The module passes
# `$connections = {}` and creates no `Microsoft.Web/connections`, so the
# trigger binds a connection id that resolves to nothing. Two connections have
# to exist first, and the mail one needs an interactive consent Terraform
# cannot give. That is why the default is false rather than true with a caveat.
resource "azapi_resource" "approval_logic_app" {
  count     = var.enable_approval_workflow ? 1 : 0
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