# Remote state via Azure Storage. Config supplied at init time (backend.hcl or -backend-config flags).
# See scripts/terraform-init.sh and scripts/bootstrap-tfstate.sh.

terraform {
  backend "azurerm" {}
}
