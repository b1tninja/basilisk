terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # Upper bound because 5.x is a breaking rename, not a drift risk: a clean
      # `terraform init` with no lock file resolves 5.4.0 today, and the module
      # does not validate under it -- `behavior_on_match` became
      # `behaviour_on_match` and the Front Door rule blocks changed shape. The
      # committed .terraform.lock.hcl pins 4.81.0, so CI never saw this; anyone
      # who deletes the lock or runs `init -upgrade` did.
      version = "~> 5.10"
    }
    azapi = {
      source  = "Azure/azapi"
      version = ">= 2.0.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}
