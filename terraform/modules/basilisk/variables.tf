variable "name_prefix" {
  type        = string
  description = "Resource name prefix (e.g. basilisk-dev)."
}

variable "location" {
  type        = string
  description = "Azure region for regional resources."
}

variable "entra_tenant_id" {
  type        = string
  description = "Microsoft Entra tenant ID for Function App Easy Auth."
}

variable "mail_provider" {
  type        = string
  description = "Logic App mail connector: office365 or gmail."
  default     = "office365"

  validation {
    condition     = contains(["office365", "gmail"], var.mail_provider)
    error_message = "mail_provider must be office365 or gmail."
  }
}

variable "require_manager_approval" {
  type        = bool
  description = "Require manager approval for O365 mail flow (reserved for Logic App)."
  default     = false
}

variable "enable_worm_immutability" {
  type        = bool
  description = "Enable WORM immutability on the certs blob container."
  default     = true
}

variable "worm_retention_days" {
  type        = number
  description = "Immutability retention days for cert blobs."
  default     = 365
}

variable "upload_rate_limit_per_minute" {
  type    = number
  default = 10
}

variable "v2_upload_rate_limit_per_minute" {
  type    = number
  default = 5
}

variable "sendtoken_rate_limit_per_minute" {
  type    = number
  default = 3
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to supported resources."
  default     = {}
}
