variable "name_prefix" {
  type        = string
  description = "Resource name prefix."
  default     = "basilisk-dev"
}

variable "location" {
  type        = string
  description = "Azure region. Leave empty to use eastus; deploy script auto-detects before apply."
  default     = ""
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
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "existing_token_secret" {
  type        = string
  description = "Existing BASILISK_TOKEN_SECRET when importing pre-created infrastructure."
  default     = ""
  sensitive   = true
}
