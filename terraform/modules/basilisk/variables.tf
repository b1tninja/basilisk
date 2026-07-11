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

variable "existing_token_secret" {
  type        = string
  description = "Use an existing HMAC secret when importing infrastructure (skips random_password)."
  default     = ""
  sensitive   = true
}

variable "google_client_id" {
  type        = string
  description = "Google OAuth2 client ID for Easy Auth (optional; omit to disable Google sign-in)."
  default     = ""
}

variable "google_client_secret" {
  type        = string
  description = "Google OAuth2 client secret for Easy Auth (optional)."
  default     = ""
  sensitive   = true
}

variable "enable_microsoft_auth" {
  type        = bool
  description = "Enable Microsoft Entra ID (Easy Auth active_directory_v2)."
  default     = true
}

variable "enable_google_auth" {
  type        = bool
  description = "Enable Google sign-in (requires google_client_id and google_client_secret)."
  default     = false
}

variable "oauth_authorized_domain" {
  type        = string
  description = "Root domain you own for Google OAuth consent screen Authorized domains (e.g. example.com). Leave empty if using only *.azurewebsites.net."
  default     = ""
}

variable "custom_domain" {
  type        = string
  description = "Public hostname on Front Door (e.g. keys.b1tninja.com). Leave empty to use only the default *.azurefd.net hostname."
  default     = ""
}

variable "route53_zone_name" {
  type        = string
  description = "Route53 hosted zone name for custom_domain DNS (e.g. b1tninja.com). Used only when route53_zone_id is empty."
  default     = ""
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID (e.g. Z0123456789ABC). Preferred — avoids zone lookup IAM permissions."
  default     = ""
}
