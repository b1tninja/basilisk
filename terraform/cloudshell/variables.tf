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

variable "google_client_id" {
  type        = string
  description = "Google OAuth2 client ID for Easy Auth (optional; leave empty to disable)."
  default     = ""
}

variable "google_client_secret" {
  type        = string
  description = "Google OAuth2 client secret for Easy Auth (optional)."
  default     = ""
  sensitive   = true
}

variable "enable_microsoft_auth" {
  type    = bool
  default = true
}

variable "enable_google_auth" {
  type    = bool
  default = false
}

variable "oauth_authorized_domain" {
  type        = string
  description = "Root domain you own for Google OAuth consent screen (e.g. example.com). Optional."
  default     = "b1tninja.com"
}

variable "custom_domain" {
  type        = string
  description = "Public hostname on Front Door (e.g. keys.b1tninja.com). Leave empty to skip custom domain."
  default     = "keys.b1tninja.com"
}

variable "route53_zone_name" {
  type        = string
  description = "Route53 hosted zone for custom_domain (e.g. b1tninja.com). Ignored when route53_zone_id is set."
  default     = "b1tninja.com"
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID. Set this to avoid ListHostedZones/ListTagsForResource IAM permissions."
  default     = "Z026512234X4JPOD7PZH1"
}

variable "aws_region" {
  type        = string
  description = "AWS region for the Route53 provider (Route53 is global; us-east-1 is typical)."
  default     = "us-east-1"
}
