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

variable "upstream_enabled" {
  type        = bool
  description = "Offer client-direct upstream HKP in the portal."
  default     = false
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
  default     = ""
}

variable "custom_domain" {
  type        = string
  description = "Public hostname on Front Door (e.g. keys.b1tninja.com). Leave empty to skip custom domain. Set explicitly in tfvars for production."
  default     = ""
}

variable "route53_zone_name" {
  type        = string
  description = "Route53 hosted zone for custom_domain (e.g. b1tninja.com). Ignored when route53_zone_id is set."
  default     = ""
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID. Set this to avoid ListHostedZones/ListTagsForResource IAM permissions."
  default     = ""
}

variable "budget_contact_emails" {
  type        = list(string)
  description = "Optional email addresses for the monthly spend budget alert (Owner role is always notified)."
  default     = []
}

variable "aws_region" {
  type        = string
  description = "AWS region for the Route53 provider (Route53 is global; us-east-1 is typical)."
  default     = "us-east-1"
}

variable "enable_front_door" {
  type        = bool
  description = "Deploy Azure Front Door and its WAF. Standard bills a flat monthly base fee that does not depend on traffic — it was $35.00 of a $61.11 month against $0.02 of actual data transfer, so it is opt-in rather than opt-out. Enabling it is what makes custom_domain possible; the domain is a child of the profile. Use profiles/production.tfvars rather than setting this by hand."
  default     = false
}

variable "function_instance_memory_mb" {
  type        = number
  description = "Memory per Function instance. Flex Consumption bills instance-seconds multiplied by this, so it scales the whole compute line: $10.99 of execution time last month against $0.01 of executions. Allowed values are 512, 2048 and 4096."
  default     = 2048
}

variable "budget_amount" {
  type        = number
  description = "Monthly cost ceiling in the billing currency. Alerts only — a budget cannot stop spending. Set it near the expected run rate: a ceiling well above what the deployment costs is a ceiling that never fires, which is how a $61 month went unremarked under a $100 budget."
  default     = 100
}
