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

variable "upstream_enabled" {
  type        = bool
  description = "Offer client-direct upstream HKP search in the portal (browser fetches allowlisted hosts)."
  default     = false
}

variable "upstream_allowlist" {
  type        = string
  description = "Comma-separated HTTPS keyserver hostnames the portal may call from the browser."
  default     = "keys.openpgp.org,keys.mailvelope.com"
}

variable "upstream_default" {
  type        = string
  description = "Default upstream keyserver hostname when the client omits keyserver=."
  default     = "keys.openpgp.org"
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

variable "web_pubsub_sku" {
  type        = string
  description = "Web PubSub SKU carrying quorum signalling. Free_F1 caps at 20 concurrent connections and 20000 messages/day."
  default     = "Free_F1"
}

variable "web_pubsub_hub" {
  type        = string
  description = "Web PubSub hub name for quorum signalling. Must match BASILISK_WEBPUBSUB_HUB."
  default     = "quorum"
}

variable "servicebus_sku" {
  type        = string
  description = "Service Bus tier. Basic bills per operation with no namespace base charge and carries queues only; Standard adds a fixed monthly fee and is required for topics, sessions, duplicate detection or scheduled delivery."

  # Basic, now that it is reachable. The downgrade is refused while any queue
  # holds a TTL above Basic's 14-day ceiling, and these queues inherited
  # Standard's TimeSpan.MaxValue default -- and could not be fixed in the same
  # apply that moves the SKU, because they depend on the namespace, so the
  # namespace update runs first and 409s before the queue updates run.
  #
  # Applied in order: run aec7083 landed `default_message_ttl = P14D` on all
  # three queues with the tier unchanged, which is what makes this reachable.
  # If the queue TTLs are ever raised past 14 days, this has to go back to
  # Standard first -- the constraint is on the queues, not on the tier.
  default = "Basic"

  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.servicebus_sku)
    error_message = "servicebus_sku must be Basic, Standard or Premium."
  }
}

variable "function_maximum_instance_count" {
  type        = number
  description = "Hard ceiling on scaled-out Function instances. This is the cost stop: without it the platform default (100) applies and a traffic spike or abuse burst scales out unbounded."
  default     = 20

  validation {
    condition     = var.function_maximum_instance_count >= 1 && var.function_maximum_instance_count <= 1000
    error_message = "function_maximum_instance_count must be between 1 and 1000."
  }
}

variable "function_instance_memory_mb" {
  type        = number
  description = "Memory per Function instance. Billed as instance-seconds x memory, so this multiplies the cost of every execution."
  default     = 2048

  validation {
    condition     = contains([512, 2048, 4096], var.function_instance_memory_mb)
    error_message = "function_instance_memory_mb must be 512, 2048 or 4096."
  }
}

variable "log_analytics_daily_quota_gb" {
  type        = number
  description = "Hard cap on Log Analytics ingestion per UTC day. Front Door access logs write one record per request, so ingestion scales with public traffic. -1 disables the cap."
  default     = 1

  validation {
    condition     = var.log_analytics_daily_quota_gb == -1 || var.log_analytics_daily_quota_gb > 0
    error_message = "log_analytics_daily_quota_gb must be positive, or -1 to disable the cap."
  }
}

variable "budget_amount" {
  type        = number
  description = "Monthly cost ceiling in the billing currency. Alerts only -- a budget cannot stop spending. The hard stops are function_maximum_instance_count, log_analytics_daily_quota_gb and the Free/Basic SKUs."
  default     = 100

  validation {
    condition     = var.budget_amount > 0
    error_message = "budget_amount must be positive."
  }
}

variable "budget_contact_emails" {
  type        = list(string)
  description = "Optional email addresses for the resource-group spend budget alert (in addition to Owner role)."
  default     = []
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
