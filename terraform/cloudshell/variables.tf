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

variable "upstream_allowlist" {
  type        = string
  description = "Comma-separated HTTPS keyserver hostnames the portal may call from the browser. The search runs in the user's browser, not on the Function App, so this is the list of third parties a visitor's client is told to hand a query to — add only keyservers you would trust with the search term and the requesting IP. Inert while upstream_enabled is false."
  default     = "keys.openpgp.org,keys.mailvelope.com"
}

variable "upstream_default" {
  type        = string
  description = "Keyserver used when a client omits keyserver=. Must also appear in upstream_allowlist, or the request the portal makes by default is the one it refuses to make."
  default     = "keys.openpgp.org"
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

variable "enable_worm_immutability" {
  type        = bool
  description = "Lock cert blobs under a WORM immutability policy. A blob written while this is on cannot be deleted or overwritten until its retention expires — not by an operator, not by the subscription owner, which is the guarantee and also the whole cost of it. It turns blob versioning on as well, so an overwrite keeps the superseded copy and stored bytes only ever grow."
  default     = true
}

variable "worm_retention_days" {
  type        = number
  description = "How long a cert blob stays undeletable once written. This is the floor on how long a bad write survives, and with versioning on it is the window over which superseded versions accumulate and are billed. Only reachable while enable_worm_immutability is true."
  default     = 365
}

variable "upload_rate_limit_per_minute" {
  type        = number
  description = "Front Door WAF ceiling on POSTs to /pks/add per client IP per minute. Nothing origin-side enforces a rate limit — basilisk/serve.py applies the security headers and the redirects itself but no limits — so this is the only thing standing between the submission endpoint and an abuse burst that scales the Function App out to function_maximum_instance_count. It exists only where there is an edge: with enable_front_door false there is no WAF and no limit."
  default     = 10
}

variable "v2_upload_rate_limit_per_minute" {
  type        = number
  description = "The same ceiling for POST and PUT under /pks/v2/. Lower than the /pks/add limit because a v2 submission does more work per request. Like the others it lives in the WAF, so it applies only when enable_front_door is true."
  default     = 5
}

variable "sendtoken_rate_limit_per_minute" {
  type        = number
  description = "WAF ceiling on /pks/v2/sendtoken per client IP per minute. The tightest of the three: a sendtoken request makes the Logic App send mail to an address the caller named, so each one past the limit is a message a real person receives. Enforced only when enable_front_door is true."
  default     = 3
}

variable "web_pubsub_sku" {
  type        = string
  description = "Web PubSub tier carrying notebook signalling. Free_F1 bills nothing and caps at 20 concurrent connections and 20000 messages/day; the paid tiers bill a unit fee every month whether or not anyone connects. The free cap is a wall, not a throttle — connection 21 is refused — so moving up buys capacity by giving up the zero-cost floor."
  default     = "Free_F1"
}

variable "web_pubsub_hub" {
  type        = string
  description = "Hub name notebook signalling connects to. Must match BASILISK_WEBPUBSUB_HUB on the Function App; when it does not, the failure is silent rather than loud — clients connect successfully to a hub nothing publishes to and simply never receive a message."
  default     = "notebook"
}

variable "servicebus_sku" {
  type        = string
  description = "Service Bus tier. Basic bills per operation with no namespace base charge and carries queues only; Standard adds a fixed monthly fee and is what topics, sessions, duplicate detection and scheduled delivery require. Basic also caps queue TTL at 14 days, and Azure refuses the downgrade while any queue exceeds it — so raising the queue TTLs means moving back to Standard first, in its own apply."
  default     = "Basic"

  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.servicebus_sku)
    error_message = "servicebus_sku must be Basic, Standard or Premium."
  }
}

variable "enable_front_door" {
  type        = bool
  description = "Deploy Azure Front Door and its WAF. Standard bills a flat monthly base fee that does not depend on traffic — it was $35.00 of a $61.11 month against $0.02 of actual data transfer, so it is opt-in rather than opt-out. Enabling it is what makes custom_domain possible; the domain is a child of the profile. Use profiles/production.tfvars rather than setting this by hand."
  default     = false
}

variable "function_maximum_instance_count" {
  type        = number
  description = "Hard ceiling on scaled-out Function instances, and the one cost stop that stops rather than warns: leave it unset and the platform default of 100 applies, so a traffic spike or an abuse burst scales out until something else gives. No instance is always-ready, so the app scales to zero and the ceiling costs nothing while idle — it is a blast radius, not a standing charge. Multiply it by function_instance_memory_mb to read the worst case in gigabytes."
  default     = 20

  validation {
    condition     = var.function_maximum_instance_count >= 1 && var.function_maximum_instance_count <= 1000
    error_message = "function_maximum_instance_count must be between 1 and 1000."
  }
}

variable "function_instance_memory_mb" {
  type        = number
  description = "Memory per Function instance. Flex Consumption bills instance-seconds multiplied by this, so it scales the whole compute line: $10.99 of execution time last month against $0.01 of executions. Allowed values are 512, 2048 and 4096."
  default     = 2048
}

variable "log_analytics_daily_quota_gb" {
  type        = number
  description = "Hard cap on Log Analytics ingestion per UTC day. PerGB2018 bills by the gigabyte and the Front Door access log writes one record per request, so ingestion is the line that tracks public traffic and rises fastest under attack. Reaching the cap halts ingestion until 00:00 UTC and keeps what was already stored: losing the tail of a day's access logs is the intended trade. -1 removes the cap, and is the only setting here with no ceiling at all."
  default     = 1

  validation {
    condition     = var.log_analytics_daily_quota_gb == -1 || var.log_analytics_daily_quota_gb > 0
    error_message = "log_analytics_daily_quota_gb must be positive, or -1 to disable the cap."
  }
}

variable "budget_amount" {
  type        = number
  description = "Monthly cost ceiling in the billing currency. Alerts only — a budget cannot stop spending. Set it near the expected run rate: a ceiling well above what the deployment costs is a ceiling that never fires, which is how a $61 month went unremarked under a $100 budget."
  default     = 100
}
