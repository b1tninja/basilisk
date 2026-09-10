# Non-secret public-hostname settings (auto-loaded by Terraform).
#
# Front Door is off. Standard bills a flat base fee that has nothing to do with
# traffic: $35.00 of a $61.11 month, against $0.02 of data actually transferred.
# The custom domain and the Route53 records go with it — the domain is attached
# to the Front Door profile and cannot outlive it — so the public URL becomes the
# Function App's own hostname and Terraform destroys the CNAME rather than
# leaving it pointing at a released *.azurefd.net name.
#
# To put it back: set enable_front_door = true and restore the two commented
# lines below in the same apply. Doing one without the other fails the plan on
# purpose, because a silently dropped custom domain is worse than a loud error.
enable_front_door = false

# custom_domain     = "keys.b1tninja.com"
custom_domain     = ""
route53_zone_name = "b1tninja.com"
route53_zone_id   = "Z026512234X4JPOD7PZH1"

# Kept: this names the domain on Google's consent screen, not the callback host.
oauth_authorized_domain = "b1tninja.com"

# Flex Consumption bills instance-seconds times this. 512 is the floor the
# module allows; the keyserver's work is per-request and short, so the 2048
# default was paying four times over. Revert to 2048 if the app OOMs.
function_instance_memory_mb = 512

# The alert thresholds are 80% and 100% of this. The old ceiling was the module
# default of 100, which a $61.11 month passed under without a word — and the
# variable was not plumbed through the root module, so there was no way to
# lower it from here. Both are fixed. Sized just above the expected run rate,
# because a ceiling that only catches a catastrophe catches nothing else.
budget_amount = 15
