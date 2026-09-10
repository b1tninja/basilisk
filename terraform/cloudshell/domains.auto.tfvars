# The dev baseline. Auto-loaded by Terraform, so this is what a deployment gets
# when nobody asks for anything else — and what the GitHub Actions workflow
# deploys under its default `deployment_profile: dev`.
#
# Dev means no edge. Front Door Standard bills a flat base fee that has nothing
# to do with traffic: $35.00 of a $61.11 month, against $0.02 of data actually
# transferred. `enable_front_door` now defaults to false in the module as well,
# so this line is a statement of intent rather than an override; it is written
# out because a profile that says what it is beats one you have to infer.
enable_front_door = false

# Empty, and it has to be: a custom domain is a child of the Front Door profile
# and holds its managed certificate, so setting it here would fail the plan.
# The hostname lives in profiles/production.tfvars, next to the edge it needs.
custom_domain = ""

# Left set although custom_domain is empty. They cost nothing while it is --
# local.route53_enabled requires the custom domain -- and keeping them means
# switching to the production profile needs no zone lookup.
route53_zone_name = "b1tninja.com"
route53_zone_id   = "Z026512234X4JPOD7PZH1"

# Kept: this names the domain on Google's consent screen, not the callback host.
oauth_authorized_domain = "b1tninja.com"

# Flex Consumption bills instance-seconds times this. 512 is the floor the
# module allows; the keyserver's work is per-request and short, so the 2048
# default was paying four times over. Revert to 2048 if the app OOMs.
function_instance_memory_mb = 512

# The blast radius, not a standing charge. No instance is always-ready, so the
# app scales to zero and a ceiling nobody reaches costs nothing idle — what it
# buys is a bound on how far a spike or an abuse burst gets before it stops. At
# the 512 MB set above, 4 caps concurrent instance memory at 2 GB where the
# module default of 20 would allow 10 GB, and dev is meant to be ultra low
# cost. Production keeps the 20; it says so outright in
# profiles/production.tfvars rather than leaning on the default.
function_maximum_instance_count = 4

# log_analytics_daily_quota_gb is deliberately not set here. It is reachable
# now — it was not before — but the module default of 1 GB/day is already the
# right number for dev. The cap exists for FrontDoorAccessLog, which writes one
# record per request, and dev has no edge: the largest ingestion source is not
# deployed at all, so a day's ingestion sits far below the cap. A quota only
# saves money on the day it binds, and this one would not, so lowering it would
# buy nothing while risking the Function App's own logs cutting out mid-debug.
# Production is where the 1 GB does real work.

# The alert thresholds are 80% and 100% of this. The old ceiling was the module
# default of 100, which a $61.11 month passed under without a word — and the
# variable was not plumbed through the root module, so there was no way to
# lower it from here. Both are fixed. Sized just above the expected run rate,
# because a ceiling that only catches a catastrophe catches nothing else.
budget_amount = 15
