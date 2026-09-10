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

# The alert thresholds are 80% and 100% of this. The old ceiling was the module
# default of 100, which a $61.11 month passed under without a word — and the
# variable was not plumbed through the root module, so there was no way to
# lower it from here. Both are fixed. Sized just above the expected run rate,
# because a ceiling that only catches a catastrophe catches nothing else.
budget_amount = 15
