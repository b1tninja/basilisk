# The production profile. Not auto-loaded — it applies only when something
# passes `-var-file=profiles/production.tfvars`, which is what
# `deployment_profile: production` on the deploy workflow does.
#
# Everything here is non-secret and already public: the hostname is in DNS and
# the zone id identifies a zone, not a credential. Secrets stay in GitHub
# Actions secrets and in an untracked `production.tfvars` overlay, which the
# deploy script still picks up separately (see production.tfvars.example).
#
# This file is the opt-in. Front Door Standard's base fee is ~$35/month whether
# or not the endpoint serves a request, so nothing turns it on by accident:
# `enable_front_door` defaults to false in the module and in the root, and the
# dev baseline in domains.auto.tfvars leaves it there.

# The edge. Buys the WAF rate limits on /pks/add, /pks/v2 and sendtoken, the
# edge cache, and the ability to serve a custom domain at all. The rate limits
# are the part with no origin-side equivalent -- basilisk/serve.py applies the
# security headers and the retired-page redirects itself, so those hold in
# either profile, but nothing outside Front Door limits requests per IP.
enable_front_door = true

# Requires enable_front_door above. The domain is a child of the Front Door
# profile and holds its managed certificate; setting one without the other
# fails the plan at `terraform_data.custom_domain_requires_front_door`, which
# needs no provider and so fails before any cloud login.
custom_domain     = "keys.b1tninja.com"
route53_zone_name = "b1tninja.com"
route53_zone_id   = "Z026512234X4JPOD7PZH1"

oauth_authorized_domain = "b1tninja.com"

# The dev baseline drops to the module's 512 floor. Production takes the
# module default back: Front Door caches the static portal at the edge, so the
# origin sees mostly API work, and the headroom is worth more than the
# difference in instance-seconds once there is real traffic.
function_instance_memory_mb = 2048

# Stated rather than inherited, the same way enable_front_door above is. The
# dev baseline drops this to 4 because a runaway there should stop early;
# production takes the module default back, because real traffic needs the
# headroom and the ceiling bills nothing until instances are actually used --
# nothing is always-ready here either. With the 2048 MB above, 20 is a 40 GB
# worst case, and it is the WAF rate limits that make reaching it unlikely.
function_maximum_instance_count = 20

# Alerts only -- a budget cannot stop spending. Sized for the edge: the base
# fee alone is ~$35, so the dev ceiling of 15 would alert on the first day of
# every month and teach everyone to ignore it.
budget_amount = 60

# No health probe, on either origin group. Not a cost compromise -- a group
# with one origin has nowhere to fail over to, so the probe cannot do the job
# it is for in production any more than in dev, and Front Door routes to an
# unprobed origin exactly as it routes to a healthy one. If a second origin is
# ever added, this is the line that has to come back.
front_door_health_probe_interval_seconds = 0
