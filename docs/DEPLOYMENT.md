# Basilisk Azure deployment



## Prerequisites



- Azure CLI (`az`) and Bicep

- Optional: [Azure Developer CLI](https://learn.microsoft.com/azure/developer/azure-developer-cli/) (`azd`)



## Deploy



```bash
az login
./scripts/deploy-azure.sh
```

PowerShell (Windows or Cloud Shell):

```powershell
az login
.\scripts\deploy-azure.ps1
```

The deploy scripts read **tenant ID and subscription** from your active `az login` session. **Region** is resolved automatically:

1. `-Location` / `LOCATION=` if you pass it
2. Existing `${namePrefix}-rg` location (for redeploys)
3. `az config` `defaults.location` if configured
4. Fallback: `eastus`

Defaults: `namePrefix=basilisk-dev`, `mailProvider=office365`.

Override via flags:

```powershell
.\scripts\deploy-azure.ps1 -NamePrefix basilisk-prod -Location westus2 -MailProvider gmail
```

```bash
NAME_PREFIX=basilisk-prod LOCATION=westus2 MAIL_PROVIDER=gmail ./scripts/deploy-azure.sh
```

Optional: copy `infra/main.bicepparam.example` to `infra/main.bicepparam` and pass `-ParamFile infra/main.bicepparam` only when you need a static param file.



## Deploy with Terraform (Cloud Shell)

Terraform is pre-installed in [Azure Cloud Shell](https://shell.azure.com). The module mirrors the Bicep stack and reads **tenant ID** from your Azure CLI session (`azurerm_client_config`).

One storage account (`basiliskdevstore`) serves everything: static portal, Terraform state, and Cloud Shell `$HOME`.

| Location | Contents |
|----------|----------|
| `$web` container | Static portal (Terraform-managed) |
| `tfstate/` blob | Terraform state — shared by CI and Cloud Shell |
| `cloudshell` file share | Cloud Shell persistent `$HOME` |

### Cloud Shell bootstrap (one-time)

> **Prerequisites:** the Azure infra must already exist (`basiliskdevstore` storage account). If this is a greenfield deploy, run `./scripts/deploy-terraform-cloudshell.sh` once first (local state is fine for that first run), then come back to this section.

**Step 1 — open [shell.azure.com](https://shell.azure.com) and clone the repo**

```bash
git clone https://github.com/b1tninja/basilisk.git ~/basilisk && cd ~/basilisk
chmod +x scripts/*.sh
```

**Step 2 — bootstrap shared state + mount persistent `$HOME`**

```bash
# Look up the GitHub deploy service principal (same name as docs/CI.md)
clientId=$(az ad sp list --display-name basilisk-github-deploy --query "[0].appId" -o tsv)

GITHUB_SP_CLIENT_ID="$clientId" \
  bash scripts/bootstrap-tfstate.sh --use-app-storage --mount-clouddrive
```

If `basilisk-github-deploy` does not exist yet, create it first (see [docs/CI.md](CI.md#3-create-azure_credentials)), then re-run the commands above. The bootstrap script also auto-detects this SP when `GITHUB_SP_CLIENT_ID` is omitted.

This:
1. Creates `tfstate` blob container on `basiliskdevstore`
2. Creates `cloudshell` file share on `basiliskdevstore`
3. Grants `Storage Blob Data Contributor` to you and the deploy SP
4. Writes `terraform/cloudshell/backend.hcl` pointing at the blob
5. Runs `terraform init` against the remote backend
6. Runs `clouddrive mount` — **this opens a new terminal session**

**Step 3 — re-clone into the new persistent `$HOME`**

> `clouddrive mount` replaces `$HOME` with the new file share, so your previous clone is gone. The new `$HOME` persists across all future Cloud Shell sessions.

```bash
# In the new terminal:
git clone https://github.com/b1tninja/basilisk.git ~/basilisk && cd ~/basilisk
chmod +x scripts/*.sh
```

**Step 4 — init Terraform against the shared backend**

```bash
# RBAC can take 1–5 min to propagate after the role assignment in Step 2.
# If you get a 403, wait a minute and retry.
NAME_PREFIX=basilisk-dev bash scripts/terraform-init.sh
```

**Step 5 — deploy**

```bash
AUTO_APPROVE=true ./scripts/deploy-terraform-cloudshell.sh
```

### Subsequent Cloud Shell sessions

`$HOME` is now persistent — your clone survives. Just pull and deploy:

```bash
cd ~/basilisk && git pull
AUTO_APPROVE=true ./scripts/deploy-terraform-cloudshell.sh
```

Cloud Shell and GitHub Actions read and write the **same** `basilisk-dev.tfstate` blob.

### If `terraform init` gives 403

Azure RBAC propagation takes 1–5 minutes after `bootstrap-tfstate.sh` grants the role. Retry:

```bash
cd ~/basilisk/terraform/cloudshell
terraform init -backend-config=backend.hcl -reconfigure
```

Or use storage key auth as a fallback:

```bash
KEY=$(az storage account keys list -g basilisk-dev-rg -n basiliskdevstore --query "[0].value" -o tsv)
terraform init \
  -backend-config="storage_account_name=basiliskdevstore" \
  -backend-config="resource_group_name=basilisk-dev-rg" \
  -backend-config="container_name=tfstate" \
  -backend-config="key=basilisk-dev.tfstate" \
  -backend-config="access_key=$KEY" \
  -reconfigure
```



PowerShell:



```powershell
az login
.\scripts\deploy-terraform-cloudshell.ps1 -AutoApprove
```



Auto-detected values (same as Bicep deploy scripts):



| Input | Source |
|-------|--------|
| Tenant ID | `azurerm_client_config` / `az account show` |
| Subscription | active `az login` session |
| Region | `-Location` / existing `${namePrefix}-rg` / `az config` / `eastus` |
| `BASILISK_TOKEN_SECRET` | generated by Terraform (`random_password`) |
| `BASILISK_BASE_URL` | set post-apply from the `public_url` output — the custom domain, else the Front Door endpoint, else the Function App's own hostname |



Layout:



- `terraform/modules/basilisk/` — reusable module (storage, Service Bus, Flex Consumption Function App, optional Logic App, optional Front Door + WAF, RBAC)
- `terraform/cloudshell/` — root module for one-shot deploy. `domains.auto.tfvars` is the auto-loaded dev baseline; `profiles/production.tfvars` is the opt-in production profile
- `scripts/deploy-terraform-cloudshell.{sh,ps1}` — init/plan/apply wrapper. Only the `.sh` understands `DEPLOY_PROFILE`; the PowerShell variant passes `terraform.tfvars` and `production.tfvars` if they exist and has no profile switch, so it always deploys the dev baseline unless a local overlay says otherwise



Override via environment variables:



```bash
NAME_PREFIX=basilisk-prod LOCATION=westus2 MAIL_PROVIDER=gmail AUTO_APPROVE=true ./scripts/deploy-terraform-cloudshell.sh
```



### Clean up a failed or partial deploy



If a previous Bicep/Terraform attempt left resources behind (e.g. `basilisk-dev-rg` already exists), delete them first:



```powershell
.\scripts\destroy-basilisk-azure.ps1 -Force
```



```bash
FORCE=true ./scripts/destroy-basilisk-azure.sh
```



Wait for the resource group delete to finish (`az group show -n basilisk-dev-rg` should 404), then re-run `terraform apply`.



## GitHub Actions deploy



After the first Terraform apply, export secrets for CI/CD:



```bash
bash scripts/export-github-secrets.sh
```



Set **`BASILISK_TOKEN_SECRET`** and **`AZURE_CREDENTIALS`** in GitHub (see [docs/CI.md](CI.md)). Then run the **deploy** workflow from the Actions tab.



The workflow applies Terraform, publishes function code, uploads the static portal to Storage `$web`, and smoke-tests the public URL. Use workflow input **skip_terraform** for code-only redeploys, and **deployment_profile** to choose which shape it deploys — `dev` unless you say otherwise; see [Deployment profiles](#deployment-profiles) below.



### Static portal hosting

Portal pages (`/`, `/search`, `/published`, `/key`, `/toolkit`, `/verify`, `/preferences`, `/stats`) are **static HTML/JS/CSS** built by Vite into `web/dist/`. **Who serves them depends on `enable_front_door`**, and the two answers are genuinely different deployments rather than two spellings of one. Since `enable_front_door` is what the deployment profile decides, so is this: the dev profile takes the second answer, the production profile the first.

**With Front Door** (`enable_front_door = true`, which only `profiles/production.tfvars` sets) there are two origins behind one hostname. Front Door sends `/pks/*`, `/api/*`, `/claim/*`, `/.auth/*` and `/health` to the Function App and everything else to the storage account's `$web` container:

| Path pattern | Origin |
|--------------|--------|
| `/pks/*`, `/api/*`, `/claim/*`, `/.auth/*`, `/health` | Function App |
| `/*` (default) | Storage static website |

**Without Front Door** there is nothing to merge two origins under one name, so there is only one: Flask serves the portal out of the function package. `scripts/package-function.sh` ships `web/dist` **inside** the zip — it used to be excluded, precisely because the portal never came from there — and `register_static_portal` in `basilisk/portal/static.py` mounts it. This is not a preference. A portal on the storage endpoint would be a different origin from the API it calls and from the Easy Auth cookie it needs, so the pages would load and nothing on them would work.

Serving from Flask keeps the response headers rather than losing them. Front Door's `SecurityHeaders` rule set adds CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy` to blob responses, which blob storage cannot add on its own; `basilisk/serve.py`'s `after_request` sets the same six values, and it is the one in the path exactly when Front Door is not. The CSP is arguably better on the Flask side — `local.content_security_policy` in `frontdoor.tf` hard-codes the two default upstream keyserver hosts, while Flask builds `connect-src` from `Settings.csp_connect_src()`, so on the dev profile changing `BASILISK_UPSTREAM_ALLOWLIST` no longer leaves the header behind.

Because the Flask portal is now a serving path and not only a dev convenience, everything the storage account publishes has to have a route in `basilisk/portal/static.py` — not just the pages, but the assets, the import maps and the integrity pin document that `docs/THREAT-MODEL.md` tells readers to fetch by hand. A file that exists in `web/dist` and is uploaded to `$web` but has no Flask route is reachable in the production profile and a 404 in the dev one, which is the most confusing shape a bug can take. `scripts/smoke-test.sh` is the backstop: it iterates every Vite rollup input and hard-fails on a 404, so a page that stops being routed stops a deploy.

`/encrypt`, `/decrypt`, `/quorum` and `/my-keys` no longer exist as pages, and which copy of the redirect runs depends on the profile. `_RETIRED_PAGES` in `basilisk/portal/static.py` 301s each to where its errand went; with Front Door in the path that route never fires for the deployed site and four `retired_page` rules in `frontdoor.tf` carry the redirects instead. With Front Door off the Flask route is the one that runs, and the Front Door rules are not deployed. Either profile keeps the old links working — just not with the same mechanism.

The storage static website is **not** gated on `enable_front_door`: it is still created and `deploy-static.sh` still uploads to it. With no Front Door that copy is reachable only on `https://<storage-account>.z.web.core.windows.net`, where it is a portal with no API and no session cookie. Treat it as a build artifact, not as a second front end.



Deploy static assets after infrastructure apply:



```bash
bash scripts/deploy-static.sh
```



Or use the GitHub **deploy** workflow (runs `deploy-static.sh` automatically when Terraform outputs include the storage account name).



Local dev serves the same files from Flask (`basilisk/portal/static.py`) so URLs match a deployment. Under the dev profile that is no longer only a local convenience — it is the deployed path too, so local dev and a dev-profile deployment exercise the same code for portal pages instead of merely agreeing on URLs. Under the production profile they diverge again, and the smoke test is what notices.



For durable Terraform state across runners, bootstrap Azure Blob remote state:

```bash
clientId=$(az ad sp list --display-name basilisk-github-deploy --query "[0].appId" -o tsv)
GITHUB_SP_CLIENT_ID="$clientId" bash scripts/bootstrap-tfstate.sh --use-app-storage
```

See `docs/CI.md` and `scripts/bootstrap-tfstate.sh`.

## Deployment profiles

A deployment of this stack comes in one of two shapes, and the difference between them is not a handful of variables scattered across a command line — it is one file you either pass or do not.

`terraform/cloudshell/domains.auto.tfvars` is the **dev baseline**. Terraform auto-loads any `*.auto.tfvars` in the working directory, so it applies unless something later overrides it, and it is therefore what a deployment gets when nobody asks for anything else: `enable_front_door = false`, `custom_domain = ""`, `function_instance_memory_mb = 512`, `budget_amount = 15`. No edge, no custom domain, the module's memory floor, and a budget ceiling sized just above the expected run rate rather than high enough to catch only a catastrophe. It keeps `route53_zone_name` and `route53_zone_id` set even though `custom_domain` is empty, because `local.route53_enabled` requires the custom domain — they cost nothing while it is blank, and having them means switching profiles needs no zone lookup.

`terraform/cloudshell/profiles/production.tfvars` is the **production profile**. It is committed to the repository — the hostname it names is already in public DNS and a Route53 zone id identifies a zone rather than granting access to one, so there is nothing in it to protect — but it is deliberately *not* auto-loaded, so it applies only when something passes `-var-file=profiles/production.tfvars`. It sets `enable_front_door = true` and `custom_domain = "keys.b1tninja.com"` in the same file, because the plan refuses them apart. It also takes `function_instance_memory_mb` back to the module default of 2048, on the reasoning that Front Door caches the static portal so the origin sees mostly API work, and raises `budget_amount` to 60: the edge's base fee alone is more than twice the dev ceiling, so a production deployment left on the dev budget would alert on the first of every month and teach everyone to ignore the alert.

### Selecting one

`scripts/deploy-terraform-cloudshell.sh` reads **`DEPLOY_PROFILE`**. It defaults to `dev`, which passes no extra var-file at all and so takes the auto-loaded baseline and nothing else; `production` maps to `profiles/production.tfvars`. Any other value exits 2 before Terraform runs, rather than quietly deploying whichever shape the auto-loaded file happens to describe — a typo in a profile name should not be a $35/month decision.

```bash
bash scripts/deploy-terraform-cloudshell.sh                              # dev
DEPLOY_PROFILE=production bash scripts/deploy-terraform-cloudshell.sh    # edge + keys.b1tninja.com
```

**The PowerShell wrapper has no equivalent.** `scripts/deploy-terraform-cloudshell.ps1` passes `terraform.tfvars` and `production.tfvars` when they exist and knows nothing about `profiles/`, so it always deploys the dev baseline unless a local overlay overrides it. Use the Bash script, or `terraform apply` with an explicit `-var-file`, for a production deployment.

The GitHub **deploy** workflow exposes the same choice as a `deployment_profile` input — a dropdown of `dev` and `production`, defaulting to `dev` — and passes it straight through as `DEPLOY_PROFILE`. The input's description carries the base fee rather than leaving it to be discovered on an invoice, and the run summary prints the profile beside the public URL and the custom domain, because a deploy log that does not say what shape it deployed is how this stopped being obvious in the first place.

### Precedence, and where local values go

Var-files are applied in the order Terraform resolves them, and the last match wins:

1. `domains.auto.tfvars` — auto-loaded, always in effect.
2. `profiles/production.tfvars` — only under `DEPLOY_PROFILE=production`.
3. `terraform.tfvars`, then `production.tfvars` — local files, if they exist.

Both files in step 3 are **gitignored**, and the patterns are rooted (`/terraform/cloudshell/production.tfvars`) precisely so that the committed `profiles/production.tfvars` is not swept up by the same rule. `production.tfvars.example` is the template for that local overlay and nothing more: copy it to `production.tfvars` and put values specific to one subscription in it — a `name_prefix`, budget contact addresses — knowing they land *on top of* the profile rather than instead of it. It has told operators to make that copy for a long time; until recently nothing stopped the copy being committed.

The deploy script has to know which shape it is deploying before Terraform runs, because it adopts pre-existing resources into state first and `terraform import` against a `count = 0` address is a hard error rather than a no-op. Its `FRONT_DOOR_ENABLED` probe takes `TF_VAR_enable_front_door` when that is set, and otherwise greps the same files in the same precedence order and keeps the last match. It **defaults to false** when it finds nothing, which is the direction that fails safely: guessing true is what would try to import Front Door resources into addresses that were never created.

## Azure Front Door is optional: `enable_front_door`

`enable_front_door` (bool, **`false` by default** in both `terraform/modules/basilisk/variables.tf` and `terraform/cloudshell/variables.tf`) decides whether a deployment has an edge at all. It is opt-in in the literal sense: a deployment pays the base fee only by naming it, and the one file in this repository that names it is `terraform/cloudshell/profiles/production.tfvars`. The dev baseline in `domains.auto.tfvars` restates `enable_front_door = false` next to the reasoning rather than leaning on the default, because a profile that says what it is beats one you have to infer.

### Why it is opt-in rather than opt-out

Front Door Standard's base fee is a subscription, not a usage charge. It billed **$35.00 of a $61.11 month** while the endpoint moved **$0.02** of actual data. No amount of low traffic makes that cheaper — the fee is the same for zero requests as for a million — so on a keyserver whose traffic is `gpg --recv-keys` a few times a day, more than half the bill was for a CDN that had nothing to cache and a WAF standing in front of an app that scales to zero. Nothing about the product misbehaved. It is simply priced for a workload a dev deployment is not, which is why the default is off and the production profile is where you say otherwise.

### What a deployment without the edge gives up

This is the honest list, and none of it is recovered elsewhere:

- **The custom domain goes.** A Front Door custom domain is a *child* of the profile — it holds the managed TLS certificate and is associated to the routes — so it cannot outlive it. This is why `profiles/production.tfvars` sets `enable_front_door` and `custom_domain` in the same file and why `domains.auto.tfvars` leaves `custom_domain` empty. Terraform will not let you get the pairing wrong by accident: a `terraform_data` precondition in `terraform/modules/basilisk/dns.tf` **fails the plan** when `custom_domain` is set and `enable_front_door` is false, rather than silently dropping every resource that would have served that hostname to `count = 0` and returning a green plan. It sits on `terraform_data` because a precondition on a `count = 0` resource never runs, and because `terraform_data` needs no provider — so the error arrives on a laptop with no Azure login, which is where the mistake gets made.
- **The WAF goes, and nothing replaces it.** This is the only item on this list with no origin-side equivalent anywhere in the codebase. See [WAF residual risk](#waf-residual-risk-standard-sku) below.
- **The CDN goes.** Portal HTML has a 1-day edge TTL (`CacheStaticHtml`) and hashed assets under `/assets/*` a 7-day one (`CacheStaticAssets`), both `OverrideAlways`. Without it every page is an origin fetch against a Function App that scales to zero, so the first request after idle pays a cold start. `deploy-static.sh` works this out on its own: it probes `terraform output -raw front_door_profile_name`, which exits non-zero on the `null` that output returns with no profile, and takes its existing "Skipping Front Door cache purge" branch. There is no cache to purge.
- **The `FrontDoorAccessLog` diagnostic setting goes**, because a diagnostic setting is a child of the resource it points at. The Log Analytics workspace stays — the Function App still logs to it — but the largest ingestion source, one record per edge request, is absent with the edge. That is a cost saving and an observability loss in the same sentence.

**Two things that look like they belong on that list do not.** The security headers and the retired-page redirects are served on both profiles. Front Door's `SecurityHeaders` rule set writes CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy`; `basilisk/serve.py`'s `after_request` sets the same six, and it is in the path for portal pages precisely when Front Door is not. The four `retired_page` rules in `frontdoor.tf` and `_RETIRED_PAGES` in `basilisk/portal/static.py` hold the same four destinations. Overstating what the edge is load-bearing for is as misleading as understating it, and the module's own variable description used to claim both of these had "no origin-side equivalent here" when both plainly do.

There is also **no country blocking** to lose. It is a natural thing to assume of a WAF, but no geo-match rule has ever existed in `terraform/modules/basilisk/frontdoor.tf`.

### What changes about the public URL

`local.public_url` in `dns.tf` prefers the custom domain, then the Front Door endpoint, and falls back to `local.function_app_url` — the Function App's own `https://<name-prefix>-fn.azurewebsites.net`. Everything downstream follows that one local: the `public_url` output, `BASILISK_BASE_URL` (set post-apply by `scripts/deploy-terraform-cloudshell.sh`), the URL the CI smoke test runs against, and `gpg_keyserver_url` in `oauth_setup`. Every `front_door_*` output becomes `null` rather than `""`, so a consumer that interpolates one gets a visible `null` instead of a plausible-looking `https://`.

**With no profile, `BASILISK_AFD_ID` is not set at all** — absent, not empty. `basilisk/security/edge.py` reads it and returns `True` when it is falsy, so the origin lock fails open, which is required: with no Front Door in front, every request is a "bypass" and a lock that matched nothing would 403 the whole service. Absent rather than empty because that setting is a kill switch and app settings are editable in the portal; empty leaves the app one accidental keystroke away from refusing every request.

### The OAuth callback moves with the public URL, and Terraform cannot follow it

`oauth_setup.google_redirect_uris` is a list built as `distinct([<public_url>/.auth/login/google/callback, <function_app_url>/.auth/login/google/callback])`, and the output's description says to register **all** of them in the identity provider. That is still exactly right — but on the dev profile the two expressions produce the same string, `distinct` collapses them, and **the list has one entry: the Function App callback.**

```
https://<name-prefix>-fn.azurewebsites.net/.auth/login/google/callback
```

That URI has to already exist under **Authorized redirect URIs** on the OAuth client in the Google Cloud Console. **Terraform cannot put it there.** It configures the `google_v2` block on the Function App and injects the client secret from Key Vault, and that is the whole of its reach — the registration lives in a Google project this deployment has no credential for. If the only URI ever registered was the custom-domain one, Google returns `Error 400: redirect_uri_mismatch` and sign-in fails on a stack where every Azure-side setting looks correct. The failure is entirely in someone else's console.

The safe habit is to register both from the start and leave both registered: an extra authorized redirect URI costs nothing, and it means switching profiles in either direction never waits on a second person with Google Cloud access. `aad_redirect_uris` collapses the same way for Entra, though `docs/AUTH.md` has always told you to register the Function App URI there.

Confirm what a given deployment actually wants with:

```bash
terraform -chdir=terraform/cloudshell output -json oauth_setup | jq -r '.google_redirect_uris[]'
```

### Turning it on

Ask for the production profile. That is the whole of it — `enable_front_door = true` and `custom_domain` are set together in `profiles/production.tfvars`, which is the point of keeping them in one file:

```bash
DEPLOY_PROFILE=production bash scripts/deploy-terraform-cloudshell.sh
```

Setting one of the two by hand without the other fails the plan on purpose; see the precondition above. `scripts/deploy-terraform-cloudshell.sh` resolves the flag before it starts importing (`TF_VAR_enable_front_door` wins, else it greps the var-files in precedence order and takes the last match) because `terraform import` against a `count = 0` address is a hard error, so the Front Door state-adoption block has to be skipped wholesale rather than per-resource.

Note that **the Bicep path (`infra/`) is unaffected**. It has no equivalent switch and always deploys `infra/modules/frontdoor.bicep`. Everything in this section is about the Terraform path.

## Custom domain (Route53 + Front Door)

> **This is the production profile.** The custom domain is attached to the Front Door profile, so it needs `enable_front_door = true`; setting one without the other fails the plan rather than quietly serving the Function App hostname instead. Everything in this section applies to `DEPLOY_PROFILE=production` and to nothing else — a dev-profile deployment has no `keys.b1tninja.com` and no Route53 records.

Terraform registers `keys.b1tninja.com` on Azure Front Door and maintains DNS in Route53. The hostname does **not** come from a variable default — every one of `custom_domain`, `route53_zone_name` and `route53_zone_id` defaults to `""` in `terraform/cloudshell/variables.tf`. `custom_domain` is set in `profiles/production.tfvars`, alongside the `enable_front_door = true` it depends on; the two Route53 variables are set in `domains.auto.tfvars` as well, so they are present on both profiles and inert on the one where `custom_domain` is empty.

### Prerequisites

1. **Route53 hosted zone** for `b1tninja.com`
2. **IAM user** with programmatic access scoped to that zone.

**Recommended:** set `route53_zone_id` (in `domains.auto.tfvars`, or via `TF_VAR_route53_zone_id`) so Terraform never calls zone lookup APIs. Minimal policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "route53:ChangeResourceRecordSets",
      "route53:ListResourceRecordSets",
      "route53:GetChange"
    ],
    "Resource": [
      "arn:aws:route53:::hostedzone/Z026512234X4JPOD7PZH1",
      "arn:aws:route53:::change/*"
    ]
  }]
}
```

If `route53_zone_id` is empty and Terraform looks up the zone by name, also allow on `"Resource": "*"`:

- `route53:ListHostedZones`
- `route53:ListHostedZonesByName`
- `route53:GetHostedZone`
- `route53:ListTagsForResource`

3. **GitHub secrets**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`

### What Terraform creates

| Record | Purpose |
|--------|---------|
| `_dnsauth.keys` TXT | Azure Front Door domain validation (managed TLS) |
| `keys` CNAME → `*.azurefd.net` | User/gpg traffic to Front Door |

Also: Front Door custom domain, route association, WAF binding, and `BASILISK_BASE_URL=https://keys.b1tninja.com`.

### Local deploy

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
./scripts/deploy-terraform-cloudshell.sh
```

To keep Front Door but drop the custom domain: `TF_VAR_custom_domain="" TF_VAR_route53_zone_name=""` on top of the production profile — the public URL then becomes the `*.azurefd.net` endpoint. To drop the edge entirely, deploy the dev profile instead; the two settings move together there, which is the point of the split.

### gpg

Whatever `public_url` resolves to is the keyserver URL, and `terraform output -raw public_url` is the authoritative answer for a given deployment:

```bash
gpg --keyserver "$(terraform -chdir=terraform/cloudshell output -raw public_url)" --recv-keys KEYID
```

On the production profile that is `https://keys.b1tninja.com`; on the dev profile it is `https://<name-prefix>-fn.azurewebsites.net`.

### WAF residual risk (Standard SKU)

**This subsection is about the production profile.** The firewall policy is a child of the Front Door profile, so on the dev profile it is not deployed at all, `waf_policy_id` is `null`, and none of the rules below is enforced anywhere. Read the two halves of this subsection as the two profiles: the first is the risk that remains when the WAF *is* deployed, the second is what stands in its place when it is not.

Front Door is deployed on **Standard_AzureFrontDoor**, which supports custom rate-limit WAF rules only. Microsoft Default Rule Set / Bot Manager require **Premium**. Direct origin access is blocked when `BASILISK_AFD_ID` is set on the Function App (must match `X-Azure-FDID`) — and Terraform does not set it when there is no profile to take a GUID from, so on the dev profile that block is not in force either. Upgrade path is documented in `terraform/modules/basilisk/frontdoor.tf`.

Without the WAF, all that remains is the in-process limiter in `basilisk/security/rate_limit.py`, and it is a weaker control in two ways that matter. It enforces a **minimum gap** rather than a per-minute budget, and it keeps its state in worker memory — Flex Consumption runs up to `function_maximum_instance_count` instances that share nothing, so the real ceiling is the configured gap divided across however many workers are warm. And `client_ip()` prefers `X-Azure-ClientIP`, a header **Azure sets at the edge**; with no edge, nothing in this repository sets or strips it and its value is whatever the caller sent, which lets a caller choose their own bucket. That is the same failure the comment in that file records for `X-Client-IP`. If a deployment ever attracts an adversary rather than a crawler, the answer is the production profile — not a tuning pass on the gap constants.

### Where the tfvars live

`terraform/cloudshell/domains.auto.tfvars` is the auto-loaded dev baseline and `terraform/cloudshell/profiles/production.tfvars` is the committed production profile; both are described under [Deployment profiles](#deployment-profiles) above, along with the precedence order and the untracked `production.tfvars` overlay that `production.tfvars.example` is a template for. The short version: the edge decision is recorded in a file, not in a flag someone remembers to pass, and there are exactly two such files.

## Post-deploy



1. Authorize Logic App connectors in Azure Portal (see **Logic App approval** below) — only when `require_manager_approval = true`, since the workflow is not deployed otherwise. Skipping this step does not merely disable manager approval: without it the workflow cannot run at all, and nothing consumes `key-events`

2. Confirm `BASILISK_BASE_URL` on the Function App matches `terraform output -raw public_url` (the Terraform deploy scripts set it from that output). It is the custom domain on the production profile and the Function App's own hostname on the dev profile — and it is the host baked into every claim link enqueued on `key-events`, so a stale value puts a dead host into a message that may not be delivered for a long time

3. Publish function code and smoke-test `/health`

4. Upload static portal: `bash scripts/deploy-static.sh`

5. Run `python -m basilisk.cli doctor` against production settings

6. (Optional) Enable Google sign-in — see [docs/AUTH.md](AUTH.md)



## Logic App approval



Resource: `{namePrefix}-approval-la` in `{namePrefix}-rg` — **deployed only when `require_manager_approval = true`** (Terraform path; the Bicep path is unchanged). `logic_app_name` is `null` when it is absent. The reason is cost: the workflow's Service Bus trigger is a Consumption-tier polling trigger that wakes on an interval whether or not a message is waiting, the connector has no push variant, and that polling billed $11.07/month.

> **This workflow has never run, and as this module deploys it, it could not.** The trigger binds to `@parameters('$connections')['servicebus']['connectionId']`, and `terraform/modules/basilisk/logicapp.tf` passes `$connections` as an empty object: the module creates no `Microsoft.Web/connections` resource, on the stated assumption that the connectors are wired up out of band in the portal. On the live `basilisk-dev` deployment that never happened — there are no API connection resources in the resource group at all, and the Logic App's run history is empty. Gating it on `require_manager_approval` therefore removed $11.07/month of polling and no behaviour whatsoever. Nothing regressed, because nothing was working.
>
> **What is broken is older and worse than a feature being off.** `key-events` has a live producer and has never had a working consumer. `basilisk/hkp/add.py` calls `enqueue_key_pending` on every accepted upload, building a `{BASILISK_BASE_URL}/claim/{fingerprint}` URL to put in the message on the understanding that something will mail it out. That call is not gated on `require_manager_approval`; the only thing that setting gates in Python is whether `basilisk/auth/claim.py` enqueues `claim.submitted` when a claim arrives. So the producer runs on every deployment, and nothing consumes what it produces. On the live namespace the queue holds **13 active messages and 0 dead-lettered**, created 2026-07-10 and last touched 2026-08-12. That is thirteen people who uploaded a key, were told a claim link was coming, and never received one. Read the flow below as the design, not as what a deployment does today.
>
> The same shape appears once more, one row down in the table below: `sendtoken-events` also has a producer in the Function App and no consumer in either IaC path. When auditing this system, the question worth asking of every queue is not whether the producer works but who reads it.
>
> Closing it means giving the queue a consumer that exists. Two options: create the Service Bus and mail API connections and reference them from the workflow's `$connections`, so the Logic App path works as designed; or move the consumer into the Function App, which already holds a Service Bus connection string in its `ServiceBusConnection` app setting and would not need a connector at all. Either way the 13 queued messages have to be drained deliberately — sending a batch of months-old verification mails to people who have forgotten they uploaded anything is its own problem.



### Queues



| Queue | Producer | Consumer |
|-------|----------|----------|
| `key-events` | Function App on upload / manager claim | Logic App (email + manager flow) — **intended, not observed**: see the note above |
| `key-approved` | Function App or Logic App after claim | `approve_fn` Function trigger |
| `sendtoken-events` | Function App on HKP v2 sendtoken | **None deployed.** `infra/logic-apps/basilisk-sendtoken.json` is a workflow definition no template references; neither the Terraform module nor the Bicep path creates a Logic App from it |



### Portal setup



This is the out-of-band step the module leaves to an operator, and it is the step that has never been performed on `basilisk-dev`. Until it is, the workflow's trigger has no connection to bind to and the run history stays empty — the workflow being **Enabled** is not the same as it being able to run.

1. Open **Logic App** → **Workflows** → edit the approval workflow
2. Authorize **Azure Service Bus** (namespace `{namePrefix}-bus`, queues `key-events` and `key-approved`)
3. Authorize **Office 365 Outlook** or **Gmail** (must match `mail_provider` at deploy time)
4. Save and ensure the workflow is **Enabled**
5. Confirm it actually fires: the Logic App's **Runs history** should show a run, and `key-events` should stop accumulating active messages. An enabled workflow with zero runs and a growing queue is the failure this section exists to catch.



### End-to-end flow (default: no manager approval)

This is the intended flow. Step 2 has never happened on the live deployment — see the note at the top of this section — so a reader debugging a missing verification email should start there rather than looking for a fault in steps 1, 3 or 4.

1. User uploads key → Function App writes blob + pending Table row → `key.pending` on `key-events`
2. Logic App sends verification email with `{BASILISK_BASE_URL}/claim/{fingerprint}` — **requires an authorized Service Bus connection and mail connector, which Terraform does not create**
3. User signs in (Entra Easy Auth) and submits claim
4. Function App enqueues `key.approved` on **`key-approved`** (or approves inline when Service Bus is not configured)
5. `approve_fn` updates Table → key is visible via HKP lookup



Set **`BASILISK_REQUIRE_MANAGER_APPROVAL=1`** (Terraform: `require_manager_approval = true`) to enqueue `claim.submitted` instead; Logic App must then post `key.approved` to `key-approved` after manager review.



## Mail providers



| Provider | Connector | Manager approval |

|----------|-----------|------------------|

| `office365` | Office 365 Outlook | Supported |

| `gmail` | Gmail Send email V2 | Use claim + Bearer flow |



## Storage model



- Blob container `certs`: WORM immutability after validated upload

- Table `Certs`, `Identifiers`, `Emails`: approval gate and indexes

- Approval updates Table only — no blob rewrite

- Rejected uploads never write blobs (validate-before-store)



## Ingest security tunables



| Variable | Default | Purpose |

|----------|---------|---------|

| `BASILISK_MAX_UPLOAD_BYTES` | 65536 | Max armored key size |

| `BASILISK_MAX_UIDS` | 20 | Max user IDs per cert |

| `BASILISK_MAX_SUBKEYS` | 32 | Max subkey blocks |

| `BASILISK_REQUIRE_EMAIL_UID` | 1 | Require `@` in at least one UID |

| `BASILISK_REJECT_REVOKED` | 1 | Reject revoked primary keys |

| `BASILISK_BLOCKED_EMAIL_DOMAINS` | (empty) | Comma-separated domain blocklist |

| `BASILISK_UPLOAD_RATE_LIMIT_SEC` | 60 | Min seconds between key uploads (`POST /pks/add`, v2 POST/PUT) per IP |

| `BASILISK_UPLOAD_FPR_RATE_LIMIT_SEC` | 60 | Min seconds between uploads of the same fingerprint |

| `BASILISK_LOOKUP_RATE_LIMIT_SEC` | 0 | Min seconds between lookups (`GET /pks/lookup`, v2 cert GET) per IP; `0` disables |

| `BASILISK_SENDTOKEN_RATE_LIMIT_SEC` | 3600 | Min seconds between sendtoken per email |

| `BASILISK_REQUIRE_PROOF` | 0 | Require `X-Basilisk-Proof` on v2 uploads |

| `BASILISK_PROOF_DIFFICULTY` | 0 | Leading zero hex digits for PoW hash |

| `BASILISK_UPSTREAM_ENABLED` | 0 | Offer client-direct upstream HKP in the portal (browser fetches; Basilisk does not proxy) |

| `BASILISK_UPSTREAM_ALLOWLIST` | `keys.openpgp.org,keys.mailvelope.com` | Comma-separated HTTPS hostnames the UI may call |

| `BASILISK_UPSTREAM_DEFAULT` | `keys.openpgp.org` | Default host when the client omits `keyserver=` |

Upstream search runs only for **signed-in** users when enabled. CSP `connect-src` includes the allowlisted `https://` hosts, and every place the policy is written has to name them: the HTML `<meta>`, the Function App header, and — on the production profile — the Front Door header, which overwrites whatever the origin sent. Terraform: `upstream_enabled` (default `false`). Advertised to the portal via `GET /api/v1/config` → `{ upstream: { enabled, allowlist, default } }`.



### Front Door WAF rate limits



**These are edge rules, and they exist only where an edge does.** They are deployed by the Bicep path always, and by the Terraform path only under the production profile — a dev-profile deployment enforces none of these thresholds anywhere. The tunables in the table above (`BASILISK_UPLOAD_RATE_LIMIT_SEC` and friends) are a different mechanism, not a fallback for these: a minimum gap held in one worker's memory, not a budget per IP per minute counted at the edge.



[`infra/modules/frontdoor.bicep`](../infra/modules/frontdoor.bicep) parameters, mirrored by `upload_rate_limit_per_minute` / `v2_upload_rate_limit_per_minute` / `sendtoken_rate_limit_per_minute` in `terraform/modules/basilisk/variables.tf`:



- `uploadRateLimitPerMinute` — `POST /pks/add` (default 10/IP/min)

- `v2UploadRateLimitPerMinute` — v2 POST/PUT (default 5/IP/min)

- `sendtokenRateLimitPerMinute` — sendtoken (default 3/IP/min)



All three run in **Prevention** mode. There is no managed rule set and no bot protection — those are Premium-only — and there is no country or geo-match rule at all.



### Proof-of-work (v2 only)



When `BASILISK_REQUIRE_PROOF=1`:



1. `GET /pks/v2/challenge` returns a nonce and timestamp

2. v2 clients send `X-Basilisk-Proof: nonce:timestamp:signature`

3. Legacy `POST /pks/add` (`gpg --send-keys`) never requires proof

4. `POST /api/v1/notebook/negotiate` requires it too — signalling is gated the same way uploads are



## Notebook signalling (Azure Web PubSub)



The shared notebook's WebRTC signalling runs over **Azure Web PubSub**. The Function App stores nothing: `POST /api/v1/notebook/negotiate` checks proof-of-work and the rate limits, validates the room id, and returns a **client access URL** whose JWT is scoped to exactly one group. The browser then opens a plain `WebSocket` with the `json.webpubsub.azure.v1` subprotocol — no npm dependency — and publishes sealed envelopes to the group. There is no server-side room record, no TTL to sweep and no global room cap.

**Lobby and room.** Proof of work is an anti-abuse gate and costs a stranger exactly what it costs a member, so it cannot be what decides admission. A request carrying only a `room` id gets a token for that room's **lobby**; a request that also carries `key` — the whole base32 room digest, of which the id is the first 16 characters — gets a token for the **room** group, where signalling is actually broadcast. Computing the key takes the relying party and the full audience, so holding it means having been told who is meeting rather than having guessed a short code. The endpoint checks only that the key starts with the id; the audience never goes over the wire. Both group names are truncated SHA-256 digests under different labels, so the two namespaces cannot collide and the service's own logs and metrics see nothing about the room.

**Bounded connection lifetime.** A grant's expiry is checked when a connection is made and never again — the service does not hang up on a connection whose token has since expired — so a token that is not reissued only takes effect if the connection is re-made. The client therefore closes and re-opens the signalling connection at **80% of the grant's stated lifetime** (four minutes at the default 300 s TTL), joining the replacement before closing the original. Shortening `BASILISK_WEBPUBSUB_TOKEN_TTL_SEC` shortens the cycle with it; there is no second setting. Each cycle is a fresh negotiate and therefore a fresh proof of work. Note the cost: for the length of one handshake a peer holds two connections, which counts twice against the tier's concurrency ceiling.

**Room rotation.** There is no eviction API — no membership to enumerate, and no connection this application can name — so a room that needs to drop a member *moves* instead. The remaining members re-derive their material at the next epoch and mint tokens for the group it names; the removed member keeps a valid token for a group nobody is in. The new name mixes a secret minted at rotation and sealed to the members who stay, because the epoch and the remaining audience are both things a removed member can compute. Rotation is announced by the peer whose invite the room locked onto, over links whose keys are already confirmed.



This replaced an in-process mailbox that could not work on Consumption Functions: instances share no memory and recycle when idle, so two peers only met when they happened to hit the same warm worker.



| Setting | Where | Notes |
|---------|-------|-------|
| `AZURE_WEBPUBSUB_CONNECTION_STRING` | Function App | `Endpoint=…;AccessKey=…`. Terraform/Bicep wire it from the Web PubSub resource. Unset ⇒ negotiate returns **503**, and the shared notebook is off. |
| `BASILISK_WEBPUBSUB_HUB` | Function App | Default `notebook`; must match the hub resource. |
| `BASILISK_WEBPUBSUB_TOKEN_TTL_SEC` | Function App | Default `300`. The token buys a handshake; the whole signalling bootstrap is seconds. |
| `web_pubsub_sku` / `web_pubsub_hub` | Terraform vars | Default `Free_F1` / `notebook`. |

> **Redeploy required — the hub was renamed.** The default hub name changed from
> `quorum` to `notebook`, in `BASILISK_WEBPUBSUB_HUB` and in the hub resource
> that Bicep and Terraform declare. A hub name is part of the client URL and the
> token's `aud` claim, so the app and the resource must agree: an app on
> `notebook` against a hub still named `quorum` mints tokens the service rejects.
>
> Applying the change replaces the hub rather than renaming it in place — Bicep
> and Terraform both see a new resource name and a deleted old one. That is safe
> here because **a hub holds no state**: no rooms, no membership, no stored
> messages. It is a namespace for connections. What is lost is the connections
> open at the moment of replacement, and those recover on their own — the client
> re-negotiates on drop, and it already re-makes the connection every 80% of a
> five-minute token anyway.
>
> Deploy the app and the infrastructure together. Rolling one ahead of the other
> leaves signalling down for the gap: existing sessions stay up on their peer
> data channels, but no new pair can mesh. There is no alias and no fallback —
> `/api/v1/quorum/negotiate` returns 404, by design, so a stale client fails
> loudly instead of half-working.



**Token claims** (HS256, signed with the connection string's `AccessKey`): `sub` (an opaque per-connection id), `role` = `["webpubsub.joinLeaveGroup.<group>", "webpubsub.sendToGroup.<group>"]`, `webpubsub.group` = `["<group>"]`, plus `nbf`/`exp`/`iat`/`aud`. The unsuffixed `webpubsub.joinLeaveGroup` / `webpubsub.sendToGroup` roles — which would grant every group on the hub — are never minted, and neither are the wildcard `webpubsub.joinLeaveGroups.<pattern>` / `sendToGroups.<pattern>` roles the service also understands: a pattern covering a room family would hand out one token for every epoch that room will ever rotate through.



**CSP.** The signalling host is per-deployment, so it is never written into a policy string. A browser enforces the **intersection** of a document's `<meta>` policy and the response header, so the origin has to reach both — and how it reaches the meta depends on who serves the HTML:

| Deployment | Serves the HTML | Header from | Meta gets the origin from |
|---|---|---|---|
| Azure, production profile (`enable_front_door = true`) | `$web` blob container | `terraform/…/frontdoor.tf` | `scripts/package-static.sh`, at upload |
| Azure, dev profile (`enable_front_door = false`) | Flask, from `web/dist` in the function zip | `basilisk/serve.py` | `basilisk/portal/static.py`, per request |
| Container / local (`docker compose`, `basilisk serve`) | Flask | `basilisk/serve.py` | `basilisk/portal/static.py`, per request |

`Settings.signaling_ws_origin()` derives `wss://<host>` from the connection string for both headers. With Front Door deployed, it routes `/*` to blob storage and only `/api/*`, `/pks/*`, `/claim/*`, `/.auth/*` and `/health` to the Function App — **Flask is not in the path for portal pages**, so the per-request merge does not cover them. Relying on it is what shipped `keys.b1tninja.com` with a header naming the signalling socket, pages that did not, and shared sessions that could not start. That is why `package-static.sh` does the merge against the bytes it uploads.

On the dev profile the same pages come from Flask, so the per-request merge does cover them and the two mechanisms agree — the merge is idempotent, and a document that already carries the origin comes back unchanged. Do not read that as the packaging step being redundant: it is what covers the `$web` copy, and it is what the production profile depends on entirely.

`scripts/deploy-static.sh` **fails** if the origin cannot be resolved rather than uploading pages with signalling off; a deployment that genuinely has none says `BASILISK_SIGNALING_WSS_ORIGIN=none`. `tests/unit/test_csp_signaling.py` fails if the three policies drift, `web/src/test/e2e/csp-policy.e2e.js` fails if any page's meta refuses a source its header allows, and `scripts/smoke-test.sh` re-checks the same thing against the live site after every deploy.



**Free tier ceilings.** `Free_F1` allows **20 concurrent connections** and **20 000 messages/day**. One connection per peer per session, and signalling moves onto the peer data channels as soon as a pair meshes — so both numbers scale with *peers*, not with how long a conversation lasts. A deployment expecting more than a few simultaneous rooms should set `web_pubsub_sku = "Standard_S1"`; nothing in the application changes.



**Locally and in CI**, leave `AZURE_WEBPUBSUB_CONNECTION_STRING` unset (or point it at loopback) and `python -m basilisk.serve` starts a local double that speaks the same subprotocol — the azurite pattern. A connection string that names a port gets that port, which is how `docker-compose.e2e.yml` publishes it on `8081`; one that names none — including the unset default — makes the double take a free port at bind time, and `serve.py` writes the result back into `AZURE_WEBPUBSUB_CONNECTION_STRING` before the app is built so the grant and both policies name it. That is what lets two servers run at once: the constant that used to be here was a socket every one of them tried to bind.



## TURN relay fallback (Cloudflare Realtime)



Some pairs of peers cannot reach each other directly — both behind symmetric NAT, or a network that filters UDP outright. The fix is a **TURN relay**, and the deployment question it raises is not "which one" but *when it is contacted*.



**The relay is not in the ICE server list.** Putting one there makes it last in ICE's priority order, but the agent still **allocates** on it during gathering, before any connectivity check has succeeded or failed — so a relay configured as a fallback learns this machine's address, and that a connection is being made, on **every** call, including the large majority that connect directly and never relay a byte. Basilisk therefore gathers and connects with STUN only, and escalates in a second phase: on a connection that reaches `failed`, the browser asks `POST /api/v1/turn/credentials` for a short-lived credential, calls `setConfiguration()` with the relay added and `restartIce()`, and re-gathers. Per W3C webrtc-pc ("set the configuration", step 9) and RFC 8829 §4.1.18, that pair is exactly what applies a new server list to a live connection — and the connection, its DTLS certificate and its data channel all survive, which matters because a notebook session key is derived over a transcript committing to that certificate. One escalation per connection; a second failure is reported, not retried.



**Nothing is contacted unless a user asks.** The fallback is off by default in toolkit preferences and is stated there in full: a relay **cannot read the traffic** — the data channel is DTLS end-to-end between the peers and the relay forwards ciphertext it holds no key for — but it **can see** both peers' IP addresses, the timing and the volume. A deployment that configures a relay does not turn it on for anybody.



**The key stays on the server.** Cloudflare's TURN key is a long-term secret that mints unlimited credentials; their documentation says to keep it server-side. `basilisk/portal/cloudflare_turn.py` is the only file that knows the vendor and makes the `POST …/credentials/generate-ice-servers` call with the bearer token; `turn_credentials.py` above it gates the route with `verify_proof` and the IP limiters and returns a credential and nothing else. This is also why the call is not made from the page: `connect-src` is built once per deployment by `Settings.csp_connect_src()`, and reaching Cloudflare's API from the browser would widen it permanently for a request that happens on the minority of connections that fail. `tests/unit/test_turn_credentials.py` pins that the policy stays untouched.



| Setting | Where | Notes |
|---------|-------|-------|
| `CLOUDFLARE_TURN_KEY_ID` | Function App | Cloudflare Realtime TURN key id. Unset ⇒ the endpoint returns **503** and there is no relay. |
| `CLOUDFLARE_TURN_API_TOKEN` | Function App | The long-term secret. Never sent to the browser. Half-configured (one of the two) is treated as unconfigured. |
| `BASILISK_TURN_TTL_SEC` | Function App | Default `600`. The credential is spent within seconds of being minted; a long TTL only widens the window in which a leaked one is spendable. |



**Free tier ceiling.** Cloudflare Realtime's free tier is **1 TB/month** of relayed egress, and every relayed byte is the operator's. The proof-of-work gate and the IP limiter are what keep the endpoint from being an open relay billed to this deployment. Nothing here stores or caches a credential, so there is no TTL bookkeeping and no secret at rest.



## Cost ceilings

Most of this deployment's cost is *readiness*, not usage. These are the knobs that bound it — each is a hard stop, not an alert.

| Knob | Default | What it bounds |
| --- | --- | --- |
| `function_maximum_instance_count` / `maximumInstanceCount` | `20` | Scaled-out Function instances. Previously unset in Bicep and pinned to the platform default (100) in Terraform, so nothing was constrained: a traffic spike or an abuse burst scaled out unbounded. |
| `function_instance_memory_mb` / `instanceMemoryMB` | `2048` (dev profile: `512`) | Billing is instance-seconds x memory, so this multiplies every execution — $10.99 of execution time last month against $0.01 of executions. The keyserver's work is per-request and short, so 2048 was paying four times over; `domains.auto.tfvars` drops to the module's floor of 512 and the root module now passes the variable through, while `profiles/production.tfvars` takes 2048 back on the reasoning that the edge cache leaves the origin doing mostly API work. Allowed values are 512, 2048 and 4096. Raise it if the app OOMs. |
| `enable_front_door` | `false` (production profile: `true`) | Not a ceiling — a subscription. Front Door Standard's base fee is charged monthly whether the endpoint serves one request or none: $35.00 of a $61.11 month. It is the only line here that low traffic cannot reduce, which is why it is the one that became opt-in rather than something to remember to turn off. See [the section above](#azure-front-door-is-optional-enable_front_door) for what a deployment without it gives up. |
| `require_manager_approval` | `false` | Gates the approval Logic App's *existence*, not just its behaviour. The Service Bus trigger in that workflow is a Consumption-tier **polling** trigger — it wakes on an interval and checks the queue whether or not a message is there, and the connector has no push variant to switch to — so a deployed-but-idle workflow billed $11.07/month. On the live deployment that workflow had never completed a single run, so the polling was the entire cost and none of the behaviour; see [Logic App approval](#logic-app-approval) for why, and for the product bug that sits underneath it. `logic_app_name` is `null` when it is not deployed. |
| `log_analytics_daily_quota_gb` | `1` | Log Analytics ingestion per UTC day. `FrontDoorAccessLog` writes one record per request, so on the production profile ingestion scales with public traffic; that diagnostic setting is a child of the Front Door profile, so on the dev profile the workspace's largest source is simply absent and the Function App is what remains. Ingestion halts for the rest of the day at the cap and resets; already-ingested data is retained. `-1` disables. |
| `servicebus_sku` | `Basic` | Basic bills per operation with **no namespace base charge** and is the intended end state; Standard adds a fixed monthly fee and is required only for topics, sessions, duplicate detection or scheduled delivery, none of which this namespace's three queues use. |
| `web_pubsub_sku` | `Free_F1` | 20 concurrent connections, 20 000 messages/day. Cannot overspend. |

### Moving Service Bus to Basic takes two applies

Azure refuses a namespace downgrade while any queue holds a TTL above Basic's 14-day ceiling:

```
409 MessagingGatewayConflict: Namespace cannot be downgraded because at least one
queue 'key-approved' has DefaultMessageTimeToLive set with an invalid value, the
value need to be between 00:00:01 and 14.00:00:00
```

Left unset, a queue inherits Standard's default of `TimeSpan.MaxValue` (`P10675199DT2H48M5.4775807S`). The queues **cannot** be fixed in the same apply that moves the SKU — they depend on the namespace, so the namespace update runs first, 409s, and the queue updates never run. Terraform also stops everything downstream, which includes the Function App, since it takes the namespace connection string as an app setting.

So:

1. Apply with `servicebus_sku = "Standard"` and `default_message_ttl = "P14D"` on the queues.
2. Then set `servicebus_sku = "Basic"` (Terraform) / `serviceBusSku = 'Basic'` (Bicep) and apply again.

Both have been done — the TTLs landed first, then the tier moved. It is recorded here because the constraint is on the **queues**, not the tier: if a queue TTL is ever raised past 14 days, the namespace has to go back to Standard before that will apply, and the same 409 returns. 14 days is Basic's ceiling, chosen as the smallest change to existing behaviour — these queues carry key-ingest and mail events that Logic Apps consume within seconds.

**No always-ready Function instance is configured.** An always-ready instance is billed continuously whether or not a request arrives, which is a standing charge on an app that otherwise scales to zero. The trade is a cold start on the first request after an idle period. To buy it back, add an `alwaysReady` entry to `scaleAndConcurrency` — and note it is a per-second charge, not a one-off.

A resource-group budget exists in **both** deployment paths — `infra/modules/budget.bicep` and `azurerm_consumption_budget_resource_group` in Terraform — at `budget_amount` / `budgetAmount`, default 100/month. Bicep previously had none, which mattered because `azure.yaml` deploys through those templates, so the azd path ran with no cost alerting at all.

Three notifications fire, to the Owner role plus any `budget_contact_emails`:

| Threshold | Type | Why |
| --- | --- | --- |
| 80% | Actual | early warning |
| 100% | Actual | ceiling reached |
| 100% | Forecasted | the only one that arrives in time to act on — actual-spend alerts tell you the money is already gone |

**Budgets alert; they do not stop anything** — enforcement is the table above. The subscription spending limit does not apply to pay-as-you-go subscriptions, so do not rely on it as a backstop.

If throttling appears under legitimate load, raise `function_maximum_instance_count` deliberately rather than removing the ceiling.

## Observability



`GET /pks/lookup?op=stats` includes counters: `rejected_uploads`, `rate_limited`, `duplicate_uploads`.


