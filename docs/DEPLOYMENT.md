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
| `BASILISK_BASE_URL` | set post-apply from Front Door output |



Layout:



- `terraform/modules/basilisk/` — reusable module (storage, Service Bus, Flex Consumption Function App, Logic App, Front Door WAF, RBAC)
- `terraform/cloudshell/` — root module for one-shot deploy
- `scripts/deploy-terraform-cloudshell.{sh,ps1}` — init/plan/apply wrapper



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



The workflow applies Terraform, publishes function code, uploads the static portal to Storage `$web`, and smoke-tests Front Door. Use workflow input **skip_terraform** for code-only redeploys.



### Static portal hosting



Portal pages (`/`, `/search`, `/my-keys`, `/key`) are **static HTML/JS/CSS** in [`web/static/`](../web/static/). Front Door routes them to the storage account static website (`$web`); only API, HKP, claim, Easy Auth, and `/health` hit the Function App.



| Path pattern | Origin |
|--------------|--------|
| `/pks/*`, `/api/*`, `/claim/*`, `/.auth/*`, `/health` | Function App |
| `/*` (default) | Storage static website |



Deploy static assets after infrastructure apply:



```bash
bash scripts/deploy-static.sh
```



Or use the GitHub **deploy** workflow (runs `deploy-static.sh` automatically when Terraform outputs include the storage account name).



Local dev serves the same files from Flask (`basilisk/portal/static.py`) so URLs match production without Front Door.



For durable Terraform state across runners, bootstrap Azure Blob remote state:

```bash
clientId=$(az ad sp list --display-name basilisk-github-deploy --query "[0].appId" -o tsv)
GITHUB_SP_CLIENT_ID="$clientId" bash scripts/bootstrap-tfstate.sh --use-app-storage
```

See `docs/CI.md` and `scripts/bootstrap-tfstate.sh`.

## Custom domain (Route53 + Front Door)

Terraform registers `keys.b1tninja.com` (defaults in `terraform/cloudshell/variables.tf`) on Azure Front Door and maintains DNS in Route53.

### Prerequisites

1. **Route53 hosted zone** for `b1tninja.com`
2. **IAM user** with programmatic access scoped to that zone.

**Recommended:** set `route53_zone_id` (default in `terraform/cloudshell/variables.tf`) so Terraform never calls zone lookup APIs. Minimal policy:

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

To disable custom domain: `TF_VAR_custom_domain="" TF_VAR_route53_zone_name="" terraform apply`

### gpg

```bash
gpg --keyserver https://keys.b1tninja.com --recv-keys KEYID
```

### WAF residual risk (Standard SKU)

Front Door is deployed on **Standard_AzureFrontDoor**, which supports custom rate-limit WAF rules only. Microsoft Default Rule Set / Bot Manager require **Premium**. Direct origin access is blocked when `BASILISK_AFD_ID` is set on the Function App (must match `X-Azure-FDID`). Upgrade path is documented in `terraform/modules/basilisk/frontdoor.tf`.

### Production domain tfvars

`terraform/cloudshell/domains.auto.tfvars` sets `keys.b1tninja.com` (auto-loaded). Without it, empty defaults would drop the custom domain on apply. Override with `TF_VAR_custom_domain=""` or an untracked `production.tfvars` (see `production.tfvars.example`).

## Post-deploy



1. Authorize Logic App connectors in Azure Portal (see **Logic App approval** below)

2. Confirm `BASILISK_BASE_URL` on the Function App points at Front Door (Terraform deploy scripts set this)

3. Publish function code and smoke-test `/health`

4. Upload static portal: `bash scripts/deploy-static.sh`

5. Run `python -m basilisk.cli doctor` against production settings

6. (Optional) Enable Google sign-in — see [docs/AUTH.md](AUTH.md)



## Logic App approval



Resource: `{namePrefix}-approval-la` in `{namePrefix}-rg`.



### Queues



| Queue | Producer | Consumer |
|-------|----------|----------|
| `key-events` | Function App on upload / manager claim | Logic App (email + manager flow) |
| `key-approved` | Function App or Logic App after claim | `approve_fn` Function trigger |
| `sendtoken-events` | Function App on HKP v2 sendtoken | (sendtoken Logic App — optional) |



### Portal setup



1. Open **Logic App** → **Workflows** → edit the approval workflow
2. Authorize **Azure Service Bus** (namespace `{namePrefix}-bus`, queues `key-events` and `key-approved`)
3. Authorize **Office 365 Outlook** or **Gmail** (must match `mail_provider` at deploy time)
4. Save and ensure the workflow is **Enabled**



### End-to-end flow (default: no manager approval)



1. User uploads key → Function App writes blob + pending Table row → `key.pending` on `key-events`
2. Logic App sends verification email with `{BASILISK_BASE_URL}/claim/{fingerprint}`
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



### Front Door WAF rate limits



[`infra/modules/frontdoor.bicep`](../infra/modules/frontdoor.bicep) parameters:



- `uploadRateLimitPerMinute` — `POST /pks/add` (default 10/IP/min)

- `v2UploadRateLimitPerMinute` — v2 POST/PUT (default 5/IP/min)

- `sendtokenRateLimitPerMinute` — sendtoken (default 3/IP/min)



### Proof-of-work (v2 only)



When `BASILISK_REQUIRE_PROOF=1`:



1. `GET /pks/v2/challenge` returns a nonce and timestamp

2. v2 clients send `X-Basilisk-Proof: nonce:timestamp:signature`

3. Legacy `POST /pks/add` (`gpg --send-keys`) never requires proof



## Observability



`GET /pks/lookup?op=stats` includes counters: `rejected_uploads`, `rate_limited`, `duplicate_uploads`.


