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

| `BASILISK_UPSTREAM_ENABLED` | 0 | Offer client-direct upstream HKP in the portal (browser fetches; Basilisk does not proxy) |

| `BASILISK_UPSTREAM_ALLOWLIST` | `keys.openpgp.org,keys.mailvelope.com` | Comma-separated HTTPS hostnames the UI may call |

| `BASILISK_UPSTREAM_DEFAULT` | `keys.openpgp.org` | Default host when the client omits `keyserver=` |

Upstream search runs only for **signed-in** users when enabled. CSP `connect-src` includes the allowlisted `https://` hosts (HTML meta, Function App header, Front Door). Terraform: `upstream_enabled` (default `false`). Advertised to the portal via `GET /api/v1/config` → `{ upstream: { enabled, allowlist, default } }`.



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

4. `POST /api/v1/quorum/negotiate` requires it too — signalling is gated the same way uploads are



## Quorum signalling (Azure Web PubSub)



Quorum's WebRTC signalling runs over **Azure Web PubSub**. The Function App stores nothing: `POST /api/v1/quorum/negotiate` checks proof-of-work and the rate limits, validates the room id, and returns a **client access URL** whose JWT is scoped to exactly one group. The browser then opens a plain `WebSocket` with the `json.webpubsub.azure.v1` subprotocol — no npm dependency — and publishes sealed envelopes to the group. There is no server-side room record, no TTL to sweep and no global room cap.

**Lobby and room.** Proof of work is an anti-abuse gate and costs a stranger exactly what it costs a member, so it cannot be what decides admission. A request carrying only a `room` id gets a token for that room's **lobby**; a request that also carries `key` — the whole base32 room digest, of which the id is the first 16 characters — gets a token for the **room** group, where signalling is actually broadcast. Computing the key takes the relying party and the full audience, so holding it means having been told who is meeting rather than having guessed a short code. The endpoint checks only that the key starts with the id; the audience never goes over the wire. Both group names are truncated SHA-256 digests under different labels, so the two namespaces cannot collide and the service's own logs and metrics see nothing about the room.

**Bounded connection lifetime.** A grant's expiry is checked when a connection is made and never again — the service does not hang up on a connection whose token has since expired — so a token that is not reissued only takes effect if the connection is re-made. The client therefore closes and re-opens the signalling connection at **80% of the grant's stated lifetime** (four minutes at the default 300 s TTL), joining the replacement before closing the original. Shortening `BASILISK_WEBPUBSUB_TOKEN_TTL_SEC` shortens the cycle with it; there is no second setting. Each cycle is a fresh negotiate and therefore a fresh proof of work. Note the cost: for the length of one handshake a peer holds two connections, which counts twice against the tier's concurrency ceiling.

**Room rotation.** There is no eviction API — no membership to enumerate, and no connection this application can name — so a room that needs to drop a member *moves* instead. The remaining members re-derive their material at the next epoch and mint tokens for the group it names; the removed member keeps a valid token for a group nobody is in. The new name mixes a secret minted at rotation and sealed to the members who stay, because the epoch and the remaining audience are both things a removed member can compute. Rotation is announced by the peer whose invite the room locked onto, over links whose keys are already confirmed.



This replaced an in-process mailbox that could not work on Consumption Functions: instances share no memory and recycle when idle, so two peers only met when they happened to hit the same warm worker.



| Setting | Where | Notes |
|---------|-------|-------|
| `AZURE_WEBPUBSUB_CONNECTION_STRING` | Function App | `Endpoint=…;AccessKey=…`. Terraform/Bicep wire it from the Web PubSub resource. Unset ⇒ negotiate returns **503**, and quorum is off. |
| `BASILISK_WEBPUBSUB_HUB` | Function App | Default `quorum`; must match the hub resource. |
| `BASILISK_WEBPUBSUB_TOKEN_TTL_SEC` | Function App | Default `300`. The token buys a handshake; the whole signalling bootstrap is seconds. |
| `web_pubsub_sku` / `web_pubsub_hub` | Terraform vars | Default `Free_F1` / `quorum`. |



**Token claims** (HS256, signed with the connection string's `AccessKey`): `sub` (an opaque per-connection id), `role` = `["webpubsub.joinLeaveGroup.<group>", "webpubsub.sendToGroup.<group>"]`, `webpubsub.group` = `["<group>"]`, plus `nbf`/`exp`/`iat`/`aud`. The unsuffixed `webpubsub.joinLeaveGroup` / `webpubsub.sendToGroup` roles — which would grant every group on the hub — are never minted, and neither are the wildcard `webpubsub.joinLeaveGroups.<pattern>` / `sendToGroups.<pattern>` roles the service also understands: a pattern covering a room family would hand out one token for every epoch that room will ever rotate through.



**CSP.** The signalling host is per-deployment, so it is never written into a policy string. `Settings.signaling_ws_origin()` derives `wss://<host>` from the connection string; `basilisk/serve.py` puts it in the response header, `basilisk/portal/static.py` merges it into each page's `<meta>` on the way out, and `terraform/…/frontdoor.tf` interpolates `local.signaling_wss_origin` into the header it overwrites. All three must allow it — the browser enforces the intersection. `tests/unit/test_csp_signaling.py` fails if they drift.



**Free tier ceilings.** `Free_F1` allows **20 concurrent connections** and **20 000 messages/day**. One connection per peer per session, and signalling moves onto the peer data channels as soon as a pair meshes — so both numbers scale with *peers*, not with how long a conversation lasts. A deployment expecting more than a few simultaneous rooms should set `web_pubsub_sku = "Standard_S1"`; nothing in the application changes.



**Locally and in CI**, leave `AZURE_WEBPUBSUB_CONNECTION_STRING` unset (or point it at loopback) and `python -m basilisk.serve` starts a local double that speaks the same subprotocol — the azurite pattern. `docker-compose.e2e.yml` publishes it on `8081`.



## TURN relay fallback (Cloudflare Realtime)



Some pairs of peers cannot reach each other directly — both behind symmetric NAT, or a network that filters UDP outright. The fix is a **TURN relay**, and the deployment question it raises is not "which one" but *when it is contacted*.



**The relay is not in the ICE server list.** Putting one there makes it last in ICE's priority order, but the agent still **allocates** on it during gathering, before any connectivity check has succeeded or failed — so a relay configured as a fallback learns this machine's address, and that a connection is being made, on **every** call, including the large majority that connect directly and never relay a byte. Basilisk therefore gathers and connects with STUN only, and escalates in a second phase: on a connection that reaches `failed`, the browser asks `POST /api/v1/turn/credentials` for a short-lived credential, calls `setConfiguration()` with the relay added and `restartIce()`, and re-gathers. Per W3C webrtc-pc ("set the configuration", step 9) and RFC 8829 §4.1.18, that pair is exactly what applies a new server list to a live connection — and the connection, its DTLS certificate and its data channel all survive, which matters because a quorum session key is derived over a transcript committing to that certificate. One escalation per connection; a second failure is reported, not retried.



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
| `function_instance_memory_mb` / `instanceMemoryMB` | `2048` | Billing is instance-seconds x memory, so this multiplies every execution. |
| `log_analytics_daily_quota_gb` | `1` | Log Analytics ingestion per UTC day. `FrontDoorAccessLog` writes one record per request, so ingestion scales with public traffic. Ingestion halts for the rest of the day at the cap and resets; already-ingested data is retained. `-1` disables. |
| `servicebus_sku` | `Basic` | Basic bills per operation with **no namespace base charge**. Standard adds a fixed monthly fee and is required only for topics, sessions, duplicate detection or scheduled delivery — none of which this namespace's three queues use. |
| `web_pubsub_sku` | `Free_F1` | 20 concurrent connections, 20 000 messages/day. Cannot overspend. |

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


