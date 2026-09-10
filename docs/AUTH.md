# Authentication setup

Basilisk uses **Azure App Service Easy Auth** as the identity layer. The Function App handles all token validation; static portal pages are fully anonymous and call the API with session cookies injected by Easy Auth.

Two identity providers are supported:

| Provider | Sign-in URL | Status |
|---|---|---|
| Microsoft (Entra ID / AAD) | `/.auth/login/aad` | Always enabled |
| Google | `/.auth/login/google` | Optional — requires credentials below |

---

## How Easy Auth works here

```
Browser → [Front Door] → Function App (Easy Auth middleware)
                                ↓
                 X-MS-CLIENT-PRINCIPAL header injected
                                ↓
                 Flask app reads email + name from header
```

Front Door is in brackets because whether it is there is a deployment-profile decision, not a property of the app: `enable_front_door` defaults to false, and only the production profile turns it on — see [docs/DEPLOYMENT.md](DEPLOYMENT.md#deployment-profiles). Everything below that talks about a "public hostname" means whatever `terraform output -raw public_url` returns: the custom domain if there is one, otherwise the Front Door endpoint, otherwise the Function App's own `*.azurewebsites.net`. On the dev profile the public hostname **is** the Function App hostname, and the two-host confusion this section exists to warn about does not arise — there is only one host. On the production profile there are two, and everything below matters.

- Easy Auth runs **in front of** the Flask app, before any Python code runs.
- `unauthenticated_action = "AllowAnonymous"` — anonymous requests reach the app; individual API routes enforce auth in code.
- The session cookie (`AppServiceAuthSession`) is `HttpOnly` / `Secure`. With `forward_proxy_convention = Standard`, it is scoped to the **public** hostname. Where a proxy sits in front and the public hostname differs from the origin's, dropping that setting makes the cookie stick on `*.azurewebsites.net` and sign-in appears to “fail” or repeat on the public name. Terraform sets it unconditionally, so this holds whether or not Front Door is deployed.
- No server-side token store (`token_store_enabled = false`) — stateless, cache-friendly.

---

## Microsoft Entra ID (AAD)

### What you need
- An Azure Active Directory tenant (this is your `entra_tenant_id`, which Terraform reads automatically from `az account show`)
- An **App Registration** in that tenant

The current Terraform config uses the placeholder client ID `00000000-0000-0000-0000-000000000000`, which causes Azure to auto-create a managed app registration on first deploy. This works for development but gives you less control. For production, create a registration manually (below).

### Create an App Registration

1. Go to **Azure Portal → Microsoft Entra ID → App registrations → New registration**

2. Fill in:
   - **Name**: `basilisk` (or `basilisk-prod`)
   - **Supported account types**: choose the narrowest that fits:
     - *Accounts in this organizational directory only* — restricts sign-in to your tenant (recommended for internal tools)
     - *Accounts in any organizational directory* — allows any Microsoft 365 tenant
     - *Accounts in any organizational directory and personal Microsoft accounts* — allows personal Outlook/Hotmail too

3. **Redirect URI** — platform: **Web**
   ```
   https://<function-app-name>.azurewebsites.net/.auth/login/aad/callback
   ```
   Replace `<function-app-name>` with your actual name (e.g. `basilisk-dev-fn`).
   If you also test locally via Flask, add `http://localhost:7071/.auth/login/aad/callback`.

4. Click **Register**.

5. Copy the **Application (client) ID** — you will need it.

### Required API permissions

Easy Auth only needs the standard **OpenID Connect** claims. No Microsoft Graph permissions are required.

The following delegated scopes are requested automatically by Easy Auth and appear as pre-consented:

| Scope | Why |
|---|---|
| `openid` | Sign-in token |
| `email` | User's email address |
| `profile` | Display name |

**Do not add** any Microsoft Graph permissions unless your application code calls the Graph API directly. User consent is not required for these built-in scopes.

### Wire the client ID into Terraform

Add the `entra_client_id` variable to `terraform/modules/basilisk/variables.tf`:

```hcl
variable "entra_client_id" {
  type        = string
  description = "AAD App Registration client ID for Easy Auth."
  default     = "00000000-0000-0000-0000-000000000000"
}
```

Then update `auth_settings_v2` in `terraform/modules/basilisk/functions.tf`:

```hcl
active_directory_v2 {
  client_id            = var.entra_client_id
  tenant_auth_endpoint = "https://login.microsoftonline.com/${var.entra_tenant_id}/v2.0/"
}
```

Pass at deploy time:

```bash
TF_VAR_entra_client_id=<app-id> ./scripts/deploy-terraform-cloudshell.sh
```

Or as a GitHub Actions secret:

```bash
gh secret set ENTRA_CLIENT_ID --body "<app-id>" --repo <owner>/<repo>
```

Then add to `.github/workflows/deploy.yml` env:

```yaml
env:
  TF_VAR_entra_client_id: ${{ secrets.ENTRA_CLIENT_ID }}
```

---

## Google OAuth 2.0

### What you need
- A Google Cloud project
- An OAuth 2.0 Web client credential (client ID + client secret)

### Create the credential

#### 1. Create or select a project

Go to [console.cloud.google.com](https://console.cloud.google.com) → select an existing project or **New Project**.

#### 2. Configure the OAuth consent screen

**APIs & Services → OAuth consent screen**

| Field | Value |
|---|---|
| User type | **Internal** (Google Workspace users only) or **External** (any Google account) |
| App name | `Basilisk` |
| User support email | your address |
| Authorized domains | See below — usually **leave empty** for default Azure hosting |
| Developer contact | your address |

**Authorized domains vs redirect URIs**

These are different settings in Google Cloud:

| Setting | Where | What to use |
|---|---|---|
| **Authorized redirect URIs** | OAuth client (Credentials) | Full callback URL(s) — **required**; include **custom domain + Function App** |
| **Authorized domains** | OAuth consent screen | Root domain you own (`b1tninja.com`) — recommended with custom domain. Terraform passes this through as `oauth_authorized_domain`, and it names the domain on the **consent screen**, not the callback host, so it stays correct even with no custom domain in play |

### Which callback URI actually gets used

Whatever `public_url` resolves to. Easy Auth builds the callback for the host the browser used, and `forward_proxy_convention = "Standard"` — which Terraform sets unconditionally — is what makes it honour a proxy's forwarded host rather than its own.

**On the production profile**, which brings Front Door and the custom domain, that is `https://keys.b1tninja.com/.auth/login/google/callback`, and the Function App URI is the spare you keep registered for direct and debug access.

**On the dev profile** — `enable_front_door = false`, which is what a deployment gets unless it asks otherwise — there is no proxy and no custom domain, so the public hostname is the Function App's own and the **Function App callback is the one Google will be sent**:

```
https://basilisk-dev-fn.azurewebsites.net/.auth/login/google/callback
```

`oauth_setup.google_redirect_uris` reflects this: it is `distinct()` over the public-URL callback and the Function-App callback, so when those are the same string the list has exactly one entry. The output's instruction to register **all** of them is unchanged and still correct — on the dev profile the list is just shorter.

**That registration is a manual step Terraform cannot perform.** It configures the `google_v2` block and injects the client secret from Key Vault; the Authorized redirect URIs live in a Google Cloud project it holds no credential for. If the Function App URI was never registered, Google answers `Error 400: redirect_uri_mismatch` and sign-in fails while every Azure-side setting reads correct.

**Do this in Google Cloud Console now** (OAuth client → Authorized redirect URIs) — add **both**, and leave both registered permanently:

```
https://keys.b1tninja.com/.auth/login/google/callback
https://basilisk-dev-fn.azurewebsites.net/.auth/login/google/callback
```

A spare authorized redirect URI costs nothing, and keeping both means turning Front Door on or off never has to wait on someone with Google Cloud access.

Also add `b1tninja.com` under **OAuth consent screen → Authorized domains** if you own it and are using the custom domain.

Then apply Terraform (`skip_terraform: false`), clear cookies for both hosts, and sign in again from the public URL.

After `terraform apply`, confirm which URI the deployment you just applied will actually send:

```bash
cd terraform/cloudshell
terraform output -json oauth_setup | jq -r '.google_redirect_uris[]'
```

Under **Scopes**, add:

| Scope | Description |
|---|---|
| `openid` | Required for OIDC |
| `.../auth/userinfo.email` | User's email address |
| `.../auth/userinfo.profile` | Display name |

These are all **non-sensitive** scopes — no Google verification or review is required.

> **Internal vs External:**
> - *Internal* — only users in your Google Workspace organization can sign in. No publishing needed. Best for corporate deployments.
> - *External (testing)* — any Google account, but limited to 100 test users you add manually. Suitable for evaluation.
> - *External (published)* — any Google account. Requires Google's verification only if you request sensitive/restricted scopes (these three are not sensitive).

#### 3. Create OAuth 2.0 credentials

**APIs & Services → Credentials → Create credentials → OAuth client ID**

| Field | Value |
|---|---|
| Application type | **Web application** |
| Name | `basilisk-easy-auth` |
| Authorized redirect URIs | Paste **every** URI from `google_redirect_uris`, and keep the other one registered too |

```
https://keys.b1tninja.com/.auth/login/google/callback
https://basilisk-dev-fn.azurewebsites.net/.auth/login/google/callback
```

Google’s `redirect_uri` is the **public** hostname, which is the Function App's own when there is no Front Door. If that URI is missing, Google returns `Error 400: redirect_uri_mismatch`.

Also add `b1tninja.com` under **OAuth consent screen → Authorized domains** if you are using the custom domain.

Click **Create**. Download or note the **Client ID** and **Client secret**.

### Set the secrets

#### GitHub Actions (recommended)

```bash
gh secret set GOOGLE_CLIENT_ID     --body "<client-id>"     --repo <owner>/<repo>
gh secret set GOOGLE_CLIENT_SECRET --body "<client-secret>" --repo <owner>/<repo>
```

Then add `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` as repository secrets. The deploy workflow picks them up automatically when **Google sign-in** is set to `auto` (the default).

```yaml
- name: Resolve sign-in settings
  run: bash scripts/resolve-deploy-auth.sh
```

#### Manual / Cloud Shell

```bash
export TF_VAR_enable_google_auth=true
export TF_VAR_google_client_id="<client-id>"
export TF_VAR_google_client_secret="<client-secret>"
./scripts/deploy-terraform-cloudshell.sh
```

When `TF_VAR_google_client_id` is non-empty, Terraform adds a `google_v2` block to Easy Auth and injects `GOOGLE_PROVIDER_AUTHENTICATION_SECRET` into the Function App settings. When it is empty (the default), Google sign-in is simply not configured — no other change is needed.

### GitHub Actions deploy workflow

Sign-in providers use **auto / on / off** (default `auto`):

| Input | Default | Behavior |
|-------|---------|----------|
| `enable_microsoft_signin` | `auto` | Enable when `AZURE_CREDENTIALS` secret exists |
| `enable_google_signin` | `auto` | Enable when both `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` exist |

`scripts/resolve-deploy-auth.sh` runs before deploy and sets `TF_VAR_*` from secret presence. Use **off** to disable Google even when secrets exist; **on** fails if secrets are missing.

Leave **Skip terraform** unchecked so Easy Auth is updated. The portal reads `/api/v1/auth/config` and only shows configured providers.

After deploy, verify:

```bash
curl -s "$(terraform -chdir=terraform/cloudshell output -raw public_url)/api/v1/auth/config"
# {"providers": ["microsoft", "google"]}
```

---

## Claims reference

After sign-in, Easy Auth injects `X-MS-CLIENT-PRINCIPAL` (base64 JSON) into every request that reaches the Function App. The `basilisk.auth.azure` module extracts:

| Field | Microsoft (AAD) claim | Google (OIDC) claim |
|---|---|---|
| `email` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `emails` or `preferred_username` |
| `oid` | `http://schemas.microsoft.com/identity/claims/objectidentifier` | `sub` |
| `name` | `name` | `name` |

The `email` field is normalized to lowercase. It is used to:
- Associate uploaded keys with the submitter
- Auto-claim keys whose UIDs contain a matching email address
- Return `GET /api/v1/me/keys` results filtered to the signed-in user

---

## Security notes

- **No secrets in the browser** — the OAuth flow is entirely server-side via Easy Auth. The static portal pages never see a token; they only use the session cookie.
- **Session cookies** — `AppServiceAuthSession` is `HttpOnly`, `Secure`, and scoped to the **public** hostname when `forward_proxy_convention = Standard`. Where that hostname differs from the origin's — a custom domain or a Front Door endpoint — landing on `*.azurewebsites.net` after sign-in means the cookie is on the wrong host and consent will repeat. With no edge deployed the public hostname *is* `*.azurewebsites.net`, so landing there is correct rather than a symptom.
- **Token store disabled** — `token_store_enabled = false` keeps the Function App stateless. Access tokens are not cached server-side; refresh tokens are not stored. Re-authentication is required when the session expires (typically 8 hours).
- **AllowAnonymous** — unauthenticated requests are not blocked at the Easy Auth layer. The `/api/v1/search`, HKP lookup, and `/health` endpoints are intentionally public. Auth is enforced in Python code for `/api/v1/me` and `/api/v1/me/keys`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `/.auth/login/google` returns 404 | Google provider not configured in Terraform | Add `GOOGLE_*` secrets; leave sign-in on `auto` or `on`; re-run with `skip_terraform: false` |
| Google button missing on portal | Provider not in `BASILISK_AUTH_PROVIDERS` | Same as above — `curl /api/v1/auth/config` should list `"google"` |
| Sign-in succeeds but `/api/v1/me` returns 401 | Email claim missing from token | Check OAuth consent screen has `email` scope; check App Registration optional claims |
| Google sign-in shows "redirect_uri_mismatch" | Redirect URI not in Google credentials — the usual cause after a deploy that switched profiles, since the public URL moves with the profile and Terraform cannot register the new one | Add **both** `https://keys.b1tninja.com/.auth/login/google/callback` and `https://basilisk-dev-fn.azurewebsites.net/.auth/login/google/callback`, and leave both registered |
| After Google sign-in, lands on `*.azurewebsites.net` **while a custom domain is deployed** | Easy Auth ignoring the forwarded host | Apply Terraform with `forward_proxy_convention=Standard`; clear cookies for both hosts; retry from the public URL. On the dev profile this is not a fault — that host *is* the public URL |
| Repeated Google consent prompts | Session cookie set on a host other than the public one | Same as above — the cookie must be on whatever `terraform output -raw public_url` returns |
| Signed-in user sees someone else's keys | `email` claim returns different address per provider | Ensure both AAD and Google accounts share the same email address |
