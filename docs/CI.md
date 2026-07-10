# GitHub Actions

Workflows run on `ubuntu-latest` (GitHub-hosted runners) using Node 24–compatible actions:

| Action | Version |
|--------|---------|
| `actions/checkout` | v5 |
| `actions/setup-python` | v6 (pip cache enabled) |
| `azure/login` | v2 |

## Secrets

Configure these under **Settings → Secrets and variables → Actions** for the repository.

| Secret | Required by | Purpose |
|--------|-------------|---------|
| `BASILISK_TOKEN_SECRET` | `ci.yml`, `e2e.yml` | HMAC secret for HKP v2 bearer tokens in tests. Optional: workflows fall back to `ci-test-secret` from `.env.test.example` if unset. |
| `AZURE_CREDENTIALS` | `deploy.yml` | JSON service principal for `az login` during Azure deploy (`clientId`, `clientSecret`, `subscriptionId`, `tenantId`). |

## Local vs CI

- **Never commit** `.env`, `.env.test`, or `local.settings.json` (see `.gitignore`).
- **Committed templates:** `.env.example`, `.env.test.example`
- **CI:** `scripts/prepare-ci-env.sh` copies examples and injects `BASILISK_TOKEN_SECRET` from GitHub Secrets when set.

## Generate values

```bash
# Token secret (production or CI)
python -c "import secrets; print(secrets.token_urlsafe(48))"

# Azure deploy principal
az ad sp create-for-rbac --name basilisk-github-deploy --role contributor \
  --scopes /subscriptions/<subscription-id> --sdk-auth
```

Paste the `az` JSON output into the `AZURE_CREDENTIALS` secret.
