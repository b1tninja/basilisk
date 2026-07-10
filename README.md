<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/basilisk-wordmark-dark.png">
  <img alt="Basilisk — Verifying Keyserver" src="docs/assets/basilisk-wordmark.png" width="480">
</picture>

Minimalist serverless verifying OpenPGP keyserver (HKP v1/v2) with Azure Functions, Logic Apps, and WORM blob storage.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
copy .env.example .env
python -m basilisk.serve --port 8080
```

Upload a key:

```bash
gpg --keyserver http://localhost:8080 --send-keys YOURKEYID
python -m basilisk.cli approve YOURFINGERPRINT --uids "you@example.com"
gpg --keyserver http://localhost:8080 --recv-keys YOURKEYID
```

## Development

| Command | Description |
|---------|-------------|
| `make install` | Create venv and install deps |
| `make dev` | Run Flask dev server on :8080 |
| `make test` | Unit + integration tests |
| `make test-e2e` | Docker gpg round-trip |
| `python -m basilisk.cli doctor` | Check dependencies |

## Brand assets

| File | Use |
|------|-----|
| [`docs/assets/basilisk-wordmark.png`](docs/assets/basilisk-wordmark.png) | README / light theme |
| [`docs/assets/basilisk-wordmark-dark.png`](docs/assets/basilisk-wordmark-dark.png) | Dark theme |
| [`docs/assets/basilisk-logo.png`](docs/assets/basilisk-logo.png) | Icon, light background |
| [`docs/assets/basilisk-logo-dark.png`](docs/assets/basilisk-logo-dark.png) | Icon, dark background |
| [`docs/assets/basilisk-favicon.png`](docs/assets/basilisk-favicon.png) | Favicon (32–64 px) |

## Architecture

- **Upload:** Policy validation first; WORM blob write only after pass; Table `approval_state=pending`
- **Approve:** Logic Apps email only → `key.approved` → `approve_fn` updates Table
- **Lookup:** Table gate → blob read → SHA-256 verify → filter-at-read for email

## Ingest security

Basilisk rejects invalid uploads **before** any blob or Table write:

- Armored v4 public keys only on `/pks/add` (64 KiB max by default)
- At least one email UID required; disposable domains blocklist configurable
- `options=nm` rejected; secret keys rejected; revoked keys rejected
- Rate limits per IP (in-app + Front Door WAF in production)
- Optional proof-of-work on HKP v2 upload paths (`BASILISK_REQUIRE_PROOF=1`); **`gpg --send-keys` is exempt**

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for tunables and Azure WAF parameters.

## CI secrets

GitHub Actions needs repository secrets for deploy and optional test hardening. See [docs/CI.md](docs/CI.md).
