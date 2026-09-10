![Basilisk](docs/assets/basilisk-logo.png)

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
| [`docs/assets/basilisk-logo.png`](docs/assets/basilisk-logo.png) | Icon (transparent) |
| [`docs/assets/basilisk-logo-dark.png`](docs/assets/basilisk-logo-dark.png) | Icon, dark background |
| [`docs/assets/basilisk-favicon.png`](docs/assets/basilisk-favicon.png) | Favicon (32–64 px) |

## Architecture

- **Upload:** Policy validation first; WORM blob write only after pass; Table `approval_state=pending`; `key.pending` → Service Bus
- **Approve:** Claim (Entra) → `key.approved` on `key-approved` queue → `approve_fn` updates Table. A Logic App is *designed* to send the verification email on `key.pending`, but it needs API connections Terraform does not create and has never run on the reference deployment — see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#logic-app-approval) before assuming those mails go out
- **Lookup:** Table gate → blob read → SHA-256 verify → filter-at-read for email

## Portal cryptography

The browser portal combines OpenPGP.js (messaging), WebCrypto (vault, shared notebook, toolkit keygen), and custom SSS/BLIP39. See [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) for the module inventory and WebCrypto toolkit gap tracker.

## Ingest security

Basilisk rejects invalid uploads **before** any blob or Table write:

- Armored v4 public keys only on `/pks/add` (64 KiB max by default)
- At least one email UID required; disposable domains blocklist configurable
- `options=nm` rejected; secret keys rejected; revoked keys rejected
- Rate limits per IP, in-app. The Front Door WAF adds per-minute limits at the edge, but only on the production deployment profile — `enable_front_door` defaults to false, so a default deployment has the in-app limiter and nothing else; see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what that achieves on its own and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the profiles
- Optional proof-of-work on HKP v2 upload paths (`BASILISK_REQUIRE_PROOF=1`); **`gpg --send-keys` is exempt**

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for tunables and Azure WAF parameters.

## CI secrets

GitHub Actions needs repository secrets for deploy and optional test hardening. See [docs/CI.md](docs/CI.md).
