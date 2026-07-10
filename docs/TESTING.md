# Testing

## Unit / integration

```bash
pytest tests/unit tests/integration -m "unit or integration"
```

## E2E (Docker + gpg)

Requires Docker Desktop.

```bash
docker compose -f docker-compose.e2e.yml up -d --build
pytest tests/e2e -m e2e
docker compose -f docker-compose.e2e.yml down
```

E2E tests run real `gpg --send-keys` / `--recv-keys` against the basilisk container via the `gpg-tester` service.
