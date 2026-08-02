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

## Browser E2E (`web/`)

```bash
cd web
npx vitest run        # 139 files, node only, no browser, no sockets
npm run test:e2e      # builds dist/, then drives it in real Chromium
```

The two are separate on purpose. `npx vitest run` must stay fast and hermetic,
so the browser specs live behind `vitest.e2e.config.js` and a `.e2e.js` suffix
the default `include` cannot match. `npm run test:e2e` runs `npm run build`
first: the point is to drive the *shipped* bundle under the *production* CSP.

| Suite | Needs |
|-------|-------|
| `rtc-transport.e2e.js` | Chromium |
| `stun-discovery.e2e.js` | Chromium; one spec also wants public STUN |
| `turn-relay.e2e.js` | Chromium **and** Docker |

### The TURN relay suite

`turn-relay.e2e.js` starts its own `coturn` container, proves a `relay`
candidate and a relay-only connection through it, and tears it down. **No manual
setup**: the image is pulled on first run and cached after, the credentials are
chosen by `src/test/helpers/coturn.js`, and the published port is picked free at
runtime so parallel checkouts do not collide. Teardown is `docker rm -f` in
`afterAll`, and the container also runs `--rm` so a crashed run leaves nothing.

**Without Docker it skips, green.** The suite classifies *why* rather than
guarding on availability — no `docker`, no engine, and no image with no network
to fetch one are all "not news" and stand down; anything else is a real fault
and fails the run. A guard that filed every Docker complaint under "no Docker"
would skip itself green on the day the relay path broke.

```
Tests  5 passed | 18 skipped (23)      # no Docker
Tests  23 passed (23)                  # with Docker, ~6s
```

Run with `--reporter=verbose` to see the stand-down reason; the default reporter
collapses it.
