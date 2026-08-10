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
npx vitest run        # 143 files, node only, no browser, no sockets
npm run test:e2e      # builds dist/, then drives it in real Chromium
```

The two are separate on purpose. `npx vitest run` must stay fast and hermetic,
so the browser specs live behind `vitest.e2e.config.js` and a `.e2e.js` suffix
the default `include` cannot match. `npm run test:e2e` runs `npm run build`
first: the point is to drive the *shipped* bundle under the *production* CSP.

| Suite | Needs |
|-------|-------|
| `rtc-transport.e2e.js` | Chromium |
| `peer-manager.e2e.js` | Chromium |
| `quorum-key-confirmation.e2e.js` | Chromium |
| `hkp-directory.e2e.js` | Chromium for the browser half; the wire half needs nothing |
| `stun-discovery.e2e.js` | Chromium; one spec also wants public STUN |
| `turn-relay.e2e.js` | Chromium **and** Docker |

### The HKP directory suite

`hkp-directory.e2e.js` runs `hkp.get`, `hkp.search`, `hkp.filter`, `hkp.cache`
and `publishArmoredKey` (what the `key.publish` artifact action calls) against a
directory, which none of them had ever met in a test. It can, because those ops
resolve against `${location.origin}/pks/lookup` — "This site" — so a directory
served by the same loopback server that serves `dist/` is same-origin by
construction and needs no CSP change.

`src/test/helpers/keyserver.js` is that directory: in-process, seedable, and
**not** an independent invention. Its response shapes are taken from the Python
service this repo actually ships — `basilisk/hkp/lookup.py`, `basilisk/hkp/add.py`,
`basilisk/portal/routes.py`, `basilisk/portal/search.py`,
`basilisk/db/sqlite_store.py` — including the parts a cleaner design would
change, because a stub that answers more helpfully than the server hides the
defects it exists to find. `basilisk/hkp_v2/` does not need separate modelling:
every one of its GET routes calls the same `lookup_get`.

It is not only `/pks/lookup`. `hkp.get` resolves through
`Promise.all([fetchJson("/api/v1/key/<fpr>"), fetchText("/pks/lookup?op=get…")])`
and `hkp.search` never issues an HKP request at all — it reads
`GET /api/v1/search?q=`. A lookup-only fake cannot run either op.

`src/test/helpers/key-corpus.js` supplies the population: eight keys generated
per run (~200ms, RSA-2048 included), sharing a surname and a domain so a search
returns several, with one multi-uid key, one signing-only key, one genuinely
expired key, one carrying a real revocation signature, one still pending, and
both algorithms. Nothing is checked in — armored text in the repo needs a
`.gitattributes` to survive a Windows checkout, and generation is cheaper than
the trap.

Keys are seeded **directly** (`keyserver.seed(corpus.list)`), never through
`POST /pks/add`. Only the publish specs use the submission door, so a defect in
publishing cannot fail every lookup test.

Several specs are labelled **DEFECT**: they assert behaviour that is wrong, so a
fix turns them red and has to be acknowledged rather than passing silently.

This suite does **not** replace `tests/e2e/test_hkp_*.py`, which drive real
`gpg --send-keys` / `--recv-keys` against the real server under
`docker-compose.e2e.yml`. That stack proves the server; this one proves the
browser client, without a second process in the Playwright path.

### The key-confirmation suite

`quorum-key-confirmation.e2e.js` is the browser half of
`src/test/quorum-dtls-binding.test.js`. Two real `QuorumSession`s mesh over two
real `RTCPeerConnection`s and confirm a pairwise key; the transcript is then
checked against the DTLS fingerprints the two engines actually minted, read back
out of Chromium's own SDP.

It needs two things `browser-peers.js` did not serve — a signalling mailbox and
a keyserver — so `src/test/helpers/quorum-room.js` supplies both in memory for
exactly the two identities the test generates, and `serveDist` takes a `routes`
hook that gets first refusal on each request. Both are same-origin, so
`connect-src 'self'` covers them and no policy is relaxed.

The mailbox opens every envelope and re-seals it under the **original signer's
own private key**, which is what makes the negative half possible: one end's
claimed fingerprint is rewritten while its SDP is left untouched, so the
transport still comes up, every PGP check still passes, and only the transcript
binding can notice. Delete `dtlsFingerprint` from the transcript in
`lib/quorum/crypto.js` and that half goes red — which is the only reason the
positive half means anything.

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
