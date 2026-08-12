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
npx vitest run        # node only, no browser, no sockets — seconds
npx tsc --noEmit      # must exit 0; see below
npm run test:e2e      # builds dist/, then drives it in real Chromium
```

No file count here on purpose: it was `143` for long enough to be wrong by
forty, and a number nobody updates is worse than no number.

The two are separate on purpose. `npx vitest run` must stay fast and hermetic,
so the browser specs live behind `vitest.e2e.config.js` and a `.e2e.js` suffix
the default `include` cannot match. `npm run test:e2e` runs `npm run build`
first: the point is to drive the *shipped* bundle under the *production* CSP.

| Suite | Needs |
|-------|-------|
| `rtc-transport.e2e.js` | Chromium |
| `peer-manager.e2e.js` | Chromium |
| `quorum-key-confirmation.e2e.js` | Chromium |
| `hkp-directory.e2e.js` | Python that can import `basilisk.serve`; Chromium for the browser half |
| `stun-discovery.e2e.js` | Chromium; one spec also wants public STUN |
| `turn-relay.e2e.js` | Chromium **and** Docker |
| `placed-run-arc.e2e.js` | Chromium; Python that can import `basilisk.serve` |
| `portal-search.e2e.js` | Chromium; Python that can import `basilisk.serve` |

### What CI runs, and what it does not

`ci.yml` runs the node suite and `npx tsc --noEmit` on every push and pull
request. Neither ran there until recently: the job built the portal and audited
dependencies, and vite strips types without reading them, so a green build said
nothing about whether anything type-checked. Three real errors reached `main`
that way.

The browser suite runs in `e2e.yml`'s `browser` job — **push to `main` and
`workflow_dispatch` only, not on pull requests**, because it has had
load-sensitive flakes and gating a PR on one teaches people to re-run red CI.
That workflow says what has to be true before it moves onto PRs. Every run
writes `web/test-results/e2e.xml`, kept as an artifact, because a rare failure
here is expensive to reproduce and the terminal scrolls.

### The HKP directory suite

`hkp-directory.e2e.js` runs `hkp.get`, `hkp.search`, `hkp.filter`, `hkp.cache`
and `publishArmoredKey` (what the `key.publish` artifact action calls) against a
directory, which none of them had ever met in a test. It can, because those ops
resolve against `${location.origin}/pks/lookup` — "This site" — so a directory
served by the same loopback server that serves `dist/` is same-origin by
construction and needs no CSP change.

`src/test/helpers/basilisk-server.js` supplies that directory by running the
service this repo ships. `startBasilisk()` spawns `basilisk/serve.py` on a free
loopback port and returns a `routes` hook that **proxies** `/pks/*`, `/api/v1/*`,
`/claim/*` and `/.well-known/*` at it — proxies rather than redirects, so the
browser still sees exactly one origin and `connect-src 'self'` is the policy
under test.

An earlier draft used a JavaScript reimplementation of `/pks/lookup`. It was
deleted on purpose: two implementations of one idea can disagree, and the one
under test is never the one users hit. Nothing in the suite constructs a
response any more — the server emits, the test reads. Several of the assertions
below exist because the real bytes turned out to differ from what the
reimplementation produced.

No Docker and no Azure. `basilisk/db/factory.py` picks its stores from one
variable: with `AZURE_STORAGE_CONNECTION_STRING` unset it falls back to
`SqliteCertStore` and `LocalBlobStore`, which need nothing running, so each run
gets a fresh temp directory. `docker-compose.e2e.yml` exists because the *Python*
e2e deliberately exercises the Azure branch; the browser suite has no such need.
`basilisk/hkp_v2/` needs no separate handling either: every one of its GET routes
calls the same `lookup_get`.

It is not only `/pks/lookup`. `hkp.get` resolves through
`Promise.all([fetchJson("/api/v1/key/<fpr>"), fetchText("/pks/lookup?op=get…")])`
and `hkp.search` never issues an HKP request at all — it reads
`GET /api/v1/search?q=`. A lookup-only fake cannot run either op.

`src/test/helpers/key-corpus.js` supplies the population: eight keys generated
per run (~100ms, RSA-2048 included), sharing a surname and a domain so a search
returns several, with one multi-uid key, one signing-only key, one genuinely
expired key, one carrying a real revocation signature, one still pending, and
both algorithms. Nothing is checked in — armored text in the repo needs a
`.gitattributes` to survive a Windows checkout, and generation is cheaper than
the trap.

`seedDirectory()` puts that corpus in through `POST /pks/add` then
`POST /api/v1/dev/approve` — the same two calls `tests/helpers/hkp_client.py`
makes for the Python e2e, so both suites populate a directory the same way and
the corpus is validated by the policy that runs in production. `BASILISK_DEV_APPROVE=1`
is what opens the second route; `BASILISK_DEV_AUTH=1` is what lets the harness
forge the Easy Auth principal the signed-in publish path needs. Refusals are
returned rather than thrown, because a key the server declines is a fact worth
asserting: the revoked key is refused outright on the default upload policy, so
the fixture starts the server with `rejectRevoked: false` to model a key revoked
*after* it was accepted.

The whole file stands down when no Python can import `basilisk.serve`, and the
browser half additionally when Chromium is absent. A Python that is present and
a server that will not start is a real failure and is reported as one, with
whatever the process wrote before it died.

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
