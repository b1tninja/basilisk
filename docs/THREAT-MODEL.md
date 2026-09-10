# Threat model

What Basilisk defends against, what it does not, and — the part most browser
crypto tools leave out — **which of these claims you can check yourself**.

Every factual claim below is pinned by `web/src/test/threat-model.test.js`
against the code it describes. If someone weakens a header or changes where
keys are stored and forgets this page, that test fails. A threat model that
can drift from its implementation is marketing.

---

## The one that matters most: you are trusting served code

Every in-browser cryptography tool has the same root problem, and it is worth
stating before anything else:

> Each time you load the page, the server hands you the JavaScript that will
> touch your keys. A server that is compromised — or compelled — can hand you
> different JavaScript exactly once, to exactly one person.

Nothing in this repository fully solves that. Native software is signed once
and inspected by many; a web page is delivered per-visit and inspected by
approximately nobody. What Basilisk does is narrow the gap and make tampering
*detectable* rather than invisible:

- **Subresource integrity on every module.** The build externalizes importmaps
  and emits SRI hashes, so a modified module fails to execute rather than
  running silently.
- **A published Merkle root over those hashes.** `web/scripts/write-module-integrity-pin.mjs`
  writes `/integrity/module-roots.json` and injects pin `<meta>` tags, so the
  running page can cross-check the code it loaded against a separately cacheable
  pin document. **That pin is served by the same origin as the code**, so an
  edge that rewrites the assets can rewrite the pin to match and the check
  agrees with itself. `verifyModuleRootAgainstPins` compares *all* configured
  pin sources and refuses when they disagree, which is what would make
  subverting one host insufficient — but nothing here configures a second one,
  and the panel says so rather than implying the comparison ran. Making it real
  needs four things this repository does not have: a value for
  `VITE_INTEGRITY_PIN_MIRRORS` at build time, a second origin under separate
  operational control that publishes the same pin document, an upload step in
  `scripts/deploy-static.sh` that puts it there, and that origin added to the
  `connect-src` of whichever component writes the CSP **response header** — a
  mirror allowed only by the page's own `<meta>` is a mirror the browser will
  refuse to fetch, because a browser enforces the intersection of the two.
  Which component that is depends on the deployment profile: on the production
  profile the `SecurityHeaders` rule set in
  `terraform/modules/basilisk/frontdoor.tf` overwrites whatever the origin
  sent, so the mirror has to be named there; on the dev profile there is no
  edge and the header is built by `Settings.csp_connect_src()` and applied in
  `basilisk/serve.py`'s `after_request`. Adding a mirror means editing
  whichever of those two writes the header for the deployment you are actually
  running — and, if you want it to hold on both, editing both.
- **A strict CSP with no escape hatches** (below), so injected code has nowhere
  to run even if it reaches the page.

**What is still missing, honestly:** the pin document is served by the same
project, and there is no reproducible-build attestation or third-party
transparency log. If you are protecting something whose loss is
unrecoverable — a root key, a treasury seed — treat the browser as a
convenience for *drafting and inspection*, and do the final ceremony offline
with audited native tooling. The toolkit is designed to make that hand-off
easy (see `docs/CLI.md`), not to argue you out of it.

---

## Content Security Policy

The production policy, verbatim from the page `<meta>`:

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
connect-src 'self' https://keys.openpgp.org https://keys.mailvelope.com;
img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self';
form-action 'self';
```

Consequences that are load-bearing rather than decorative:

- **No inline styles anywhere.** `style-src 'self'` blocks every
  `element.style` write, including the ones React makes from a style object.
  `no-inline-styles.test.js` enforces this at source level, with an empty
  baseline: closed vocabularies become data attributes with enumerated CSS,
  and genuinely continuous values (a panel width, a progress bar) go through a
  *constructed* stylesheet (`lib/css-vars.js`), which is CSSOM built by
  already-trusted script and therefore not an inline style.
- **`connect-src` is an allow-list of two keyservers.** The app cannot phone
  anywhere else. Exfiltrating a key by `fetch` to an attacker's host is
  blocked by the policy, not by our good intentions.
- **`default-src 'none'` and `object-src 'none'`** mean anything not
  explicitly permitted above is refused.
- **`'wasm-unsafe-eval'` is not `'unsafe-eval'`,** despite the shared suffix.
  It permits WebAssembly compilation and nothing else — it does not allow
  `eval` of strings or `new Function`. It is present because OpenPGP.js
  compiles Argon2 (the S2K used to lock vault keys) to WebAssembly. Removing
  it would break passphrase-protected keys, not tighten the eval surface.
- **`img-src 'self' data:`** — no remote images, so nothing renders a pixel
  that reports back. This one has teeth in practice: it is why `qr.scan`
  rasterizes through a `data:` URL, because a `blob:` URL is silently blocked.

**The dev server serves a different, looser policy** — it relaxes
`script-src`/`style-src` because strict CSP breaks HMR, and widens
`connect-src` with `ws:`/`localhost` for the HMR socket. The policy quoted
above is the one in the page source that ships. That divergence is why the
production policy also rides along as `Content-Security-Policy-Report-Only`,
and why `lib/boot-diagnostics.js` reports violations as "would break in
production". Do not read a clean console in dev as a clean bill of health.

---

## The edge, and what depends on it

**A deployment of this stack is one of two shapes, and one protection on this
page exists in only one of them.** Azure Front Door is opt-in:
`enable_front_door` defaults to `false`, the dev baseline in
`terraform/cloudshell/domains.auto.tfvars` leaves it there, and only
`terraform/cloudshell/profiles/production.tfvars` — applied when someone asks
for `DEPLOY_PROFILE=production` — turns it on. The reason is cost: Front Door
Standard's base fee is a flat monthly subscription that does not fall with
traffic, and it was more than half the bill for a service moving two
hundredths of a dollar in data. That reasoning belongs in
`docs/DEPLOYMENT.md`. What belongs here is the consequence, which is that
**the sentence "the WAF rate-limits uploads" is true on the production profile
and false on the dev one**, and a reader has to know which one they are
looking at before anything below means what it says.

**The WAF is a production-profile control, and nothing takes over its job
without it.** The firewall policy holds three rate-limit rules in Prevention
mode, all per source IP per minute: `POST /pks/add` at 10, v2 `POST`/`PUT` at
5, and `/pks/v2/sendtoken` at 3. Those are edge rules, and the policy is a
child of the Front Door profile — on the dev profile it is not deployed at
all, `waf_policy_id` is `null`, and no origin-side rule replaces it. This is
the *only* protection on this page that the profile decides; see the end of
this section for two that look like they should be and are not. What remains
without it is `basilisk/security/rate_limit.py`, which is a *different*
control and a weaker one in two specific ways worth naming rather than
glossing:

- It enforces a **minimum gap** between requests, not a budget per window,
  and it is **in-process memory**. Flex Consumption runs up to
  `function_maximum_instance_count` (20) instances that share nothing and
  recycle when idle, so the effective ceiling is the configured gap divided
  across however many workers the platform happens to have warm. A limiter
  the platform can multiply by twenty is not the limiter its constant says
  it is.
- `client_ip()` reads `X-Azure-ClientIP` in preference to everything else,
  and that header is one Azure sets **at the edge**. With no edge in front,
  nothing in this repository sets it and nothing strips it, so its value is
  whatever the caller put there. That is the same defect the comment in that
  file records for `X-Client-IP` — a caller who picks their own bucket is a
  caller with no bucket. On the dev profile, treat the per-IP limiters as
  unenforced against an adversary who has read this paragraph.

Neither profile has a managed rule set or bot protection: those require Front
Door **Premium**, and this is Standard. Neither has country blocking either,
despite it being an obvious thing to assume of a WAF — no geo-match rule has
ever existed in `terraform/modules/basilisk/frontdoor.tf`.

**The origin lock fails open without an edge, deliberately.**
`basilisk/security/edge.py` refuses any request that does not carry a matching
`X-Azure-FDID` — but only when `BASILISK_AFD_ID` is set, and Terraform does
not set it at all when there is no Front Door profile to take a GUID from. It
cannot be otherwise: with no edge, every request is a direct origin hit, and a
lock that matched nothing would 403 the entire service. So on the dev profile
the Function App answers on `<name-prefix>-fn.azurewebsites.net` to anyone who
asks, which is also its public URL. The protection is not weakened; the thing
it protects against is the normal case there, and the lock is the production
profile's, not a general one.

**Two things that look profile-dependent are not.** The security headers hold
on both. Front Door's `SecurityHeaders` rule set writes CSP, HSTS,
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and
`Permissions-Policy` onto portal pages served from blob storage, which cannot
add a response header of its own — and on the dev profile Flask serves those
pages from inside the function package and sets the same six in
`basilisk/serve.py`'s `after_request`, so the policy a browser computes is the
same either way. The retired-page redirects likewise exist in both the
`frontdoor.tf` rules and `_RETIRED_PAGES` in `basilisk/portal/static.py`. It
would be easy to list these as edge protections and call them lost, and that
would overstate the difference between the profiles as badly as omitting the
WAF understates it.

What the dev profile genuinely does lose besides the WAF is the CDN: every
portal page is an origin fetch against a Function App that scales from zero,
so the first request after an idle period pays a cold start. That is a
latency fact, not a security one.

---

## Key material at rest

- **Private keys live in IndexedDB, envelope-encrypted** under a
  **non-extractable, device-bound AES-GCM key** (`lib/vault.js`). Because the
  wrapping key is non-extractable, reading the database does not yield the
  keys — an attacker needs code execution *on this origin, on this device*.
- **`localStorage` is deliberately unused for secrets.** It is string-only and
  readable by any script that achieves XSS.
- **Optional outer layers**: an OpenPGP S2K/Argon2 passphrase, or a passkey
  (WebAuthn PRF → HKDF) whose KEK wraps the device-encrypted blob. With a
  passkey, unlocking requires the authenticator, not just the device.
- **Session-only keys** (`lib/e2e-hooks.js`, agent unlock) live in memory with
  a TTL and never touch IndexedDB. Closing the tab is the erase.
- **Buffers are zeroed** after use (`fill(0)`, and `zeroKeyMaterial` for
  OpenPGP private params). This is best-effort by nature: JavaScript strings
  are immutable and the engine may have copied a value before you wiped it.
  Treat it as reducing exposure window, not as guaranteed erasure.

---

## What the peer-to-peer mesh does and does not prove

- **Signalling envelopes are sealed end to end** — audience-encrypted and
  PGP-signed — and relayed frames are the same sealed envelopes. A member who
  forwards traffic can delay or drop it, never read, forge, or replay it into
  another session.
- **RFC 8844 (unknown key-share) is designed against, not bolted on.** The
  pairwise session key binds room, both identities, the full audience, both
  nonces, and both DTLS fingerprints. Signing a bare SDP is the intuitive
  implementation and the vulnerable one; this is not that.
- **Connectivity and authentication are reported separately, everywhere.** A
  peer can be fully connected and completely unverified, and the UI never
  conflates the two — `authenticated` requires both the signed envelope and
  the transcript-bound key confirmation.
- **Not defended:** traffic analysis and metadata. A network observer learns
  that you contacted a signalling relay and STUN/TURN servers, and roughly how
  much you sent. Basilisk hides content, not the fact of communication.
- **The STUN default is refusable, and the refusal is kept.** An exchange with
  no `ice=` uses two public STUN servers (Cloudflare and Google), and a STUN
  binding request tells whoever answers it your public address. `rtc.ice
  stun=none` names the opposite choice: no server of any kind, host candidates
  only, no packet to anyone but the peer. That empty list is carried unchanged
  through `parseIceConfig`, the raw ops and the session — the substitution
  rule (`iceServersOrDefault`) fills in defaults for *absent*, never for
  *empty*. The trade is stated where the choice is made: host candidates reach
  peers on the same network and cannot cross NAT.
- **Not defended:** a malicious *participant*. Anyone you invite into a room
  is inside it. Threshold schemes limit what one participant can do; they do
  not make a hostile participant harmless.

---

## Out of scope, stated plainly

- **A compromised endpoint.** Malware, a hostile browser extension with access
  to this origin, or a physically compromised device defeats everything here.
  Extensions are the realistic one: they can read page memory.
- **A compromised or coerced server**, beyond the integrity measures above.
- **Rubber-hose / legal compulsion.** There is no duress mode and no plausible
  deniability.
- **Side channels.** WebCrypto's timing behaviour is the browser's business;
  the SSS and BLIP39 code paths are not written to be constant-time.
- **Quantum adversaries.** The primitives are classical (X25519, P-256,
  RSA, AES-GCM). No post-quantum KEM is offered today.
- **`stream.*` and other Basilisk-original formats** have not been
  independently reviewed. Where interoperability with audited tooling exists
  (age, OpenPGP, JOSE), prefer it — that is why it is there.
- **DKG, when it lands, will be experimental** and is not a substitute for an
  audited threshold-signature implementation.

---

## If you want to verify rather than trust

1. Read the CSP in the page source; compare it against the block above.
2. Check `/integrity/module-roots.json` against the SRI hashes in the HTML.
   This path has to answer on whichever component serves the portal — the
   storage account behind Front Door on the production profile, Flask out of
   the function package on the dev profile — because it is the one file on the
   site whose job is to be an independent statement about the others. If it
   does not answer, every visitor's power-on self-test reports an unreachable
   pin rather than a match, which is a refusal and not a pass. That is why
   `scripts/smoke-test.sh` compares the served pin against the built one byte
   for byte and fails the deploy when they differ or when it is missing
   entirely, rather than leaving it to a reader to notice.
3. Run the test suite — it is the same one CI runs, and the claims on this
   page are pinned by `threat-model.test.js`.
4. Run recipes headlessly with the CLI (`docs/CLI.md`), where there is no
   served-code question at all, and compare outputs against `gpg`, `age`, or
   `openssl`.
5. Load the page, then disconnect the network. Everything except keyserver
   lookups continues to work — because nothing else was ever going anywhere.
