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
- **A published Merkle root over those hashes.** `scripts/write-module-integrity-pin.mjs`
  writes `/integrity/module-roots.json` and injects pin `<meta>` tags, so the
  running page can cross-check the code it loaded against an independently
  cacheable pin document — optionally mirrored on other origins, so subverting
  one host is not enough.
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
3. Run the test suite — it is the same one CI runs, and the claims on this
   page are pinned by `threat-model.test.js`.
4. Run recipes headlessly with the CLI (`docs/CLI.md`), where there is no
   served-code question at all, and compare outputs against `gpg`, `age`, or
   `openssl`.
5. Load the page, then disconnect the network. Everything except keyserver
   lookups continues to work — because nothing else was ever going anywhere.
