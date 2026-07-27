# Toolkit glyphs

Stroke SVG icons for the ops drawer (toolboxes, shelves) and toolkit chrome.
Assets live under `web/glyphs/`; `web/src/lib/toolkit/glyphs.js` is **generated
at build time** by `npm run glyphs` (`scripts/build-glyphs.mjs`).

| | |
|---|---|
| Manifest | `web/glyphs/manifest.json` |
| SVG assets | `web/glyphs/svg/<id>.svg` |
| Generated module | `web/src/lib/toolkit/glyphs.js` |
| View box | `0 0 20 20` |
| Stroke | `currentColor`, width `1.6`, round caps/joins |

**Conventions:** single-color line icons, recognizable without a caption where
possible. Prefer established crypto UI metaphors (ModernPGP locked envelope,
FIDO passkey person+key, Shamir share fragments) over abstract decoration.

Rebuild after editing an SVG or the manifest:

```bash
cd web && npm run glyphs
```

`predev` / `prebuild` / `pretest` run the same step automatically.

---

## Toolboxes

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `webcrypto` | WebCrypto | Browser window with key | SubtleCrypto lives in the browser — a chrome window with a small key signals Web API crypto (genkey, digest, AEAD, KDF, …). <br><small>W3C Web Cryptography API</small> |
| `openpgp` | OpenPGP | Locked envelope | ModernPGP convention for encrypted mail/messages — flap envelope with lock-shackle (gpg.encrypt, gpg.sign, …). <br><small>ModernPGP icons</small> |
| `encoding` | Encoding | Bidirectional transform arrows | Bytes ↔ text transforms (pem, base64, hex, …) — folded rails with encode/decode arrowheads. |
| `io` | Input / output | Panel with header and body | Runtime ports and tiles (input, out, random, qr) — a simple content panel. |
| `flow` | Flow | Branching corner forks | Pipeline control (foreach, tee, in, as) — two L-shaped forks suggesting stem/branch flow. |
| `agent` | Agent | Vault key with TTL arc | My Keys vault agent (unlock, save, list) — classic key plus a circular timer/TTL arc, distinct from bare Keys. |
| `hkp` | HKP | Keyserver hub with radiating spokes | HTTP Keyserver Protocol lookup/search — a central node with compass spokes (directory + fetch). <br><small>OpenPGP HKP</small> |
| `sss` | SSS / BLIP39 | Stacked share cards | Shamir secret sharing / BLIP39 — offset stacked cards as K-of-N fragments (any threshold recovers; a single share is useless alone). <br><small>Shamir 1979; puzzle/share UX metaphor</small> |
| `webauthn` | WebAuthn | FIDO passkey (person + overlapping key) | Official passkey layout: person on the left, simplified key on the right slightly overlapping (create, prf, caps). <br><small>FIDO Alliance Passkey Icon Usage Guidelines</small> |

## Shelves

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `keys` | Keys | Key | WebCrypto key material — genkey, export, import. |
| `digest` | Digest | Input lines collapsing into hash bars | Cryptographic hash — long input lines beside a “#”-like pair of bars (digest). |
| `sign` | Sign | Quill / pen stroke | Digital signature — a pen tip stroke (WebCrypto sign/verify or OpenPGP gpgsign shelf). |
| `aead` | AEAD | Shield | Authenticated encryption (AES-GCM) — protective shield. |
| `cipher` | Cipher | Swapped block grid | Unauthenticated block/stream ciphers (AES-CBC/CTR) — four cells with a swap diagonal (not an “eye”). |
| `rsa` | RSA | Certificate document with key | RSA-OAEP / PKCS1 ops — document lines plus a small key. |
| `kdf` | KDF | Extract funnel → expand fan | HKDF/PBKDF2 — narrow extract phase then widen expand (RFC 5869 extract-then-expand). <br><small>RFC 5869 HKDF</small> |
| `agreement` | Agreement | Two keys joining | ECDH / X25519 — two key heads meeting at a shared vertical (shared secret). |
| `wrap` | Wrap | Package / parcel | Key wrap / unwrap — 3D parcel with ribbon crease. |
| `pubkey` | Public key | Envelope with person mark | OpenPGP public-key ops (genkey, encrypt, inspect) — message envelope under a head. |
| `password` | Password | Key with bit shank | Symmetric OpenPGP password/SKESK shelf — key bow and bit. |
| `split` | Split | Diverging bolts | SSS split / BLIP39 encode — energy splitting into branches. |
| `recover` | Combine | Waveform converging with refresh | SSS combine — signal converging toward recovery, with a small refresh corner. |
| `binary` | Binary | Four bit cells | Binary encodings (pem, base64, hex, …) — a 2×2 bit grid. |
| `text` | Text | Typography “T” | Text encodings (utf8) — a capital T with baseline marks. |
| `ports` | Ports | Two linked ports | I/O ports — two sockets with a bridge (input/out/random). |
| `control` | Control | Flow graph nodes | Flow control shelf — three nodes linked by a U-shaped bus. |
| `essentials` | Essentials | Passkey person with check | WebAuthn essentials (caps, create, prf) — passkey person plus a readiness checkmark. <br><small>FIDO passkey</small> |
| `attestation` | Attestation / MDS | Shield with check | Soft attestation / FIDO MDS — shield containing a checkmark. |
| `directory` | Directory | People / contacts | HKP directory search — two contact silhouettes (alias of recipients). |
| `recipients` | Recipients | People / contacts | Recipients list / merge — two contact silhouettes. |

## Toolbar / kernel

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `variables` | Variables / slots | Slot grid with plus | Kernel @slots chip — three cells and a plus for binding live values. |
| `gear` | Preferences | Gear / cog | Settings / preferences control. |
| `more` | More | Three dots | Overflow / more menu. |
| `shortcuts` | Keyboard shortcuts | Keyboard | Keyboard shortcuts help — simple keyboard outline with keys. |

## Keyring actions

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `fingerprint` | Fingerprint | Fingerprint ridges | OpenPGP key fingerprint — ridge arcs (ModernPGP fingerprint icon). <br><small>ModernPGP fingerprint</small> |
| `unlock` | Unlock | Open padlock | Unlock vault key into session — shackle open. <br><small>ModernPGP open lock</small> |
| `lock` | Lock | Closed padlock | Lock / clear session material — shackle closed. <br><small>ModernPGP closed lock</small> |

## Asset format

Each `web/glyphs/svg/<id>.svg` is a complete icon:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="none"
     stroke="currentColor" stroke-width="1.6"
     stroke-linecap="round" stroke-linejoin="round">
  <!-- geometry -->
</svg>
```

The builder strips the root `<svg>` and embeds the inner markup into
`GLYPH_PATHS[id]`. Runtime `glyphHtml(id)` wraps that fragment with the
shared attributes used in the toolkit UI.

See also [CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md) (toolbox taxonomy) and
`registry.js` `TOOLBOX_META` / `SHELF_META` `glyph` keys.
