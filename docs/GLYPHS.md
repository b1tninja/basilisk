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
| `age` | age | Document with a lock shackle | age encrypts files, not messages — a page with a folded corner and a shackle, distinguishing it from OpenPGP's envelope (age.keygen, age.encrypt, …). <br><small>age-encryption.org/v1</small> |
| `ssh` | SSH | Terminal prompt chevron with a key on the baseline | The shell's key — a prompt chevron with a horizontal key lying to its right. No window chrome, distinguishing it from WebCrypto's browser-plus-key (ssh.encode, ssh.sign, …). <br><small>PROTOCOL.sshsig; draft-miller-ssh-agent</small> |
| `encoding` | Encoding | Bidirectional transform arrows | Bytes ↔ text transforms (pem, base64, hex, …) — folded rails with encode/decode arrowheads. |
| `io` | Input / output | Panel with header and body | Runtime ports and tiles (input, out, random, qr) — a simple content panel. |
| `flow` | Flow | Branching corner forks | Pipeline control (foreach, tee, in, as) — two L-shaped forks suggesting stem/branch flow. |
| `agent` | Agent | Vault key with TTL arc | My Keys vault agent (unlock, save, list) — classic key plus a circular timer/TTL arc, distinct from bare Keys. |
| `hkp` | HKP | Keyserver hub with radiating spokes | HTTP Keyserver Protocol lookup/search — a central node with compass spokes (directory + fetch). <br><small>OpenPGP HKP</small> |
| `sss` | SSS / BLIP39 | Stacked share cards | Shamir secret sharing / BLIP39 — offset stacked cards as K-of-N fragments (any threshold recovers; a single share is useless alone). <br><small>Shamir 1979; puzzle/share UX metaphor</small> |
| `webauthn` | WebAuthn | FIDO passkey (person + overlapping key) | Official passkey layout: person on the left, simplified key on the right slightly overlapping (create, prf, caps). <br><small>FIDO Alliance Passkey Icon Usage Guidelines</small> |
| `otp` | OTP | Key whose bow is a countdown dial | A TOTP secret is a key that expires. The shank is the `password` shelf glyph's, because the shared secret underneath is the same kind of thing; the bow is a dial with hands and a gap at twelve where the period has run off. Two cues rather than one on purpose — at 16px the gap alone reads as a broken circle and the hands alone read as a plain clock, and it has to stay distinct from `password` right beside it in the drawer. <br><small>RFC 6238 (TOTP)</small> |
| `jose` | JOSE | Three dot-separated segments | A compact JOSE serialization is header.payload.signature - three blocks with the separators between them, plus the signature spark (jose.sign, jose.verify). <br><small>RFC 7515 - JSON Web Signature</small> |

## Shelves

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `agent-boundary` | Boundary | Vault wall with a keyhole inside it | The wall is the subject: a rounded vault outline with the keyhole centred inside, for ops that use a key without letting it out (agent.sign, agent.decrypt). |
| `ssh-key` | Keys & wire | Key whose shank trails into three linked blocks | The RFC 4253 blob is literally a chain of length-prefixed fields — a key head trailing chained blocks reads as 'wire format' at 20px (ssh.encode, ssh.decode, ssh.fingerprint). |
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
| `binary` | Binary | Four bit cells | Binary encodings shelf — a 2×2 bit grid (fallback when a tool has no dedicated glyph). |
| `text` | Text | Typography “T” | Text encodings (utf8) — a capital T with baseline marks. |
| `ports` | Ports | Two linked ports | I/O ports — two sockets with a bridge (input/out/random). |
| `file` | Files | Document with a folded corner | Whole-file operations (age.encrypt, stream.seal) — a page rather than the AEAD shield, because these produce a framed file with many tags, not one message with one. |
| `control` | Control | Flow graph nodes | Flow control shelf — three nodes linked by a U-shaped bus. |
| `essentials` | Essentials | Passkey person with check | WebAuthn essentials (caps, create, prf) — passkey person plus a readiness checkmark. <br><small>FIDO passkey</small> |
| `attestation` | Attestation / MDS | Shield with check | Soft attestation / FIDO MDS — shield containing a checkmark. |
| `directory` | Directory | People / contacts | HKP directory search — two contact silhouettes (alias of recipients). |
| `recipients` | Recipients | People / contacts | Recipients list / merge — two contact silhouettes. |
| `jose-jwe` | JWE envelope | Sealed envelope | A JWE carries an encrypted payload rather than a signed one - the envelope glyph with a lock shackle (jose.encrypt, jose.decrypt). <br><small>RFC 7516 - JSON Web Encryption</small> |

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

## kind

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `key-public` | Public key | Key with an open bow | The unmarked member of the sensitivity pair: an ordinary key, bow hollow. You can see through it, because there is nothing in it to hide. Identical to key-secret in every other respect - same bow radius, same shank, same two bits - so the one thing that differs is the one thing that matters. <br><small>WCAG 2.1 SC 1.4.1 Use of Colour</small> |
| `key-secret` | Secret key | Key with a filled bow | The same key as key-public with its bow filled in: solid, opaque, something inside. Fill rather than a second mark because the badge renders at 12-16px, where a gap, a dot or an extra tooth all close up - at 12px a rasterised disc against a rasterised ring is still unmistakable, which no finer cue survives. This is the shape channel that carries the sensitivity split beside the badge tint, so a reader who cannot separate the two hues still can. <br><small>WCAG 2.1 SC 1.4.1 Use of Colour</small> |
| `key-pair` | Keypair | Two bows on one shank, one filled and one hollow | Both halves on a single key: the filled bow is the secret one, the hollow bow the public one. It reads on the secret side of the split because a filled bow is present, which is the honest claim - a keypair holds secret material even though its identity is showable. <br><small>WCAG 2.1 SC 1.4.1 Use of Colour</small> |

## op

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `agent-decrypt` | agent.decrypt | Vault wall with two text lines emerging | Plaintext out, wall closed. Distinct from gpg-decrypt's open shackle: nothing here opens. |
| `agent-sign` | agent.sign | Vault wall with a quill stroke emerging through a gap | The signature leaves, the key does not — the vault outline opens on the right just far enough for the sign quill to pass through. |
| `sshsig-sign` | sshsig | Quill stroke with a prompt chevron tucked lower-left | The established signature quill, marked as the shell's — sshsig format, what ssh-keygen -Y and git SSH signing produce (ssh.sign, ssh.verify). |

## tool

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `hex` | Hex | Hexagon with crosshair | `to hex` / `from hex` — hexagon (hex) with a center cross (byte grid). |
| `base64` | Base64 | Stacked encoded rows with 64 marks | Base64 / Base64url — two full code rows and a truncated third with twin hash marks. |
| `base32` | Base32 | Stacked rows with downward chevron | Base32 — three encoding rows with a small expand chevron (5-bit alphabet). |
| `pem` | PEM | Armored document | PEM / DER armor — framed document with BEGIN/END-style text lines. |
| `genkey` | Generate key | Key with spark rays | WebCrypto genkey — classic key with creation rays. |
| `export` | Export | Arrow up out of tray | Export key material — upload arrow from tray. |
| `import` | Import | Arrow down into tray | Import key material — download arrow into tray. |
| `random` | Random | Dice / bit cells | CSPRNG random bytes — irregular bit cells. |
| `input` | Input | Panel with inbound rail | Runtime input — content panel with left inbound mark. |
| `out` | Out | Panel with outbound rail | Emit / slot out — content panel with right outbound mark. |
| `passphrase` | Passphrase | Key over baseline | Passphrase source — key above a text baseline. |
| `clipboard` | Clipboard | Clipboard with clip | Clipboard source/sink - board with binder clip (clipboard.read, clipboard.write). |
| `file-read` | File read | Document with outbound arrow | file.read - a document on disk feeding the pipeline; the arrow leaves the page because bytes flow out of the file. |
| `file-save` | File save | Document with downward arrow | file.save - the pipeline value coming to rest on disk; down is the universal save direction. |
| `stream` | Chunked AEAD | Three sealed blocks in a row | stream.seal / stream.open - a file split into independently-tagged chunks, each with its own shackle, which is exactly what the STREAM construction does. |
| `age-key` | age identity | Key | age.keygen / age.recipient - an X25519 identity and the recipient derived from it. |
| `age-lock` | age file | Padlock | age.encrypt / age.decrypt - a padlocked age-encryption.org/v1 file. |
| `qr` | QR | QR finder squares | QR code sink — three finder patterns plus modules. |
| `inspect` | Inspect | Magnifier with crosshair | Inspect / dump — magnifying glass with focus cross. |
| `peek` | Peek | Eye | Peek side snapshot — eye outline. |
| `text-sink` | Text sink | T with outbound mark | text / print sink — typography T with outbound tick. |
| `foreach` | Foreach | Mapped tiles | foreach — three tiles suggesting map-over-items. |
| `tee` | Tee | T junction forks | tee — stem with left/right branch forks. |
| `in` | In | Arrow into slot rail | in @slot — arrow into a vertical slot rail. |
| `as` | As | Cast chevron A | as cast — A-shaped chevron over a baseline. |
| `select` | Select | Document with fold | select / .public — folded document page. |
| `at` | At | @ spiral | at / [n] index — @-like spiral. |
| `gpg-encrypt` | OpenPGP encrypt | Locked envelope | gpg.encrypt / gpg.decrypt — flap envelope with lock. |
| `gpg-sign` | OpenPGP sign | Quill stroke | gpg.sign / gpg.verify — pen tip stroke. |
| `gpg-genkey` | OpenPGP genkey | Key with OpenPGP bar | gpg.genkey — key plus a small header bar. |
| `gpg-inspect` | OpenPGP inspect | Message with magnifier | gpg.inspect — message panel with lens. |
| `gpg-sym` | OpenPGP symmetric | Password key under panel | gpg.symencrypt / gpg.symdecrypt — passphrase key under a panel. |
| `blip39` | BLIP39 | Mnemonic word rows | blip39 — stacked word rows for share mnemonics. |
| `shares` | Shares | Offset share cards | shares input — stacked offset cards. |
| `agent-list` | Agent list | List with plus | agent.list — list lines with a plus mark. |
| `agent-save` | Agent save | Diskette / save card | agent.save — save card with top flap. |
| `hkp-search` | HKP search | Magnifier with plus | hkp.search — lens with focus cross. |
| `hkp-get` | HKP get | Download arrow | hkp.get — arrow down to baseline. |
| `hkp-filter` | HKP filter | Funnel | hkp.filter — funnel / filter shape. |
| `hkp-cache` | HKP cache | Drawer stack | hkp.cache — stacked cache drawers. |
| `hkdf` | HKDF | Extract box then expand | hkdf — extract rectangle feeding an expand fan. |
| `pbkdf2` | PBKDF2 | Passphrase into KDF box | pbkdf2 — password key under an extract panel. |
| `wa-create` | WebAuthn create | Passkey with key | webauthn.create — person plus overlapping key. |
| `wa-get` | WebAuthn get | Passkey with download | webauthn.get — person plus downward arrow. |
| `wa-prf` | WebAuthn PRF | Passkey with hash bars | webauthn.prf — person plus digest bars. |
| `wa-caps` | WebAuthn caps | Passkey with check | webauthn.caps — person plus readiness check. |
| `wa-attest` | WebAuthn attest | Shield with check | webauthn.attest — attestation shield. |
| `wa-mds` | WebAuthn MDS | Directory document | webauthn.mds — MDS document with lens. |
| `jose-decode` | Decode token | Segments under a lens | Reading a token without verifying it - the three segments with an inspection lens, deliberately not the signature spark (jose.decode). <br><small>RFC 7519 - JSON Web Token</small> |
| `gpg-decrypt` | OpenPGP decrypt | Envelope, shackle open | The conjugate of gpg-encrypt - same envelope, padlock open, so the two directions are distinguishable at a glance. |
| `encode` | Encode | Double chevron right | Forward direction of a conjugate pair - encode, wrap, sign. |
| `decode` | Decode | Double chevron left | Reverse direction of a conjugate pair - decode, unwrap, verify. Mirrors encode exactly so direction reads without labels. |

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
