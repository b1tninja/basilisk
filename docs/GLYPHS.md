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
| `agent` | Agent | Keyhole | The Agent toolbox and the vault shelf: a key is used inside, and never comes out. The keyhole is the mark `agent-boundary`, `agent-decrypt` and `agent-sign` already carry inside their vault wall, drawn here on its own and large — the toolbox is the keyhole, the shelf is the keyhole put behind a wall, so the two differ by a whole silhouette (round-with-a-skirt against square) rather than by a detail. It replaces a key crossed by an r=5.5 TTL arc that was unreadable at both shipping sizes: rasterised at 12px the old bow region held 3.73 of ink with one clear pixel in sixteen, against 0.36 and four for this ring. TTL is not what separates the agent from Keys — that the key stays inside is, and that is what a keyhole says. |
| `hkp` | HKP | Keyserver hub with radiating spokes | HTTP Keyserver Protocol lookup/search — a central node with compass spokes (directory + fetch). <br><small>OpenPGP HKP</small> |
| `sss` | SSS / BLIP39 | Stacked share cards | Shamir secret sharing / BLIP39 — offset stacked cards as K-of-N fragments (any threshold recovers; a single share is useless alone). <br><small>Shamir 1979; puzzle/share UX metaphor</small> |
| `webauthn` | WebAuthn | FIDO passkey (person + overlapping key) | Official passkey layout: person on the left, simplified key on the right slightly overlapping (create, prf, caps). <br><small>FIDO Alliance Passkey Icon Usage Guidelines</small> |
| `otp` | OTP | Key whose bow is a countdown dial | A TOTP secret is a key that expires. The shank is the `password` shelf glyph's, because the shared secret underneath is the same kind of thing; the bow is a dial with hands and a gap at twelve where the period has run off. Two cues rather than one on purpose — at 16px the gap alone reads as a broken circle and the hands alone read as a plain clock, and it has to stay distinct from `password` right beside it in the drawer. <br><small>RFC 6238 (TOTP)</small> |
| `jose` | JOSE | Three dot-separated segments | A compact JOSE serialization is header.payload.signature - three blocks with the separators between them, plus the signature spark (jose.sign, jose.verify). <br><small>RFC 7515 - JSON Web Signature</small> |
| `webrtc` | WebRTC | A span carrying two ends | A connection is a span the two ends stand on: an arch between two solid footings. Not a wire — ICE builds the route, it is not handed one. Distinct from ports (two sockets bridged, the ICE/STUN shelf) because the mass sits in the footings rather than the band. <br><small>W3C WebRTC 1.0</small> |
| `quorum` | Quorum | Three nodes closed into a mesh | Built from webrtc's own vocabulary — the same solid endpoint nodes — with one more node and the span closed into a ring. That is exactly what the layer adds: WebRTC connects two ends, quorum meshes an audience. Also the Exchange shelf's mark, so a toolbox whose first shelf is its lifecycle reads as one thing. <br><small>WEBRTC-TOOLBOX.md §8</small> |

## Shelves

| Id | Label | Metaphor | Description |
|----|-------|----------|-------------|
| `agent-boundary` | Boundary | Vault wall with a keyhole inside it | The wall is the subject: a rounded vault outline with the keyhole centred inside, for ops that use a key without letting it out (agent.sign, agent.decrypt). |
| `ssh-key` | Keys & wire | Key whose shank trails into three linked blocks | The RFC 4253 blob is literally a chain of length-prefixed fields — a key head trailing chained blocks reads as 'wire format' at 20px (ssh.encode, ssh.decode, ssh.fingerprint). |
| `keys` | Keys | Key, bow hollow, teeth up the shank | WebCrypto key material — genkey, export, import; the base drawing for `genkey`, `gpg-genkey` and `passphrase`. The bow is a plain ring rather than the old outlined silhouette with an r=1 hole punched in it: at 12px that hole filled solid, and the silhouette's closing chord ran straight through the bow, so the whole thing read as a diagonal lozenge. Measured in a 4x4 window on the bow centre at 12px the old drawing carried 1.89 of ink, where `key-public` carries 0 and the deliberately filled `key-secret` carries 4 — it sat halfway into the range the sensitivity split reserves. This one measures 0, four clear pixels of four, the same as `key-public`. It runs bow-low to teeth-high so it cannot be read as `inspect`'s magnifier, whose handle falls the other way, and stays off the horizontal axis `password` and the `key-*` kind badges use. |
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
| `jose-jwe` | JWE envelope | Token whose middle segment is filled | A JWE carries an encrypted payload rather than a signed one, so it is the `jose` token with the payload segment blacked out — the part you cannot read. Segment ink at 12px is 5.89 against `jose`'s 2.58, a 2.28x difference. It was an envelope with a lock shackle, which at badge size was the same silhouette as `pubkey` and `openpgp`; staying inside the JOSE token family says more, and says it at 12px. <br><small>RFC 7516 - JSON Web Encryption</small> |
| `peer` | Peer & signaling | Offer and answer facing each other | Two solid wedges pointed at one another across a gap — the offer and the answer, not yet met. Signalling is exactly the part where the two halves are addressed to each other and have not arrived (quorum.offer/join/close, rtc.offer/answer/state/restart). <br><small>RFC 8829 (JSEP)</small> |
| `channel` | Data channel | Two arrows, opposite directions | An RTCDataChannel is bidirectional and both directions are the users job: an up arrow and a down arrow side by side (quorum.send, quorum.recv, peer.send, peer.recv, rtc.stats). Vertical on purpose — the horizontal band belongs to ports. <br><small>W3C WebRTC 1.0 §6 RTCDataChannel</small> |

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
| `key-openpgp` | OpenPGP key | A key whose shank branches into a second key | The `openpgp-key` type - what `gpg.genkey`, `hkp.get` and the agent hand back. It has to be a key and it has to not be `key-public`/`key-secret`, which is what an SSH key already draws, so the difference is a whole arm rather than a detail: a filled bow at the top left, a shank running right with its bit, and a spine dropping to a second shank with a bit of its own. Subkeys are what the type's own doc names as the thing an OpenPGP key has and a CryptoKey has no room for, so that is what the drawing says - not ASCII armour, which the doc explicitly says this type is not (`the packet structure of RFC 9580, not the armored text around it`). Rasterised at 12px it stands 28.3 from `ssh` and 35.7 from `key-secret` in per-pixel L1, against the 6.2 that separates `key-public` from `key-secret` - the pair this repo already ships as unmistakable at that size. The bow is filled, on the same asymmetry `key` is: an OpenPGP key is public or private and the type cannot know which, so the glyph it is likeliest to be mistaken for should be the secret one. Not in KEY_GLYPH_TIERS, because no artifact role wears it - an OpenPGP key whose half is known arrives as `openpgp-public` or `openpgp-private` and draws `key-public`/`key-secret` there. <br><small>RFC 9580 - OpenPGP</small> |

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
| `genkey` | Generate key | Key with a plus | WebCrypto genkey — the `keys` key with a plus in the free lower-right quadrant, the same 'and one more' mark `agent-list` and `wa-get` use. The old spark rays were three 1.2-unit ticks, 0.7px of noise at 12px beside a bow that had already filled in. |
| `export` | Export | Arrow up out of tray | Export key material — upload arrow from tray. |
| `import` | Import | Arrow down into tray | Import key material — download arrow into tray. |
| `random` | Random | Dice / bit cells | CSPRNG random bytes — irregular bit cells. |
| `input` | Input | Panel with an arrow entering | Runtime input — content panel pushed right, with a full arrow (shaft and head) crossing its left edge. The old inbound mark was a bare 4-unit rail, which left `input` and `out` differing by which side a nub sat on. |
| `out` | Out | Panel with an arrow leaving | Emit / slot out — the conjugate of `input`: panel pushed left, full arrow leaving the right edge. Direction is carried by an arrowhead that survives 12px, not by the side a rail sits on. |
| `passphrase` | Passphrase | Key over a baseline | Passphrase source (io / ports) — the `keys` key, lifted and shortened, over a full-width text baseline: a secret that is typed. The old drawing's bow was an open arc that never closed, so it read as a hook over a line; this bow measures 0.11 of ink in the 4x4 bow window at 12px against the old 2.79, four clear pixels against none. |
| `clipboard` | Clipboard | Clipboard with clip | Clipboard source/sink - board with binder clip (clipboard.read, clipboard.write). |
| `file-read` | File read | Document with outbound arrow | file.read - a document on disk feeding the pipeline; the arrow leaves the page because bytes flow out of the file. |
| `file-save` | File save | Document with downward arrow | file.save - the pipeline value coming to rest on disk; down is the universal save direction. |
| `stream` | Chunked AEAD | Three sealed blocks in a row | stream.seal / stream.open - a file split into independently-tagged chunks, each with its own shackle, which is exactly what the STREAM construction does. |
| `age-key` | age identity | Key | age.keygen / age.recipient - an X25519 identity and the recipient derived from it. |
| `age-lock` | age file | Padlock | age.encrypt / age.decrypt - a padlocked age-encryption.org/v1 file. |
| `qr` | QR | QR finder squares | QR code sink — three finder patterns plus modules. |
| `inspect` | Inspect | Magnifier | Inspect / dump — a plain magnifier, lens enlarged to r=5 and the crosshair dropped. The cross was the detail that made this and `hkp-search` the same drawing described twice; the magnifier stays here because inspect is the generic 'look at this', and `hkp-search` now says what it looks through. |
| `peek` | Peek | Eye | Peek side snapshot — eye outline. |
| `text-sink` | Text sink | T falling to a floor | text / print sink — a typographic T whose stem carries an arrowhead down onto a floor line. The old outbound tick was a 2-unit stroke invisible at 12px, which left this and the `text` encoding glyph as the same drawing; the arrow and the floor are a silhouette apart from it. |
| `foreach` | Foreach | Mapped tiles | foreach — three tiles suggesting map-over-items. |
| `tee` | Tee | T junction forks | tee — stem with left/right branch forks. |
| `in` | In | Arrow into slot rail | in @slot — arrow into a vertical slot rail. |
| `as` | As | Cast chevron A | as cast — A-shaped chevron over a baseline. |
| `select` | Select | Document with fold | select / .public — folded document page. |
| `at` | At | @ spiral | at / [n] index — @-like spiral. |
| `gpg-encrypt` | OpenPGP encrypt | Padlock, body filled | gpg.encrypt — a padlock whose body is solid, because what it produces is opaque. Filled rather than a finer mark: `age-lock` is already a closed hollow padlock on age.encrypt, and at 12px this carries 41.6 of ink against its 28.3, a 1.47x difference no detail at this size could match. Its conjugate `gpg-decrypt` is the same body hollow with the shackle open, so the pair reads as one act in two directions. |
| `gpg-sign` | OpenPGP sign | Quill stroke | gpg.sign / gpg.verify — pen tip stroke. |
| `gpg-genkey` | OpenPGP genkey | Key with an armour bar | gpg.genkey — the `keys` key under a single bold armour bar, top left, where the key leaves the box empty. One 6-unit rule rather than the old 4x1.5 block, which at 12px was a 2.4x0.9px nub. Position as well as shape separates it from `genkey`: bar high left against plus low right. |
| `gpg-inspect` | OpenPGP inspect | Message with magnifier | gpg.inspect — message panel with lens. |
| `gpg-sym` | OpenPGP symmetric | Password key under panel | gpg.symencrypt / gpg.symdecrypt — passphrase key under a panel. |
| `blip39` | BLIP39 | Mnemonic word rows | blip39 — stacked word rows for share mnemonics. |
| `shares` | Shares | Offset share cards | shares input — stacked offset cards. |
| `agent-list` | Agent list | List with plus | agent.list — list lines with a plus mark. |
| `agent-save` | Agent save | Diskette / save card | agent.save — save card with top flap. |
| `hkp-search` | HKP search | Directory lines under a lens | hkp.search — a keyserver listing with a lens over it. Searching a directory is not the same act as inspecting a value, and drawing the directory is what separates it from `inspect`: two full-width rules give it a rectangular mass at the top that a bare magnifier has nowhere, 25.2 of ink at 12px against 19.1. |
| `hkp-get` | HKP get | Download arrow | hkp.get — arrow down to baseline. |
| `hkp-filter` | HKP filter | Funnel | hkp.filter — funnel / filter shape. |
| `hkp-cache` | HKP cache | Folder | hkp.cache — a folder, not a panel. Its old drawing was a bordered panel with a small tab, one of four panels in the drawer separated by a unit or two of interior mark; the folder's stepped top edge is a silhouette difference instead. |
| `hkdf` | HKDF | Extract box then expand | hkdf — extract rectangle feeding an expand fan. |
| `pbkdf2` | PBKDF2 | Passphrase into KDF box | pbkdf2 — password key under an extract panel. |
| `wa-create` | WebAuthn create | Passkey with key | webauthn.create — person plus overlapping key. |
| `wa-get` | WebAuthn get | Passkey with download | webauthn.get — person plus downward arrow. |
| `wa-prf` | WebAuthn PRF | Passkey with hash bars | webauthn.prf — person plus digest bars. |
| `wa-caps` | WebAuthn caps | Passkey with check | webauthn.caps — person plus readiness check. |
| `wa-attest` | WebAuthn attest | Shield with check | webauthn.attest — attestation shield. |
| `wa-mds` | WebAuthn MDS | Directory document | webauthn.mds — MDS document with lens. |
| `jose-decode` | Decode token | Segments under a lens | Reading a token without verifying it - the three segments with an inspection lens, deliberately not the signature spark (jose.decode). <br><small>RFC 7519 - JSON Web Token</small> |
| `gpg-decrypt` | OpenPGP decrypt | Padlock, open, body hollow | gpg.decrypt — the conjugate of `gpg-encrypt`: same square body, hollow, shackle swung open. The shackle hinges on the right and opens left, the mirror of `unlock`, which is the only other open padlock the drawer renders; the square body keeps both off `lock` / `age-lock`, which are round-cornered. |
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
