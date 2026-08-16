# Cryptography modules

Client-side cryptography inventory for the Basilisk portal (`web/`). Use this to track what is implemented today and what remains for a complete **WebCrypto toolkit** (CyberChef-style pipelines over `SubtleCrypto`).

Server-side OpenPGP **parsing/policy** (`basilisk/openpgp/`) is out of scope here — it validates and stores keys; it does not run user recipes.

---

## Stack overview

| Layer | Role | Primary paths |
|-------|------|----------------|
| **OpenPGP.js** | Message encrypt / sign / decrypt; Curve25519 keygen; Argon2 S2K (WASM) | `web/src/lib/pgp/`, `crypto-worker.js` |
| **WebCrypto** | Vault KEK, notebook session keys, toolkit keygen/import/export, digests, PBKDF2/HKDF internally | `vault.js`, `notebook/crypto.js`, `toolkit/engine.js` |
| **Custom** | GF(256) Shamir SSS, BLIP39 mnemonics, EFF diceware | `slip39/`, `passphrase-gen.js` |

### Toolkit toolboxes

Every recipe step declares a `toolbox` in `registry.js`. The ops drawer is a Swiss-army layout: toolboxes (with SVG glyphs) → taxonomy **shelves** → **collections** (AES modes, RSA paddings, Base64/Base32 with Encrypt|Decrypt or Encode|Decode actions) → **conjugate rows**. Badges on builder/suggest chips keep similar verbs distinct. Shelves, collections, and conjugates are UX-only — recipe tokens are unchanged. Glyph metaphors, exported SVG assets, and the build-time `glyphs.js` pipeline are documented in [GLYPHS.md](./GLYPHS.md).

Drawer order: WebCrypto → Encoding → I/O → Flow → OpenPGP → SSS → WebAuthn.

| Toolbox | Shelves | Examples |
|---------|---------|----------|
| `webcrypto` | Keys · Digest · Sign · AEAD · Cipher · RSA · KDF · Agreement · Wrap | `genkey`, `digest`, `sign`/`verify`, `aes-gcm`/`-d`, `hkdf`, `ecdh`, `wrap`/`unwrap` (AES-KW / AES content / RSA-OAEP) |
| `encoding` | Binary · Text | `pem`/`-d`, `base64`/`-d`, `base64url`/`-d`, `base32`/`-d`, `hex`/`-d`, `utf8` |
| `io` | Ports | `input`/`out`, `random`, `qr` |
| `flow` | Control | `foreach`, `tee`, `in`, `as` (see [RECIPE.md](./RECIPE.md)) |
| `openpgp` | Public key · Sign · Password | `gpg.genkey`, `gpg.inspect`, `gpg.encrypt`/`decrypt` (`-s` sign+encrypt), `gpg.sign`/`verify`, `gpg.symencrypt`/`symdecrypt` |
| `sss` | Split · Combine | `sss.split`, `blip39`/`-d`, `sss.combine` |
| `webauthn` | Essentials · Attestation/MDS | `webauthn.caps`, `webauthn.create`, `webauthn.prf`, `webauthn.attest`, `webauthn.mds` |

Cipher (unauthenticated AES) and Wrap shelves default collapsed; WebAuthn toolbox + Attestation shelf start collapsed.

**Naming:** OpenPGP / SSS / WebAuthn use dotted namespaces (`gpg.*`, `sss.*`, `webauthn.*`). WebCrypto ciphers use hyphenated OpenSSL-style names (`aes-gcm`); OpenSSL-sized (`aes-256-gcm`) and JCE (`AES/GCM/NoPadding`) forms parse to the same op. WebCrypto keeps bare `sign`/`verify`; OpenPGP signatures are only `gpg.sign`/`gpg.verify`.

Product split (intentional today):

- **Encrypt / Decrypt pages** — OpenPGP messaging for humans
- **Toolkit** — notebook of recipe cells (blank-line chains) with a session kernel for `$slots`; keygen, encoding, SSS/BLIP39, OpenPGP encrypt *sinks* (see [RECIPE.md](./RECIPE.md#notebook-execution-toolkit-ui))
- **Shared notebook** — ephemeral P-256 ECDH → HKDF → AES-GCM session crypto over WebRTC

---

## Status legend

| Status | Meaning |
|--------|---------|
| **Done** | Shipped and used in production UI/worker paths |
| **Internal** | Implemented but not exposed as a toolkit recipe step |
| **Partial** | Key material or API exists; op / mode incomplete |
| **Todo** | Desired for a complete WebCrypto toolkit; not implemented |

---

## Module inventory

### OpenPGP (`web/src/lib/pgp/`)

| Module | Status | Notes |
|--------|--------|-------|
| `encrypt.js` | Done | Profiles → OpenPGP.js config; `encryptArtifacts()` |
| `encrypt-intent.js` | Done | Human-readable profile / intent strings |
| `algos.js` | Done | Display maps (PK, symmetric, AEAD, hash, compression, S2K) |
| `capabilities.js` | Done | SEIPDv2 feature bit / modern vs legacy recipients |
| `preferences.js` | Done | Preferred algos from key self-sig |
| `armor.js` / `inspect.js` / `identity.js` | Done | Armor split, packet inspect, key IDs |
| `intended-recipient.js` | **Parsed, not enforced** | Reads Intended Recipient Fingerprint (subpacket 35). `crypto-worker.js` extracts the fingerprints onto each signature status and **nothing reads them**; `checkIntendedRecipient()` — the comparison that would detect surreptitious forwarding (RFC 9580 §13.12) — has no caller. Do not read this row as a defence that is in force. |
| `notations.js` / `deprecation.js` | Done | Notation data; RFC 9580 deprecation *warnings* |
| `memory.js` | Done | `zeroKeyMaterial()` wipe of OpenPGP `privateParams` |
| `passphrase.js` | Done | Soft strength estimate (not a KDF) |
| Padding packets (RFC 9580 tag 21) | Todo | Explicitly skipped in `encrypt.js` comments |

**Encrypt profiles**

| Profile | Symmetric | AEAD | S2K | Compression |
|---------|-----------|------|-----|-------------|
| Compatible | AES-256 | off (SEIPDv1) | iterated | uncompressed |
| Modern / Auto | AES-256 | OCB (SEIPDv2) | Argon2 | uncompressed |
| Custom UI | AES-128/192/256 | off \| ocb \| gcm \| eax | argon2 \| iterated | off \| zlib \| zip |

**OpenPGP keygen (My Keys):** ECC Curve25519 only (`type: "ecc"`, `curve: "curve25519"`), optional S2K passphrase, optional expiration.

### Vault (`web/src/lib/vault.js`)

| Capability | Status | Notes |
|------------|--------|-------|
| Device KEK | Done | Non-extractable AES-GCM-256 in IndexedDB (`basilisk-vault` schema v3) |
| Passphrase wrap | Done | OpenPGP S2K / Argon2 on armored key |
| Passkey wrap | Done | WebAuthn PRF → HKDF-SHA-256 → AES-GCM |
| Passkey attestation / MDS | Done | Soft only: `attestation: "direct"` at PRF create; AAGUID lookup via same-origin `/api/v1/mds/blob` (cached MDS3 JWT). **MDS verified / unverified** badge + device-label prefill; **does not block** enroll/unlock; not a CAST |
| Protection modes | Done | `device` \| `passphrase` \| `passkey` |
| `publicArmored` / `lastUsedAt` | Done | Stored on save; public backfilled on unlock; Encrypt/Decrypt selects ordered by last use |
| Shared unlock | Done | `vault-unlock.js` — Encrypt / Decrypt / Toolkit / `agent.unlock` |
| Agent session | Done | `vault-session.js` — in-memory unlocked armor, 5 min TTL; cleared on idle / secure-destroy / hide |
| Pubkey cache store | Done | Same DB, object store `pubkeys` (see below) — **public armor only** |

### Browser trust stack (recipients)

| Layer | Storage | Holds |
|-------|---------|--------|
| **Vault** | IndexedDB `keys` + `kek` | *Your* private keys (+ own `publicArmored`) |
| **Pubkey cache** | IndexedDB `pubkeys` (`pubkey-cache.js`) | Third-party public keys discovered via Basilisk or upstream HKP; `origin` = `basilisk` \| `upstream` \| `import` |
| **Ownertrust** | localStorage `basilisk.keyTrust.v1` (`trust.js`) | `trusted` / `marginal` / `never` by fingerprint (this browser only) |
| **UI prefs** | localStorage (`prefs.js`) | Expert mode; **preferred upstream keyserver** (`basilisk.preferredKeyserver`) — allowlisted host or empty for server default; Preferences page at `/preferences` |

Resolve order for Encrypt / Toolkit recipients: in-memory → pubkey cache → Basilisk portal/`/pks/lookup` → (signed-in + `BASILISK_UPSTREAM_ENABLED`) browser-direct HKP to an allowlisted host. Upstream results are **never** written as server `approved`; they stay device-local with an origin chip. Recipient picker ranks by ownertrust, then origin (Basilisk before upstream), and shows `.trust-badge` / `:key-hit-trusted` styles for locally trusted keys.

**GET-only CORS:** Public key fetch (`/pks/lookup`, WKD, `GET /api/v1/key/<fpr>`) sends `Access-Control-Allow-Origin: *` on success and error responses (including 404), plus OPTIONS preflight for `GET, HEAD, OPTIONS` only. Legacy mutate paths (`POST /pks/add`, claim/auth APIs) do **not**. Never combine `*` with credentials. If `cache_mode=redirect`, the CDN/blob host must also send ACAO for the follow-up GET.

**HKP v2 CORS is spec-mandated, not GET-only:** `draft-gallagher-openpgp-hkp` §7.1 makes `Access-Control-Allow-Origin: *` a **MUST** on *every* `/pks/v2/*` response, submissions included, so `POST /pks/v2/certs` and `PUT /pks/v2/canonical/<identity>` send it and their OPTIONS preflight advertises `POST` / `PUT` plus `Authorization, Authentication, Content-Type, X-Basilisk-Proof`. This is safe here only because **no ambient credential exists**: Basilisk sets no cookie and keeps no session, so a cross-origin page gains nothing it could not get by calling the endpoint from its own server. The write paths remain gated on a Bearer token that only reaches the mailbox owner, plus proof-of-work and per-IP rate limits. If a cookie or `Authorization`-by-default session is ever introduced, this decision must be revisited before that change ships.

**Toolkit Agent** (`agent.*`) is the local My Keys keyring surface (gpg-agent metaphor). **HKP** (`hkp.*`) uses the same recipient stack as Encrypt (`hkp.get` / `hkp.search` / `hkp.filter` / `hkp.cache`). OpenPGP crypto stays on `gpg.*`.

### Shared notebook (`web/src/lib/notebook/`)

The multi-party P2P session: presence, signalling, and the authenticated key
exchange that secures a mesh of WebRTC data channels. It is not a threshold
scheme — see the next section for what still carries the *quorum* name.

| Capability | Status | Notes |
|------------|--------|-------|
| Signaling seal | Done | OpenPGP sign+encrypt to audience (`crypto.js`) — **not** PFS |
| Signaling transport | Done | Azure Web PubSub group, joined with a server-minted JWT scoped to one room (`signaling.js` → `webpubsub.js`). The relay carries only sealed envelopes; it can read or alter none of them. |
| Session keys | Done | Ephemeral ECDH P-256 → HKDF-SHA-256 → AES-GCM-256 |
| Room / channel IDs | Done | SHA-256 / HKDF (`room.js`) |
| Key confirmation | Done | Transcript-bound v2 (`session.js` + `crypto.js`) |

The HKDF/transcript domain-separation labels still read `basilisk-quorum-*`
(`crypto.js`, `room.js`), as do the Web PubSub group labels in
`basilisk/portal/webpubsub.py`. Those strings are hash preimages, not names:
every session key, channel id and group name in existence is a function of
them, so they did not move with the directory. Changing one is a protocol
version bump, not a rename.

### Quorum — threshold (`web/src/lib/quorum/`)

What the word means on its own: an *m*-of-*n* scheme where that many parties
must cooperate. Runs **over** a shared notebook session; it does not implement
one.

| Capability | Status | Notes |
|------------|--------|-------|
| Feldman VSS | Done | P-256 commitments, share verification (`vss.js`) |
| Distributed key generation | Done | `dkg.js`, `dkg-run.js`, `dkg-session.js` |

### SSS / BLIP39 (`web/src/lib/slip39/`)

| Module | Status | Notes |
|--------|--------|-------|
| `gf256.js` | Done | Shamir over AES field poly `0x11d` |
| `slip39.js` | Done | `splitRawShares` / `combineRawShares`; optional PBKDF2-SHA-256 (20k) XOR mask |
| `blip39.js` | Done | Mnemonic encode/decode; RS1024 tag `basilisk-slip39-v1` |
| `rs1024.js` / `wordlist.js` | Done | Official 1024-word SLIP-39 list |
| Master size | Done | Exactly **16 or 32** bytes; larger payloads → `gpg.symencrypt` first |
| Legacy AES-GCM share envelope | Partial | Combine-only for old flags; new splits never set it |

### Passphrase / CSPRNG

| Module | Status | Notes |
|--------|--------|-------|
| `passphrase-gen.js` | Done | EFF Large Wordlist diceware + char mode; rejection sampling |
| `crypto.getRandomValues` | Done | Toolkit `random`, SSS coeffs, vault IVs, notebook nonces |

### Integrity / policy

| Module | Status | Notes |
|--------|--------|-------|
| `crypto-self-test.js` | Done | POST/CAST latch; suite status; refuses crypto on module ERROR |
| `fips-mode.js` | Done | Toolkit “FIPS mode” preference (verified suites only; **not** a FIPS 140 cert) |
| `toolkit/suite-gate.js` | Done | Toolbox → suite map; FIPS recipe assert |
| `module-integrity.js` | Done | SHA-256 Merkle of loaded module SRI digests |
| `memory-safety.js` | Done | **Docs only** — wipe rules (no shared `zeroBuffer`) |
| CSP + WASM | Done | `script-src 'self' 'wasm-unsafe-eval'` for Argon2; Compatible profile avoids WASM |

### POST / CAST suites

Eager startup self-tests (`runCryptoSelfTests`) cover:

| Suite | CAST IDs | Status |
|-------|----------|--------|
| **OpenPGP** | CAST-1…5 (keygen, encrypt/decrypt, sign/verify, signed+encrypted, Argon2) | Verified after POST |
| **WebCrypto** | CAST-6…11, 13–14 (SHA-256 KAT, AES-GCM, Ed25519, ECDH P-256, HKDF KAT, AES-KW, AES-CBC, AES-CTR) | Verified after POST |
| **SSS** | CAST-12 (GF(256) split/combine + BLIP39 encode/decode) | Verified after POST |

Toolkit UI always shows **verified** / **⚠ unverified** chips per crypto toolbox. **FIPS mode** (persisted `basilisk.fipsMode`) hard-blocks adding/running ops whose suite is unverified; the worker enforces the same gate via `executeToolkitRun` (`toolkit-run.js`). Disclaimer: FIPS-*inspired* posture only — not a NIST FIPS 140 certificate.

Encrypt / Decrypt banners say **OpenPGP verified** (CAST-1…5). Shared-notebook session ECDH/HKDF/AES-GCM is **not** CAST-gated today.

RSA-OAEP encrypt/decrypt is toolkit op **`rsa-oaep`** (also parses JCE OAEP forms). Distinct from OpenPGP **`gpg.encrypt`** and AES **`aes-gcm`**.

---

## Toolkit operations

Source of truth: `web/src/lib/toolkit/registry.js` + `engine.js` + `step-names.js` (alternates / migrator).

### Sources

| Op | Status | Crypto |
|----|--------|--------|
| `genkey` | Done | WebCrypto `generateKey` (see algorithms below) |
| `random` | Done | `getRandomValues` (1–1024 B) |
| `passphrase` | Done | EFF diceware (default) or `mode=char` (69-char alphabet) |
| `shares` | Done | Runtime BLIP39 mnemonic binding (no crypto) |
| `input` (`paste` / `cat`) | Done | Free-form text binding |
| `file.read` | Done | File System Access picker (or `<input type=file>`); text-ish → `text`, else `bytes`; filename/MIME in meta |
| `clipboard.read` | Done | `navigator.clipboard.readText` behind the UI's per-run permission gate |
| `age.keygen` | Done | age X25519 identity (`AGE-SECRET-KEY-1…`) — `age-keygen` |
| `gpg.decrypt` | Done | OpenPGP.js decrypt → plaintext (`count=all` for a bundle; `shares` collects mnemonics) |

### Transforms — keys & encoding

| Op | Status | Crypto |
|----|--------|--------|
| `export` | Done | `exportKey`: pkcs8 / spki / jwk / raw / scalar |
| `import` | Done | `importKey` (+ scalar → PKCS#8 for EC/OKP; `import jwk` text; RSA/X25519 SPKI) |
| `pem` / `der` | Done | Armor / identity |
| `base64` / `base64url` / `base32` / `hex` / `utf8` | Done | Encoding (`-d` decode where applicable; Base32 = RFC 4648 unpadded) |
| `inspect` (`dump` / `hexdump`) | Done | Dump; openssl-`-text`-ish key summary + JWK thumbprint; result tile keeps a snapshot for live format switching (no re-run) |

### Transforms — WebCrypto ops

| Op | Status | Crypto |
|----|--------|--------|
| `digest` | Done | `subtle.digest` SHA-256/384/512; SHA-1 **discouraged** (warn + `legacy` tags) |
| `sign` / `verify` | Done | Bound JWK / `key=$slot`; `signature=$slot` or bare base64url; fail-loud default; `soft`/`-q` → bool `true`\|`false` |
| `aes-gcm` / `-d` | Done | AES-GCM; `key=$slot`; also `aes-256-gcm`, `AES/GCM/NoPadding` |
| `aes-cbc` / `aes-ctr` | Done | Unauthenticated AES-CBC/CTR interop; IV(16)\|\|CT; prefer `aes-gcm` |
| `rsa-oaep` / `-d` | Done | RSA-OAEP content encrypt; `key=$slot`; JCE OAEP forms accepted |
| `rsa-pkcs1` / `-d` | Done | RSAES-PKCS1-v1_5 (pure-JS; **discouraged**; warn + tags); prefer `rsa-oaep` |
| `hkdf` / `pbkdf2` | Done | `deriveBits` (default) or `deriveKey` via `as=aes/256` etc. → live `key` tip (`which: secret`) |
| `ecdh` | Done | ECDH/X25519; `bits=0` curve-aware; `as=` → `deriveKey` like hkdf |
| `wrap` / `unwrap` | Done | `mode=aes-kw` (default), `aes-gcm`/`aes-cbc`/`aes-ctr`, or `rsa-oaep`; unwrap → live `key` tip (`export raw` for bytes); unwrap `alg=` aes/hmac/aes-kw; optional OAEP `label=`, GCM `tagLength=`, CTR `length=` |

### Transforms — whole-file encryption

Both live on the `files` shelf, and the distinction between them is the point:
one is Basilisk's own format keyed by any AES slot the notebook holds, the
other is real age that leaves the browser.

| Op | Status | Crypto |
|----|--------|--------|
| `stream.seal` / `stream.open` | Done | Chunked AES-256-GCM in the STREAM construction; per-file key wrapped under `key=$slot`; 64 KiB chunks (`chunk=`); counter+final-flag nonce ⇒ reorder / splice / truncation detected |
| `age.encrypt` / `age.decrypt` | Done | **age-encryption.org/v1** via typage; X25519 `to=` recipients or scrypt `passphrase=`; `armor=true` for the PEM-style form |
| `age.recipient` | Done | Identity → `age1…` recipient (derived, publishable) |

**`stream.*` is not age.** Same construction, different everything else:

| | age v1 | `stream.seal` |
|---|---|---|
| AEAD | ChaCha20-Poly1305 | AES-256-GCM (WebCrypto has no ChaCha) |
| Chunk | 64 KiB fixed | 64 KiB default, `chunk=` selectable |
| Key delivery | recipient stanzas (X25519 / scrypt) + HMAC'd header | one AES-GCM-wrapped file key under `key=$slot` |
| Header integrity | HMAC-SHA-256 keyed by the file key | header is the AAD of the file-key wrap |
| Armor | `BEGIN AGE ENCRYPTED FILE` | none — pipe through `base64` for text |
| Magic | `age-encryption.org/v1` | `BSKSTRM1` |

Why chunk at all: `SubtleCrypto.encrypt` is one-shot, so a file must fit in
memory and its single tag only verifies after the last byte. STREAM (Hoang–
Reyhanitabar–Rogaway–Vizár, [ePrint 2015/189](https://eprint.iacr.org/2015/189))
bakes the chunk index and a final-chunk flag into each nonce, which is what
makes the chunked form as strong as the one-shot one. Wire format and the
reasoning are in `web/src/lib/toolkit/stream-aead.js`.

Why typage for age: what the toolkit writes has to be what someone else's
`age -d` reads, and a format that is 95% compatible fails only on their
machine. `age-encryption` is the implementation by age's own author.

### Transforms — secret sharing

| Op | Status | Crypto |
|----|--------|--------|
| `sss.split` | Done | GF(256) Shamir → `shares/raw` |
| `blip39` | Done | Encode `shares/raw` → `shares/mnemonic` |
| `blip39 -d` | Done | Decode mnemonics → raw |
| `sss.combine` | Done | Combine raw SSS → `bytes/master` |

### Transforms — OpenPGP

| Op | Status | Crypto |
|----|--------|--------|
| `gpg.genkey` | Done | Curve25519 keygen; private on stem, public artifact |
| `gpg.inspect` | Done | Armored summary / packet map / JSON (no decrypt) |
| `gpg.encrypt` / `gpg.decrypt` | Done | Public-key encrypt / decrypt; `to=@\|email\|fpr`; `mode=separate\|combined`; `sign`/`-s` |
| `gpg.sign` / `gpg.verify` | Done | Cleartext (default) or detached; `key=$slot` or vault panel; soft `-q` |
| `gpg.symencrypt` | Done | Dual mode: default `mode=master` (SKESK under fresh 32 B master tip + envelope); `mode=passphrase` + `passphrase=` (`gpg -c` tip) |
| `gpg.symdecrypt` | Done | Dual mode: `mode=master` unwraps bound envelope with hex(master); `mode=passphrase` decrypts armored tip |

### Agent (toolbox `agent`, no CAST suite)

Local My Keys IndexedDB — unlock/list/save; never put unlocked private armor into recipe text (use fingerprints / `@` slots). Pipeline type `openpgp-key/private` (or `/public` for `agent.pub`). Toolkit **keyring panel** + **agent TTL strip** show metas / countdown only — Lock all calls `sessionClear()` (same 5m idle TTL). Session holds armored strings (unwipeable); visible chrome does not put private armor in the DOM.

| Op | Status | Notes |
|----|--------|-------|
| `agent.unlock` | Done | Unlock by `fpr=` → `openpgp-key/private`; main-thread; session-cached |
| `agent.pub` | Done | Emit stored `publicArmored` as `openpgp-key/public` |
| `agent.list` | Done | JSON metas (no secrets) |
| `agent.save` | Done | Save pipeline private into vault; `protection=device\|passphrase\|passkey` |

### HKP (toolbox `hkp`, no CAST suite)

Typed `recipients` lists for encrypt `to=@…`. Email `to=` uses deferred lookup (search glyph → picker); not silent auto-all.

| Op | Status | Notes |
|----|--------|-------|
| `hkp.get` | Done | Public key by fingerprint → `openpgp-key/public` |
| `hkp.search` | Done | Directory search → `recipients` (`format=json` → text) |
| `hkp.filter` | Done | Keep approved; drop what the directory shows cannot encrypt — revoked, expired (defaults on). Capability of the rest is unverified: only `hkp.get` reads the certificate |
| `recipients.merge` | Done | Dedupe by fingerprint (`with=$slot`) |

### WebAuthn (toolbox `webauthn`, no CAST suite)

Shelves keep attestation/MDS out of the main Essentials list. Ceremonies (`webauthn.create` / `webauthn.get` / `webauthn.prf`) run on the **main thread** (not the crypto worker). Soft MDS never blocks crypto and is **not** a CAST.

| Op | Shelf | Status | Notes |
|----|-------|--------|-------|
| `webauthn.caps` | Essentials | Done | Capability probe → JSON |
| `webauthn.create` | Essentials | Done | Create + PRF IKM bytes (vault meta); soft MDS |
| `webauthn.get` | Essentials | Done | Assertion → extension-results JSON |
| `webauthn.prf` | Essentials | Done | Vault passkey PRF unlock → IKM bytes |
| `webauthn.attest` | Attestation / MDS | Done | Parse attestationObject (bytes or base64/hex text) → fmt/aaguid JSON |
| `webauthn.mds` | Attestation / MDS | Done | Soft FIDO MDS lookup (same-origin proxy) |

Compose with WebCrypto: `webauthn.prf \| hkdf 32 \| …` / `aes-gcm`.

**Templates → WebAuthn:** `webauthn-prf-aes-gcm` (PRF → HKDF → AES-GCM) and `webauthn-attest-mds` (paste attestationObject in Inputs → `webauthn.attest` → `webauthn.mds`).

### Flow & sinks

| Op | Status | Crypto |
|----|--------|--------|
| `foreach` | Done | Map via required body (`-` list or `{ … }`); optional `:items` / `:values` / `:keys` |
| `tee` / `peek` / `in` / `as` | Done | tee = mid-stem forks; `out $x` + chains + `in $x`; named args `key=$x`; cast `as master` (retag) / `as int`/`as bool` (coerce) / `as key` (materialize); distinct from hkdf/pbkdf2/ecdh param `as=aes/256`; `peek` = side inspect |
| `at` / `[n]` | Done | 1-based share index / slice |
| `gpg.encrypt` | Done | OpenPGP.js public-key encrypt (sink); `-s` sign-then-encrypt |
| `gpg.genkey` / `gpg.inspect` | Done | Curve25519 keygen; armor inspect without decrypt |
| `qr` / `text` / `out` | Done | Presentation sinks |
| `file.save` | Done | Save dialog (or download); passthrough sink like `out`; name from `name=`, else the value's meta |
| `clipboard.write` | Done | Passthrough sink; text verbatim, bytes as base64 |

### Cipher spelling accept forms

| Canonical | OpenSSL-sized | JCE (case-insensitive) |
|-----------|---------------|------------------------|
| `aes-gcm` | `aes-128-gcm`, `aes-256-gcm` | `AES/GCM/NoPadding` |
| `aes-cbc` | `aes-128-cbc`, `aes-256-cbc` | `AES/CBC/NoPadding`, `…/PKCS5Padding`, `…/PKCS7Padding` |
| `aes-ctr` | `aes-128-ctr`, `aes-256-ctr` | `AES/CTR/NoPadding` |
| `rsa-oaep` | — | `RSA/ECB/OAEPWithSHA-1AndMGF1Padding`, `…SHA-256…` |
| `rsa-pkcs1` | — | `RSA/ECB/PKCS1Padding` |

Serialize always emits the hyphenated canonical name. Bare `encrypt` / `decrypt` sugar is **migrator-only** (Upgrade recipe → concrete `aes-gcm` / …). Legacy Basilisk tokens (`aesgcm`, `wa-*`, `recover`, `encrypt gpg`, …) also require `migrateRecipe` / Upgrade recipe.

### Missing toolkit steps (WebCrypto gap tracker)

| Op | Status | Notes |
|----|--------|-------|
| `digest` | Done | SHA-256 / 384 / 512 |
| `sign` / `verify` | Done | Bound JWK or `key=$slot`; `signature=$slot`; soft `-q` text artifact |
| `aes-gcm` / `-d` | Done | IV\|\|CT\|\|tag; distinct from OpenPGP `gpg.encrypt` |
| `aes-cbc` / `aes-ctr` | Done | Unauthenticated interop; IV(16)\|\|CT; prefer `aes-gcm` for new work |
| `rsa-oaep` / `-d` | Done | RSA-OAEP content encrypt/decrypt; `key=$slot` |
| `rsa-pkcs1` / `-d` | Done | RSAES-PKCS1-v1_5 pure-JS interop; discouraged (warn + tags) |
| `hkdf` / `pbkdf2` | Done | `deriveBits` or `as=` → `deriveKey` (AES / HMAC / AES-KW → live `key` tip, `which: secret`) |
| `ecdh` | Done | Curve-aware bits; `as=` → deriveKey; slots `private=@` `peer=@` |
| `wrap` / `unwrap` | Done | `mode=aes-kw`\|`aes-gcm`\|`aes-cbc`\|`aes-ctr`\|`rsa-oaep`; unwrap → `key` tip (`export raw` for bytes); unwrap `alg=` aes/hmac/aes-kw; `label=` / `tagLength=` / `length=` |
| `hmac` / `hmac.verify` | Done | Parse sugar → `sign` / `verify` (HMAC keys) |
| `sign` / `verify` knobs | Done | RSA-PSS `saltLength=`; ECDSA `hash=` (`auto` = curve default) |
| `aes-gcm` `tagLength=` | Done | 96\|104\|112\|120\|128 (default 128) |
| `aes-ctr` `length=` | Done | AesCtrParams.length 1–128 (default 64); IV packing still 16 bytes |
| `rsa-oaep` `label=` | Done | Optional OAEP label (UTF-8) |
| `genkey` sizes / RSA hash | Done | `aes/192`, `hmac/sha384`; RSA `hash=sha-256\|384\|512` |
| SHA-1 digest | **Discouraged** | Supported via `digest sha-1`; prefer SHA-256/384/512 |
| RSAES-PKCS1-v1_5 | **Discouraged** | Supported via `rsa-pkcs1` (not SubtleCrypto); prefer `rsa-oaep` |
| RSASSA-PKCS1-v1_5 | **Discouraged** | `genkey`/`import` `padding=pkcs1` (default `pss`); prefer RSA-PSS |

`import` alg enum aligned with `genkey` (`aes/128|192|256`, `hmac/sha256|384|512`, …); formats include `jwk` (text) and SPKI for RSA / X25519 public keys. RSA: `padding=pss|pkcs1` (default `pss`) and `hash=sha-256|384|512`.

---

## WebCrypto API surface

### Used in production

| API | Where |
|-----|--------|
| `getRandomValues` | Toolkit, SSS, vault, notebook, diceware, BLIP39 ids |
| `subtle.generateKey` | Toolkit genkey; vault AES-GCM; notebook ECDH P-256 |
| `subtle.importKey` / `exportKey` | Toolkit; vault HKDF; notebook ECDH JWK; inspect |
| `subtle.encrypt` / `decrypt` | AES-GCM / AES-CBC / AES-CTR (toolkit); RSA-OAEP (`rsa-oaep`); vault/notebook AES-GCM |
| `subtle.deriveBits` | Notebook ECDH; SSS PBKDF2 mask; room channel HKDF; toolkit `hkdf`/`pbkdf2`/`ecdh` default |
| `subtle.deriveKey` | Vault PRF KEK; notebook session AES-GCM; toolkit `hkdf`/`pbkdf2`/`ecdh` with `as=` |
| `subtle.digest` | SHA-256 — room id, JWK thumbprints, notebook transcript, module integrity |
| `subtle.sign` / `verify` | Toolkit `sign`/`verify` (RSA-PSS or RSASSA-PKCS1-v1_5; optional soft mode) |
| `subtle.wrapKey` / `unwrapKey` | Toolkit `wrap`/`unwrap` (`aes-kw`, AES-GCM/CBC/CTR, `rsa-oaep`) |

### Discouraged (supported with warning + tags)

| API | Status |
|-----|--------|
| SHA-1 digests | `digest sha-1` — compile warning; artifact tags `legacy` / `discouraged` / `sha-1` |
| RSAES-PKCS1-v1_5 | `rsapkcs1` — pure-JS (SubtleCrypto removed this alg); prefer `rsaoaep` |
| RSASSA-PKCS1-v1_5 | `genkey`/`import` `padding=pkcs1` — prefer `padding=pss` (default) |

---

## Algorithms supported today

### Toolkit `genkey`

| Family | Variants | Default usage |
|--------|----------|---------------|
| ECDSA / ECDH | P-256, P-384, P-521 | `sign` or `derive` |
| OKP | Ed25519, X25519 | sign / derive |
| RSA | OAEP or sign @ 2048 / 3072 / 4096, SHA-256, e=65537; sign `padding=pss` (default) or `pkcs1` | encrypt / sign |
| AES-GCM | 128, 256 | encrypt (fixed; `usage=` ignored with warn) |
| HMAC | SHA-256, SHA-512 | sign (fixed; `usage=` ignored with warn) |

Export formats: PKCS#8, SPKI, JWK, raw, scalar/`d`.

### OpenPGP (chosen at encrypt time)

Actively selected: AES-128/192/256; AEAD ocb/gcm/eax or SEIPDv1; S2K argon2 or iterated; compression uncompressed/zip/zlib.

Display maps in `algos.js` also name historical algorithms for **inspection** of foreign keys/messages — that does not mean Basilisk generates or prefers them.

### Custom

- GF(256) SSS (K-of-N, N ≤ 16 in toolkit)
- BLIP39 (`basilisk-slip39-v1`)
- EFF diceware (~12.9 bits/word)
- PBKDF2-SHA-256 @ 20 000 iterations (SSS passphrase mask only)

---

## Feature matrix by surface

| Capability | Encrypt page | Decrypt page | Toolkit | Quorum |
|------------|:------------:|:------------:|:-------:|:------:|
| OpenPGP public-key encrypt | ✓ | | ✓ sink | signaling |
| OpenPGP password / SKESK | ✓ | | `gpg.symencrypt` | |
| Sign + encrypt | ✓ | | | signaling |
| Decrypt / verify | | ✓ | `gpg.decrypt` / `gpg.symdecrypt` | session AES-GCM |
| Profiles Auto/Modern/Compatible | ✓ | | ✓ | default seal |
| Crypto self-test gate | ✓ OpenPGP | ✓ OpenPGP | suites + FIPS mode | separate (ungated) |
| WebCrypto keygen | | | ✓ | ECDH only |
| SSS + BLIP39 | | | ✓ | |
| Vault unlock | signing pick | ✓ | decrypt unlock | audience keys |
| Ephemeral session crypto | | | | ✓ |

---

## Example recipes (current)

Normative grammar and slots/chains semantics: [RECIPE.md](./RECIPE.md).
Stem stays a flat `|` pipeline; `tee` / `foreach` take brace or indented `-` bodies;
blank lines separate chains; `out $label` / `in $label` reuse live values.

```text
# WebCrypto key → PEM (openssl pkey / genpkey style)
genkey ec/p256 | export pkcs8 | pem

# Tee selector branches (prefer :public / :private over export which=)
genkey ec/p256 | tee
  - :private | inspect
  - :public | export spki | pem | out $public
| export pkcs8 | pem | out $private

# Multi-chain reuse (blank line + in $slot)
genkey ec/p256 | out $kp

$kp | :public | export spki | pem | out $public
$kp | :private | export pkcs8 | pem | out $private

# Scalar SSS + BLIP39 (tee public, foreach shares)
genkey ec/p256 | tee
  - :public | export spki | pem | out $public
| export scalar | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share

# One share (1-based) — a real slot, readable in a later cell (in $share-1)
… | blip39 | [1] | out $share-1

# Recover (bare `shares` reads the Inputs tray, or shares a split's foreach
# emitted earlier this session; name slots instead with `$share | shares with=$late`)
shares | blip39 -d | sss.combine | import scalar alg=ec/p256 | export pkcs8 | pem

# Large payload via OpenPGP envelope then SSS
… | pem | gpg.symencrypt mode=master | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share
```

### OpenSSL CLI ↔ toolkit (keys)

Coarse tip is always `keypair` (or projected `key`); RSA vs EC vs Ed25519 live in refined `alg` / meta — not separate IoTypes. OpenPGP stays `openpgp-key`.

| OpenSSL (1.1.1) | Toolkit |
|-----------------|---------|
| [`genpkey`](https://docs.openssl.org/1.1.1/man1/genpkey/) / `genrsa` | `genkey alg=…` |
| [`pkey -pubout`](https://docs.openssl.org/1.1.1/man1/pkey/) / [`ec -pubout`](https://docs.openssl.org/1.1.1/man1/ec/) / [`rsa -pubout`](https://docs.openssl.org/1.1.1/man1/rsa/) | `:public \| export spki \| pem` |
| private PEM/DER | `export pkcs8 \| pem` or `:private \| export pkcs8 \| pem` |
| `pkey -text` / `-text_pub` | `inspect` / `peek` (openssl-style summary + JWK thumbprint on auto/text; `format=jwk` for full JWK) |
| PEM ↔ DER | `pem` / `der` |
| `dgst` / `enc` / `rand` / `pkeyutl` | `digest` / `aes-*`+`rsa-oaep` / `random` / `sign`·`verify`·encrypt ops |
| `rand -hex 32` | `random 32 \| to hex` |
| `enc -aes-256-gcm` / `-d` | `aes-gcm` / `aes-gcm -d` (prefer AEAD over CBC/CTR) |

Prefer selectors over `export which=` (discouraged; compile warns). In the ops
drawer, **Keys → Key formats** picks PKCS#8 / SPKI / JWK / … (bare Export/Import
tiles are kit-only). Not in scope: `req` / `x509` / `cms` / `pkcs12` / CA / OCSP.

### OpenSSL / GPG ↔ toolkit (password → cipher)

Password-based encryption is **two steps** in the toolkit: derive a key, then encrypt.
There is no single `openssl enc -pass` twin for WebCrypto AEAD.

| Goal | OpenSSL / GPG | Toolkit recipe |
|------|---------------|----------------|
| Passphrase → AES key | `openssl kdf` / PBKDF2 | `input \| utf8 \| pbkdf2 32 salt=$salt as=aes/256 \| out $cek` |
| Encrypt with that CEK | `enc -aes-256-gcm -K … -iv …` | `"payload" \| utf8 \| aes-gcm key=$cek \| to hex \| out $ct` |
| Decrypt | `enc -d …` | `in $ct \| from hex \| aes-gcm -d key=$cek \| utf8` |
| OpenPGP password (SKESK) | `gpg -c` | `gpg.symencrypt mode=passphrase passphrase=$pw` / `gpg.symdecrypt mode=passphrase passphrase=$pw` (SSS path: `mode=master`, random master tip) |
| Wrap CEK under KEK | `pkeyutl -encrypt` / AES-KW | `wrap key=$kek target=$cek` → bytes; `unwrap … \| export raw` for key bytes |

```text
# Password → AES-GCM (WebCrypto)
"correct horse battery staple" | utf8 | out $pw
random 16 | out $salt
in $pw | pbkdf2 32 salt=$salt as=aes/256 | out $cek
"hello" | utf8 | aes-gcm key=$cek | to hex | out $ct

# OpenPGP symmetric (gpg -c style)
"secret" | out $pw
"hello" | utf8 | gpg.symencrypt mode=passphrase passphrase=$pw | out $msg
in $msg | gpg.symdecrypt mode=passphrase passphrase=$pw | utf8
```

`unwrap` yields a live **`key` tip** (CryptoKey), not bytes — pipe `export raw` / `export jwk` when you need material. Prefer `unwrap key=$kek` over panel defaults.

### GPG CLI ↔ toolkit (OpenPGP)

| GPG | Toolkit |
|-----|---------|
| `gpg --gen-key` (Curve25519) | `gpg.genkey email="…" \| out $priv` |
| `--export` / `--export-secret-keys` | `out` of public/private armor; `agent.pub` / `agent.unlock` for My Keys |
| `--encrypt` / `--decrypt` | `gpg.encrypt` / `gpg.decrypt` (`-s` = sign+encrypt) |
| `--sign` / `--verify` | `gpg.sign` / `gpg.verify` |
| `--symmetric` / `-c` | `gpg.symencrypt mode=passphrase passphrase=$pw` / `gpg.symdecrypt mode=passphrase passphrase=$pw` (`mode=master` for SSS envelope path) |
| `--list-packets` / inspect | `gpg.inspect` (`format=summary\|packets\|json`) |

---

## Roadmap sketch (complete WebCrypto toolkit)

**Shipped (see toolkit ops above):** toolbox UX; namespaced `gpg.*` / `sss.*` / `webauthn.*`; hyphen ciphers + OpenSSL/JCE accept forms; cipher/HMAC/key-format meta pickers; `digest` (incl. discouraged SHA-1); WebCrypto `sign`/`verify` (+ `hmac`/`hmac.verify` sugar; PSS `saltLength=`; ECDSA `hash=`); `gpg.genkey` / `gpg.inspect` / `gpg.encrypt -s` / `gpg.sign`/`gpg.verify`; `passphrase mode=char`; `base32`; `aes-gcm` (`tagLength=`) / `aes-cbc` / `aes-ctr` (`length=`); `rsa-oaep` (`label=`) / discouraged `rsa-pkcs1`; RSA `padding=` + `hash=`; `aes/192` + `hmac/sha384`; `hkdf`/`pbkdf2`/`ecdh` (`as=` → aes/hmac/aes-kw; ecdh curve-aware bits); `wrap`/`unwrap` `mode=aes-kw|aes-gcm|aes-cbc|aes-ctr|rsa-oaep`; import jwk + RSA/X25519 SPKI; CAST-13/14 AES-CBC/CTR.

Out of scope / separate track: OpenPGP padding packets (RFC 9580 tag 21); AES-GCM/CBC as wrap algorithms; PQ algorithms.

Discouraged but available: SHA-1 (`digest sha-1`); RSAES-PKCS1-v1_5 (`rsa-pkcs1`); RSASSA-PKCS1-v1_5 (`padding=pkcs1`).

When adding an op: registry entry + refined types + engine case + `tests/` + update **this document**.

---

## Security notes (pointers)

| Topic | Where |
|-------|--------|
| Wipe policy / no shared `zeroBuffer` | `web/src/lib/memory-safety.js` |
| OpenPGP privateParams wipe | `web/src/lib/pgp/memory.js` |
| CSP + `wasm-unsafe-eval` for Argon2 | `basilisk/serve.py`, HTML CSP metas |
| SRI / module Merkle pin | `crypto-self-test.js`, `module-integrity.js` |
| FIPS mode / suite badges | `fips-mode.js`, `toolkit/suite-gate.js`, toolkit UI |
| WebAuthn PRF + soft MDS | `vault.js`, `webauthn/attestation.js`, `webauthn/mds.js`, `portal/mds_cache.py`, toolkit `webauthn.*` |
| Vault: no secrets in localStorage | `vault.js` header |
| Shared notebook: signaling ≠ PFS; session keys discarded on leave | `notebook/crypto.js` |
| Smartcards / YubiKey GPG unavailable in browser | Toolkit `gpg.decrypt` docs / UI |

---

## Related docs

- [CAST-AND-TEST-GAPS.md](CAST-AND-TEST-GAPS.md) — CAST / FIPS-mode / test gap plan
- [TESTING.md](TESTING.md) — server/pytest and e2e
- [DEPLOYMENT.md](DEPLOYMENT.md) — CSP / Front Door tunables
- Portal UI: `/toolkit` (with `#encrypt`, `#decrypt` and `#keys` fragments), `/published`, `/verify`, `/key`. `/encrypt`, `/decrypt`, `/quorum` and `/my-keys` were retired into the toolkit and 301 to their replacements.
