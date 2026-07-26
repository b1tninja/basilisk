# Cryptography modules

Client-side cryptography inventory for the Basilisk portal (`web/`). Use this to track what is implemented today and what remains for a complete **WebCrypto toolkit** (CyberChef-style pipelines over `SubtleCrypto`).

Server-side OpenPGP **parsing/policy** (`basilisk/openpgp/`) is out of scope here — it validates and stores keys; it does not run user recipes.

---

## Stack overview

| Layer | Role | Primary paths |
|-------|------|----------------|
| **OpenPGP.js** | Message encrypt / sign / decrypt; Curve25519 keygen; Argon2 S2K (WASM) | `web/src/lib/pgp/`, `crypto-worker.js` |
| **WebCrypto** | Vault KEK, quorum session keys, toolkit keygen/import/export, digests, PBKDF2/HKDF internally | `vault.js`, `quorum/crypto.js`, `toolkit/engine.js` |
| **Custom** | GF(256) Shamir SSS, BLIP39 mnemonics, EFF diceware | `slip39/`, `passphrase-gen.js` |

### Toolkit toolboxes

Every recipe step declares a `toolbox` in `registry.js`. The ops drawer is a Swiss-army layout: toolboxes (with SVG glyphs) → taxonomy **shelves** → **conjugate rows** (encrypt | decrypt, encode | `-d`). Badges on builder/suggest chips keep similar verbs distinct. Shelves and conjugates are UX-only — recipe tokens are unchanged.

Drawer order: WebCrypto → Encoding → I/O → Flow → OpenPGP → SSS → WebAuthn.

| Toolbox | Shelves | Examples |
|---------|---------|----------|
| `webcrypto` | Keys · Digest · Sign · AEAD · Cipher · RSA · KDF · Agreement · Wrap | `genkey`, `digest`, `sign`/`verify`, `aesgcm`/`-d`, `hkdf`, `ecdh`, `wrap`/`unwrap` |
| `encoding` | Binary · Text | `pem`/`-d`, `base64`/`-d`, `hex`/`-d`, `utf8` |
| `io` | Ports | `input`/`out`, `random`, `qr` |
| `flow` | Control | `foreach`, `tee`, `in`, `as` (see [RECIPE.md](./RECIPE.md)) |
| `openpgp` | Public key · Password | `encrypt`/`decrypt`, `symencrypt`/`symdecrypt` |
| `sss` | Split · Recover | `sss`, `blip39`/`-d`, `recover` |
| `webauthn` | Essentials · Attestation/MDS | `wa-caps`, `wa-create`, `wa-prf`, `wa-attest`, `wa-mds` |

Cipher (unauthenticated AES) and Wrap shelves default collapsed; WebAuthn toolbox + Attestation shelf start collapsed.

**Recipe name vs UI label:** the parser token is always unique (`encrypt` = OpenPGP). Optional `label` is display-only (e.g. `aesgcm` may show as “encrypt” under the WebCrypto badge).

Product split (intentional today):

- **Encrypt / Decrypt pages** — OpenPGP messaging for humans
- **Toolkit** — keygen, encoding, SSS/BLIP39, OpenPGP encrypt *sinks*
- **Quorum** — ephemeral P-256 ECDH → HKDF → AES-GCM session crypto over WebRTC

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
| `intended-recipient.js` | Done | Intended Recipient Fingerprint (subpacket 35) |
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
| Device KEK | Done | Non-extractable AES-GCM-256 in IndexedDB |
| Passphrase wrap | Done | OpenPGP S2K / Argon2 on armored key |
| Passkey wrap | Done | WebAuthn PRF → HKDF-SHA-256 → AES-GCM |
| Passkey attestation / MDS | Done | Soft only: `attestation: "direct"` at PRF create; AAGUID lookup via same-origin `/api/v1/mds/blob` (cached MDS3 JWT). **MDS verified / unverified** badge + device-label prefill; **does not block** enroll/unlock; not a CAST |
| Protection modes | Done | `device` \| `passphrase` \| `passkey` |

### Quorum (`web/src/lib/quorum/`)

| Capability | Status | Notes |
|------------|--------|-------|
| Signaling seal | Done | OpenPGP sign+encrypt to audience (`crypto.js`) — **not** PFS |
| Session keys | Done | Ephemeral ECDH P-256 → HKDF-SHA-256 → AES-GCM-256 |
| Room / channel IDs | Done | SHA-256 / HKDF (`room.js`) |
| Key confirmation | Done | Transcript-bound v2 (`rtc.js` + `crypto.js`) |

### SSS / BLIP39 (`web/src/lib/slip39/`)

| Module | Status | Notes |
|--------|--------|-------|
| `gf256.js` | Done | Shamir over AES field poly `0x11d` |
| `slip39.js` | Done | `splitRawShares` / `combineRawShares`; optional PBKDF2-SHA-256 (20k) XOR mask |
| `blip39.js` | Done | Mnemonic encode/decode; RS1024 tag `basilisk-slip39-v1` |
| `rs1024.js` / `wordlist.js` | Done | Official 1024-word SLIP-39 list |
| Master size | Done | Exactly **16 or 32** bytes; larger payloads → `symencrypt` first |
| Legacy AES-GCM share envelope | Partial | Combine-only for old flags; new splits never set it |

### Passphrase / CSPRNG

| Module | Status | Notes |
|--------|--------|-------|
| `passphrase-gen.js` | Done | EFF Large Wordlist diceware + char mode; rejection sampling |
| `crypto.getRandomValues` | Done | Toolkit `random`, SSS coeffs, vault IVs, quorum nonces |

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

Encrypt / Decrypt banners say **OpenPGP verified** (CAST-1…5). Quorum session ECDH/HKDF/AES-GCM is **not** CAST-gated today.

RSA-OAEP encrypt/decrypt is available as toolkit op **`rsaoaep`** (UI label `encrypt` under WebCrypto — distinct from OpenPGP `encrypt` and AES `aesgcm`).

---

## Toolkit operations

Source of truth: `web/src/lib/toolkit/registry.js` + `engine.js`.

### Sources

| Op | Status | Crypto |
|----|--------|--------|
| `genkey` | Done | WebCrypto `generateKey` (see algorithms below) |
| `random` | Done | `getRandomValues` (1–1024 B) |
| `passphrase` | Done | EFF diceware |
| `shares` | Done | Runtime BLIP39 mnemonic binding (no crypto) |
| `input` (`paste` / `cat`) | Done | Free-form text binding |
| `decrypt` | Done | OpenPGP.js decrypt → share set |

### Transforms — keys & encoding

| Op | Status | Crypto |
|----|--------|--------|
| `export` | Done | `exportKey`: pkcs8 / spki / jwk / raw / scalar |
| `import` | Done | `importKey` (+ scalar → PKCS#8 for EC/OKP; `import jwk` text; RSA/X25519 SPKI) |
| `pem` / `der` | Done | Armor / identity |
| `base64` / `base64url` / `hex` / `utf8` | Done | Encoding (`-d` decode where applicable, including `base64url -d`) |
| `inspect` (`dump` / `hexdump`) | Done | Dump; result tile keeps a snapshot for live format switching (no re-run) |

### Transforms — WebCrypto ops

| Op | Status | Crypto |
|----|--------|--------|
| `digest` | Done | `subtle.digest` SHA-256/384/512; SHA-1 **discouraged** (warn + `legacy` tags) |
| `sign` / `verify` | Done | Bound JWK / `key=@slot`; `signature=@slot` or bare base64url; fail-loud default; `soft`/`-q` → `verified`\|`invalid` |
| `aesgcm` / `aesgcm -d` | Done | AES-GCM (UI label `encrypt`); `key=@slot` |
| `aescbc` / `aesctr` | Done | Unauthenticated AES-CBC/CTR interop; IV(16)\|\|CT; prefer `aesgcm` |
| `rsaoaep` / `rsaoaep -d` | Done | RSA-OAEP content encrypt (UI label `encrypt`); `key=@slot` |
| `rsapkcs1` / `-d` | Done | RSAES-PKCS1-v1_5 (pure-JS; **discouraged**; warn + tags); prefer `rsaoaep` |
| `hkdf` / `pbkdf2` | Done | `deriveBits` (default) or `deriveKey` via `as=aes/256` etc. |
| `ecdh` | Done | ECDH/X25519; `bits=0` curve-aware; `as=` → `deriveKey` like hkdf |
| `wrap` / `unwrap` | Done | `mode=aes-kw` (default) or `mode=rsa-oaep`; AES/HMAC CEKs for AES-KW |

### Transforms — secret sharing

| Op | Status | Crypto |
|----|--------|--------|
| `sss` | Done | GF(256) Shamir → `shares/raw` |
| `blip39` | Done | Encode `shares/raw` → `shares/mnemonic` |
| `blip39 -d` | Done | Decode mnemonics → raw |
| `recover` | Done | Combine raw SSS → `bytes/master` |

### Transforms — OpenPGP envelope

| Op | Status | Crypto |
|----|--------|--------|
| `symencrypt` | Done | SKESK + SEIPD under fresh 32 B master |
| `symdecrypt` | Done | Unwrap with master-as-passphrase |

### WebAuthn (toolbox `webauthn`, no CAST suite)

Shelves keep attestation/MDS out of the main Essentials list. Ceremonies (`wa-create` / `wa-get` / `wa-prf`) run on the **main thread** (not the crypto worker). Soft MDS never blocks crypto and is **not** a CAST.

| Op | Shelf | Status | Notes |
|----|-------|--------|-------|
| `wa-caps` | Essentials | Done | Capability probe → JSON |
| `wa-create` | Essentials | Done | Create + PRF IKM bytes (vault meta); soft MDS |
| `wa-get` | Essentials | Done | Assertion → extension-results JSON |
| `wa-prf` | Essentials | Done | Vault passkey PRF unlock → IKM bytes |
| `wa-attest` | Attestation / MDS | Done | Parse attestationObject → fmt/aaguid JSON |
| `wa-mds` | Attestation / MDS | Done | Soft FIDO MDS lookup (same-origin proxy) |

Compose with WebCrypto: `wa-prf \| hkdf 32 \| …` / `aesgcm`.

### Flow & sinks

| Op | Status | Crypto |
|----|--------|--------|
| `foreach` | Done | Map via required body (`-` list or `{ … }`); optional `.items` / `.values` / `.keys` |
| `tee` / `peek` / `in` / `as` | Done | tee = mid-stem forks; `out @x` + chains + `in @x`; named args `key=@x`; cast `as master` (retag) distinct from KDF param `as=aes/256`; `peek` = side inspect |
| `at` / `[n]` | Done | 1-based share index / slice |
| `encrypt` / `gpg` | Done | OpenPGP.js public-key encrypt |
| `qr` / `text` / `out` | Done | Presentation sinks |

### Missing toolkit steps (WebCrypto gap tracker)

| Op | Status | Notes |
|----|--------|-------|
| `digest` | Done | SHA-256 / 384 / 512 |
| `sign` / `verify` | Done | Bound JWK or `key=@slot`; `signature=@slot`; soft `-q` text artifact |
| `aesgcm` / `aesgcm -d` | Done | UI label `encrypt`; IV\|\|CT\|\|tag; distinct from OpenPGP `encrypt` |
| `aescbc` / `aesctr` | Done | Unauthenticated interop; IV(16)\|\|CT; prefer `aesgcm` for new work |
| `rsaoaep` / `rsaoaep -d` | Done | RSA-OAEP content encrypt/decrypt; `key=@slot` |
| `rsapkcs1` / `-d` | Done | RSAES-PKCS1-v1_5 pure-JS interop; discouraged (warn + tags) |
| `hkdf` / `pbkdf2` | Done | `deriveBits` or `as=` → `deriveKey` (AES / HMAC keypair) |
| `ecdh` | Done | Curve-aware bits; `as=` → deriveKey; slots `private=@` `peer=@` |
| `wrap` / `unwrap` | Done | `mode=aes-kw`\|`rsa-oaep`; AES-KW unwrap `alg=` aes/hmac |
| SHA-1 digest | **Discouraged** | Supported via `digest sha-1`; prefer SHA-256/384/512 |
| RSAES-PKCS1-v1_5 | **Discouraged** | Supported via `rsapkcs1` (not SubtleCrypto); prefer `rsaoaep` |
| RSASSA-PKCS1-v1_5 | **Discouraged** | `genkey`/`import` `padding=pkcs1` (default `pss`); prefer RSA-PSS |

`import` alg enum aligned with `genkey` (`aes/128`, `hmac/sha512`, …); formats include `jwk` (text) and SPKI for RSA / X25519 public keys. RSA sign keys: `padding=pss|pkcs1` (default `pss`).

---

## WebCrypto API surface

### Used in production

| API | Where |
|-----|--------|
| `getRandomValues` | Toolkit, SSS, vault, quorum, diceware, BLIP39 ids |
| `subtle.generateKey` | Toolkit genkey; vault AES-GCM; quorum ECDH P-256 |
| `subtle.importKey` / `exportKey` | Toolkit; vault HKDF; quorum ECDH JWK; inspect |
| `subtle.encrypt` / `decrypt` | AES-GCM / AES-CBC / AES-CTR (toolkit); RSA-OAEP (`rsaoaep`); vault/quorum AES-GCM |
| `subtle.deriveBits` | Quorum ECDH; SSS PBKDF2 mask; room channel HKDF; toolkit `hkdf`/`pbkdf2`/`ecdh` default |
| `subtle.deriveKey` | Vault PRF KEK; quorum session AES-GCM; toolkit `hkdf`/`pbkdf2`/`ecdh` with `as=` |
| `subtle.digest` | SHA-256 — room id, JWK thumbprints, quorum transcript, module integrity |
| `subtle.sign` / `verify` | Toolkit `sign`/`verify` (RSA-PSS or RSASSA-PKCS1-v1_5; optional soft mode) |
| `subtle.wrapKey` / `unwrapKey` | Toolkit `wrap`/`unwrap` (`mode=aes-kw` or `mode=rsa-oaep`) |

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
| OpenPGP password / SKESK | ✓ | | `symencrypt` | |
| Sign + encrypt | ✓ | | | signaling |
| Decrypt / verify | | ✓ | `decrypt` / `symdecrypt` | session AES-GCM |
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
blank lines separate chains; `out @label` / `in @label` reuse live values.

```text
# WebCrypto key → PEM
genkey ec/p256 | export pkcs8 | pem

# Tee selector branches
genkey ec/p256 | tee
  - .private | inspect
  - .public | export spki | pem | out @public
| export pkcs8 | pem | out @private

# Multi-chain reuse (blank line + in @slot)
genkey ec/p256 | out @kp

in @kp | .public | export spki | pem | out @public
in @kp | export pkcs8 | pem | out @private

# Scalar SSS + BLIP39 (tee public, foreach shares)
genkey ec/p256 | tee
  - .public | export spki | pem | out @public
| export scalar | sss threshold=2 shares=3 | blip39 | foreach
  - out @share

# One share (1-based)
… | blip39 | [1] | out @share-1

# Recover
shares | blip39 -d | recover | import scalar alg=ec/p256 | export pkcs8 | pem

# Large payload via OpenPGP envelope then SSS
… | pem | symencrypt | sss threshold=2 shares=3 | blip39 | foreach
  - out @share
```

---

## Roadmap sketch (complete WebCrypto toolkit)

**Shipped (see toolkit ops above):** toolbox UX; `digest` (incl. discouraged SHA-1); `sign`/`verify` (soft `-q`, `signature=@slot`); `aesgcm` / `aescbc` / `aesctr`; `rsaoaep` / discouraged `rsapkcs1`; RSA sign `padding=pss|pkcs1` (pkcs1 discouraged); `hkdf`/`pbkdf2`/`ecdh` (`as=` → deriveKey; ecdh curve-aware bits); `wrap`/`unwrap` `mode=aes-kw|rsa-oaep`; import jwk + RSA/X25519 SPKI; WebAuthn `wa-*`; CAST-13/14 AES-CBC/CTR.

Out of scope / separate track: OpenPGP padding packets (RFC 9580 tag 21); AES-GCM/CBC as wrap algorithms; PQ algorithms.

Discouraged but available: SHA-1 (`digest sha-1`); RSAES-PKCS1-v1_5 (`rsapkcs1`); RSASSA-PKCS1-v1_5 (`padding=pkcs1`).

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
| WebAuthn PRF + soft MDS | `vault.js`, `webauthn/attestation.js`, `webauthn/mds.js`, `portal/mds_cache.py`, toolkit `wa-*` |
| Vault: no secrets in localStorage | `vault.js` header |
| Quorum: signaling ≠ PFS; session keys discarded on leave | `quorum/crypto.js` |
| Smartcards / YubiKey GPG unavailable in browser | Toolkit `decrypt` docs / UI |

---

## Related docs

- [CAST-AND-TEST-GAPS.md](CAST-AND-TEST-GAPS.md) — CAST / FIPS-mode / test gap plan
- [TESTING.md](TESTING.md) — server/pytest and e2e
- [DEPLOYMENT.md](DEPLOYMENT.md) — CSP / Front Door tunables
- Portal UI: `/toolkit`, `/encrypt`, `/decrypt`, `/quorum`, My Keys
