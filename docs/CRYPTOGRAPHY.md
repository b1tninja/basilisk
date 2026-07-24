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

Every recipe step declares a `toolbox` in `registry.js`. The ops drawer groups by toolbox; builder cards and suggest chips show a badge so similar verbs (e.g. UI label “encrypt” for `aesgcm` vs OpenPGP `encrypt`) stay distinct.

| Toolbox | Examples |
|---------|----------|
| `webcrypto` | `genkey`, `export`, `import`, `digest`, `sign`, `aesgcm`, … |
| `openpgp` | `encrypt`, `decrypt`, `symencrypt`, `symdecrypt` |
| `sss` | `sss`, `blip39`, `recover`, `shares` |
| `encoding` | `pem`, `base64`, `hex`, `utf8` |
| `io` | `random`, `input`, `out`, `qr` |
| `flow` | `foreach`, `merge`, `tee`, `inspect` |

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
| `crypto-self-test.js` | Done | POST/CAST latch; refuses crypto on failure |
| `module-integrity.js` | Done | SHA-256 Merkle of loaded module SRI digests |
| `memory-safety.js` | Done | **Docs only** — wipe rules (no shared `zeroBuffer`) |
| CSP + WASM | Done | `script-src 'self' 'wasm-unsafe-eval'` for Argon2; Compatible profile avoids WASM |

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
| `input` / `paste` / `cat` | Done | Free-form text binding |
| `decrypt` / `gpgdecrypt` | Done | OpenPGP.js decrypt → share set |

### Transforms — keys & encoding

| Op | Status | Crypto |
|----|--------|--------|
| `export` | Done | `exportKey`: pkcs8 / spki / jwk / raw / scalar |
| `import` | Done | `importKey` (+ scalar → PKCS#8 for EC/OKP) |
| `fanout` | Done | Side-export without consuming keypair |
| `pem` / `der` | Done | Armor / identity |
| `base64` / `base64url` / `hex` / `utf8` | Done | Encoding (`-d` decode where applicable) |
| `inspect` / `tee` | Done | Dump / peek |

### Transforms — WebCrypto ops

| Op | Status | Crypto |
|----|--------|--------|
| `digest` | Done | `subtle.digest` SHA-256/384/512 |
| `sign` / `verify` | Done | Bound JWK; fail-loud verify |
| `aesgcm` / `aesgcm -d` | Done | AES-GCM (UI label `encrypt`) |
| `hkdf` / `pbkdf2` | Done | SubtleCrypto KDFs |
| `ecdh` | Done | ECDH/X25519 `deriveBits` |
| `wrap` / `unwrap` | Done | AES-KW |

### Transforms — secret sharing

| Op | Status | Crypto |
|----|--------|--------|
| `sss` / `split` / `sss-split` | Done | GF(256) Shamir → `shares/raw` |
| `blip39` | Done | Encode `shares/raw` → `shares/mnemonic` |
| `blip39 -d` | Done | Decode mnemonics → raw |
| `recover` / `sss-combine` | Done | Combine raw SSS → `bytes/master` |

### Transforms — OpenPGP envelope

| Op | Status | Crypto |
|----|--------|--------|
| `symencrypt` / `skesk` | Done | SKESK + SEIPD under fresh 32 B master |
| `symdecrypt` / `pgpunwrap` | Done | Unwrap with master-as-passphrase |

### Flow & sinks

| Op | Status | Crypto |
|----|--------|--------|
| `foreach` / `merge` | Done | Collection map / collect |
| `encrypt` / `gpg` | Done | OpenPGP.js public-key encrypt |
| `qr` / `text` / `out` | Done | Presentation sinks |

### Missing toolkit steps (WebCrypto gap tracker)

| Op | Status | Notes |
|----|--------|-------|
| `digest` | Done | SHA-256 / 384 / 512 |
| `sign` / `verify` | Done | Bound WebCrypto JWK (`inputs.key`); fail-loud verify |
| `aesgcm` / `aesgcm -d` | Done | UI label `encrypt`; IV\|\|CT\|\|tag; distinct from OpenPGP `encrypt` |
| `hkdf` / `pbkdf2` | Done | First-class SubtleCrypto KDFs |
| `ecdh` | Done | P-256 / X25519 via bound local + peer JWK |
| `wrap` / `unwrap` | Done | AES-KW |
| AES-CBC / AES-CTR | Deferred | Not required yet |
| RSAES-PKCS1-v1_5 | Deferred | Prefer OAEP |

`import` alg enum aligned with `genkey` (`aes/128`, `hmac/sha512`, …).

---

## WebCrypto API surface

### Used in production

| API | Where |
|-----|--------|
| `getRandomValues` | Toolkit, SSS, vault, quorum, diceware, BLIP39 ids |
| `subtle.generateKey` | Toolkit genkey; vault AES-GCM; quorum ECDH P-256 |
| `subtle.importKey` / `exportKey` | Toolkit; vault HKDF; quorum ECDH JWK; inspect |
| `subtle.encrypt` / `decrypt` | **AES-GCM only** — vault, quorum, legacy SSS envelope |
| `subtle.deriveBits` | Quorum ECDH; SSS PBKDF2 mask; room channel HKDF |
| `subtle.deriveKey` | Vault PRF KEK; quorum session AES-GCM |
| `subtle.digest` | SHA-256 — room id, JWK thumbprints, quorum transcript, module integrity |

### Not used (app crypto)

| API | Status |
|-----|--------|
| `subtle.sign` / `verify` | Done via toolkit `sign`/`verify` |
| `subtle.wrapKey` / `unwrapKey` | Done via toolkit `wrap`/`unwrap` (AES-KW) |
| AES-CBC, AES-CTR, AES-KW as general modes | AES-KW done; CBC/CTR deferred |
| SHA-1 / SHA-384 / SHA-512 digests | SHA-384/512 via `digest`; SHA-1 not exposed |

---

## Algorithms supported today

### Toolkit `genkey`

| Family | Variants | Default usage |
|--------|----------|---------------|
| ECDSA / ECDH | P-256, P-384, P-521 | `sign` or `derive` |
| OKP | Ed25519, X25519 | sign / derive |
| RSA | OAEP or PSS @ 2048 / 3072 / 4096, SHA-256, e=65537 | encrypt / sign |
| AES-GCM | 128, 256 | encrypt |
| HMAC | SHA-256, SHA-512 | sign |

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
| Crypto self-test gate | ✓ | ✓ | worker path | separate |
| WebCrypto keygen | | | ✓ | ECDH only |
| SSS + BLIP39 | | | ✓ | |
| Vault unlock | signing pick | ✓ | decrypt unlock | audience keys |
| Ephemeral session crypto | | | | ✓ |

---

## Example recipes (current)

```text
# WebCrypto key → PEM
genkey ec/p256 | export pkcs8 | pem

# Scalar SSS + BLIP39
genkey ec/p256 | export scalar | sss threshold=2 shares=3 | blip39 | foreach | out name=share

# Recover
shares | blip39 -d | recover | import scalar alg=ec/p256 | export pkcs8 | pem

# Large payload via OpenPGP envelope then SSS
… | pem | symencrypt | sss threshold=2 shares=3 | blip39 | foreach | out
```

---

## Roadmap sketch (complete WebCrypto toolkit)

**Shipped (see toolkit ops above):** toolbox UX; `digest`; `sign`/`verify`; `aesgcm`; `hkdf`/`pbkdf2`; `ecdh`; `wrap`/`unwrap`; import/genkey enum alignment.

Still deferred:

1. AES-CTR/CBC — only if an interop requirement appears
2. OpenPGP padding packets (RFC 9580 tag 21)
3. Soft `verify` (boolean artifact instead of throw)

When adding an op: registry entry + refined types + engine case + `tests/` + update **this document**.

---

## Security notes (pointers)

| Topic | Where |
|-------|--------|
| Wipe policy / no shared `zeroBuffer` | `web/src/lib/memory-safety.js` |
| OpenPGP privateParams wipe | `web/src/lib/pgp/memory.js` |
| CSP + `wasm-unsafe-eval` for Argon2 | `basilisk/serve.py`, HTML CSP metas |
| SRI / module Merkle pin | `crypto-self-test.js`, `module-integrity.js` |
| Vault: no secrets in localStorage | `vault.js` header |
| Quorum: signaling ≠ PFS; session keys discarded on leave | `quorum/crypto.js` |
| Smartcards / YubiKey GPG unavailable in browser | Toolkit `decrypt` docs / UI |

---

## Related docs

- [TESTING.md](TESTING.md) — server/pytest and e2e
- [DEPLOYMENT.md](DEPLOYMENT.md) — CSP / Front Door tunables
- Portal UI: `/toolkit`, `/encrypt`, `/decrypt`, `/quorum`, My Keys
