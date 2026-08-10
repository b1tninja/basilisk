# Basilisk toolkit recipe language

Normative syntax for Crypto Toolkit pipelines. The parser is a hand-rolled
recursive descent matching the EBNF below (PEG-style ordered choice).

Implementation: `web/src/lib/toolkit/recipe-parse.js` (parse),
`recipe.js` (validate / serialize / presets), `engine.js` (run).

## Quick examples

```text
# Linear stem
genkey ec/p256 | export pkcs8 | pem | out $private

# Mid-stem fork (tee): branches run on a clone; stem continues
genkey ec/p256 | tee
  - :private | inspect
  - :public | export spki | pem | out $public
| export pkcs8 | pem | out $private

# Multi-chain: blank line starts a new pipeline; $slot loads a prior out
genkey ec/p256 | out $kp

$kp | :public | export spki | pem | out $public
$kp | export pkcs8 | pem | out $private

# Shares collection → foreach body
random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share

# Dict view + per-item projection
… | blip39 | foreach :items
  - :value | out $share

# One share (1-based index)
… | blip39 | [1] | out $share-1
```

## Design rules

- A recipe is one or more **chains** separated by blank lines.
- Within a chain: flat `|` stem; a newline between stem lines is the same as `|`.
- Blocks: `tee` / `foreach` take a **body** (braces `{ … }` or indented `-` lines).
- Member / dict projection uses **colon selectors** (`:private`, `:items`, …). Dot (`.`) is reserved for namespaced ops (`gpg.encrypt`, `sss.split`) — not members.
- Slots: `out $label` registers a live pipeline value; load with bare `$label` (preferred) or `in $label` / `in 1`. `$kp | out` re-emits as `$kp`.
- Named slot args pass live values into ops: `aes-gcm key=$cek` (stem stays the payload).
- Namespaced product ops use dots (`gpg.encrypt`, `sss.combine`, `webauthn.prf`); cipher ops use hyphens (`aes-gcm`). OpenSSL-sized (`aes-256-gcm`) and JCE (`AES/GCM/NoPadding`) parse to the same canonical hyphen name — **serialize preserves** size/hash as `keyBits=` / `hash=` when implied by those forms. Bare `encrypt`/`decrypt` sugar is migrator-only.
- Bare `out kp` / `in kp` / `key=cek` do **not** live-parse — use `$label` (`out $kp`, `key=$cek`). Upgrade recipe / `migrateRecipe` rewrites bare forms. A pre-swap `@label` still loads (with a compile warning) and re-serializes as `$label`; `@` at the head of a chain is reserved.
- Stem literals: `"hello"` / `'…'` → text; `255` / `0xff` → int (serialize ints as decimal); `true` / `false` → bool. Example: `"hello world" | out $var`.
- Prefer **positional** args: `out $public`, `export pkcs8`, `genkey ec/p256`.
- Casts: retag (`as master` / `as public` / …), coerce (`as int` / `as bool`), or materialize (`as key` / `as keypair` → WebCrypto handles). Literal postfix (`1234 as int`) is not shipped — use `"1234" | as int` or `1234` stem lit.
- Empty `tee` is invalid; use `peek` for a side inspect snapshot.
- List marker is only `-`. Leading tabs are errors.
- File paths (`./x.pem`, quoted paths, `file:…`) stay reserved as *tokens* — files enter and leave through the `file.read` / `file.save` **ops**, whose picker the browser owns. A recipe never names a path, so a shared recipe cannot reach into someone else's disk.
- Comments: full-line `# …` (kept inside the current chain).
- Ops-drawer **shelves**, **collections** (`OP_COLLECTIONS`: AES / RSA / Base64·Base32), and **conjugate rows** (encrypt | decrypt, encode | decode, sign | verify, `pem` | `der`, `encode` | `decode`) are UI only — friendly tile labels (`pairLabels` / collection `actionLabels`) do not change recipe tokens. Encoding twins canonicalize to `base64.encode` / `base64.decode` (`-d` parse-only); PEM armor uses `pem` ↔ `der`; base alphabets use `encode <alphabet>` / `decode <alphabet>`. Cipher twins keep `aes-gcm` / `aes-gcm -d`.

## Chains

| Rule | Behavior |
|------|----------|
| Separator | One or more blank lines |
| Order | Chains run top-to-bottom |
| Slots | Shared registry across the whole recipe |
| First chain | Also exposed as `ast.steps` for older callers |

Use **tee** when you need a mid-stem projection fork (public beside private export).
Use **blank-line chains + `$slot` / `in`** when a later pipeline should reuse an earlier `out`.

## Notebook execution (toolkit UI)

In the browser toolkit, each blank-line **chain** is one notebook **cell**. A session **kernel** holds live `$slot` values across cell runs (Jupyter-like), so you can run an HKP cell, then an encrypt cell that consumes `to=$alices` without re-searching.

| Action | Effect |
|--------|--------|
| **Run cell** | Executes that chain against the kernel’s slot map; updates that cell’s output tiles; marks **downstream** cells stale (no auto-cascade) |
| **Run all** / **Run from here** | Sequential cell runs top-to-bottom; soft-disabled while a runnable cell still needs input, recipients, or `$slots` |
| **Clear sensitive data** | Wipes kernel slots, all cell outputs, runtime inputs, and the agent session; **keeps** cell recipes and title |
| **Reset notebook** | Clear sensitive **plus** collapse to a single empty cell (More menu) |
| **Destroy** | Same wipe as Clear sensitive for secrets/outputs; recipe text retained (v1) |
| **Clear outputs** (per cell) | Surgical cleanup of that cell’s tiles only |

Idle auto-scrub uses the same path as **Clear sensitive data**. The whole notebook still serializes to multi-chain recipe source (shareable / Templates). Slot-side params (`to=$`, `key=$`) resolve from the kernel when present. Duplicate `out $label` within one cell still errors; re-running a later cell may replace a kernel binding written earlier.

OpenPGP **Modern / Compatible / Auto** lives once in the notebook header (with **Advanced OpenPGP…** for profile details). Messaging **Encrypt** cells use the recipient binder only when the recipe has no `to=` — look-up chrome stays quiet until that panel is focused.

**Keyring** and **Variables** open as right-side Sheets (pull-outs) from the command strip / More menu — not an inline header `<details>`. Full vault management remains on **My Keys**. The Toolkit page UI is React + Tailwind + shadcn primitives; recipe/engine libs stay shared JS.

### Companion templates (forward ⇄ inverse)

The **Templates** menu is organized by category (Keys, Encrypt, WebAuthn, …) with search; recipe text is hidden behind “Show recipe” until expanded. Templates with a shared `pair` id (e.g. SSS split ⇄ recover) appear as a linked row with a bridge badge (**Slot bridge** / **Shares panel** / **Linked slots**). **Add both ⇄** appends forward then inverse as new cells and shows a mode-specific status hint.

**WebAuthn starters:** Templates → WebAuthn includes PRF → AES-GCM and **Attestation → MDS** (`input | webauthn.attest` — paste base64/hex attestationObject in Inputs).

Inter-cell feed stays **explicit `$slots`** — there is no implicit “trailing tile → next cell stem” and no new chain operator:

| Bridge | When | How |
|--------|------|-----|
| **Slot** | Inverse already uses `in $x` / `key=$x`, or starts with `input` while forward ends with `out $x` | Kernel: run top→bottom so `$x` is registered before the inverse cell |
| **Inputs** | Inverse starts with `shares` / `gpg.decrypt` | Paste share mnemonics / ciphertext into that cell’s runtime Inputs (smoke tests feed forward tiles → `inputs`) |

**Add both** may rewrite a reverse `input` head to `in $bridge` when a slot bridge applies; SSS/GPG-share inverses are left unchanged (inputs bridge). If the inverse reuses an `out $label` already emitted by the forward cell, Add both renames the inverse tip (e.g. `$pem` → `$pem_rev`) so the joined notebook validates. Trailing auto-emitted tiles alone never become slots — only `out` does.

**Exhaustive verb smoke** (Vitest, not CAST): `web/src/test/helpers/verb-smoke.js` + `web/src/test/recipe-verbs.test.js` require every `listSteps()` op and every enum/bool param value to appear in a compiling recipe, then **run** every case. WebAuthn create/get/prf and `agent.save protection=passkey` use Vitest-only `installWebAuthnPrfStub` in `web/src/test/helpers/toolkit-smoke-stubs.js` (fake `navigator.credentials` + fixed PRF IKM) — never imported by production pages.

### Sharing via URL fragment

Toolkit recipes are addressable in the **URL fragment** (never sent to the server):

| Fragment | Loads |
|----------|--------|
| `#encrypt` / `#decrypt` / `#symencrypt` | Messaging quick-start notebooks (`#symencrypt` = `mode=passphrase` + generated `$pw`) |
| `#t=<presetId>` | A Templates preset by id |
| `#r=<compact-recipe>` | Full notebook in a URL-friendly compact form |
| `#decrypt&ct=<base64url>` | Decrypt starter + **ciphertext Inputs seed** |
| `#r=…&ct=…` / `#t=…&ct=…` | Recipe/preset plus ciphertext seed |

**Compact `#r=` form** (what Copy link / auto-hash write):

- Pipes without spaces: `input|gpg.encrypt`
- Chains joined with `~` instead of blank lines
- `tee` / `foreach` bodies as one-line braces: `foreach{ - out $share }`
- Spaces encoded as `+`; tokens like `|$@=~` stay readable in the address bar — `$` costs one character per slot, not three

On load, the compact payload is expanded and **beautified** back to canonical multi-line recipe text (blank-line chains, spaced pipes, indented or brace bodies). Legacy fully percent-encoded pretty recipes still parse.

**Ciphertext seed (`ct`)** — from a ciphertext tile’s **Copy decrypt link**:

- `ct` is unpadded base64url of **binary** OpenPGP message bytes (ASCII armor is stripped for transport, then re-armored into Inputs on load).
- Seeds are minted only by an explicit share action (not auto-synced on every edit).
- Soft cap ~6k characters for the whole hash; longer messages: copy armor / download instead.

| Allowed in the fragment | Forbidden (v1) |
|-------------------------|----------------|
| Recipe / starter / preset id | Private-key armor, passphrases |
| OpenPGP **ciphertext** / envelope (`ct`) | Plaintext Inputs (`txt=`), vault selection |

Ciphertext in a URL may appear in **browser history**, screenshots, and chat logs (like emailing an `.asc`). The recipient still needs the matching private key. The fragment is not sent to Basilisk servers. Idle / Clear sensitive wipes Inputs; reload the link to re-seed.

Use **Copy link** in the notebook header for recipe-only shares. Private-key armor and passphrases are never written into the fragment. If the encoded recipe exceeds ~6k characters, auto-hash updates stop — share via **Copy recipe** instead.

### Notebook library and files

Besides the URL fragment, the toolkit can keep **named notebooks** in this browser and on disk:

| Action | What it stores |
|--------|----------------|
| **Save** / **Library…** | Title + recipe source in `localStorage` (`basilisk.toolkit.workspaces`) |
| **Export file** | Same fields as `.basilisk.json` |
| **Import file…** | `.basilisk.json` or plain recipe text (`.txt` / `.recipe`) |
| **Copy recipe** | Canonical recipe text to the clipboard (no URL length limit) |

Workspace JSON shape (v1): `{ "v": 1, "id", "title", "recipe", "updatedAt" }`.

**Never persisted in the library or export file:** Inputs (plaintext, ciphertext, JWKs, shares, passphrases), kernel slots/outputs, vault keys, or agent session. XSS can read `localStorage` — recipes that look like private-key material are refused on save/import. Prefer **Copy link** / `#decrypt&ct=` for short public ciphertext shares; use Export / Library for larger notebooks that exceed the fragment cap.

## Arguments

Each apply stage is `name` then zero or more args:

| Form | Example | Notes |
|------|---------|-------|
| Positional | `genkey ec/p256`, `out $public` | Binds the step’s `positional` param |
| Named | `sss.split threshold=2 shares=3` | `ident=value` — **unknown `name=` rejected at parse** |
| Flag | `aes-gcm -d`, `base64 -d` | Sets the param with `flag: "-d"` to `true` (ciphers + encoding twins) |
| Encode / decode verb | `base64.encode`, `base64.decode` | Encoding `decodeTwin` steps — serialize as `.encode` / `.decode` (AST still `{ decode }`) |
| Armor conjugate | `pem`, `der` | Armor / dearmor — not `.encode`/`.decode` twins |
| Base alphabet conjugate | `encode hex`, `decode base64` | Bytes ↔ text in `hex` / `base64` / `base64url` / `base32` |

Canonical serialize omits redundant `name=` for the primary positional when the
value is not the registry default (slot names always serialize as `$label`).
Encoding twins canonicalize to `name.encode` / `name.decode` (not `-d`).
PEM armor serializes as bare `pem` / `der`; base alphabets as `encode <alphabet>` / `decode <alphabet>`.

Aliases resolve at parse time only via Upgrade recipe for retired tokens (`paste` → `input`, …). Slot load is **`in $label` / bare `$label`**; `from` and `to` were retired in favour of `decode` / `encode`, which removes the ambiguity that made `from base64` unparseable. Basilisk-legacy step tokens (`aesgcm`, `wa-prf`, `recover`, bare `hex` / `unhex`, `to` / `from`, bare `encrypt`/`decrypt` sugar, …) do **not** parse — use `migrateRecipe()` / **Upgrade recipe**.

### ParamSpec (registry)

`web/src/lib/toolkit/registry.js` declares each step’s params. Parser, serialize,
Reference, and toolcards all read this schema — toolcards are views of
`getStep()`, not a second DSL. At most one `positional` param per step.

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Kwarg key and AST `params` key |
| `type` | yes | `enum` \| `int` \| `string` \| `bool` \| `flag` \| `slot` — CLI flags use `bool` + `flag` |
| `doc` | no | Reference / toolcard blurb |
| `default` | no | Filled when omitted; usually omitted from serialize |
| `enum` | no | Allowed values when `type === "enum"` |
| `min` / `max` | no | Int bounds (docs / UI) |
| `positional` | no | First bare token binds here (≤1 per step) |
| `flag` | no | Bare CLI flag (e.g. `"-d"`) → sets bool `true` |
| `allowIndex` | no | For `type: "slot"`: allow 1-based index refs |
| `serialize` | no | `"always"` — emit `name=value` even when equal to default (e.g. `mode=`) |

Non-param parse mechanisms stay outside ParamSpec: JCE/sized verb forms →
`keyBits` / `hash` via `step-names`; mid-token `@` emails; bare `$label` /
`out`/`in` slot sugar.

## Slots (`$label`)

`out` emits a result tile **and** registers a cloned live pipeline value.
`in` sources that value (typed keypair / bytes / shares / …) — not
re-parsed artifact text.

| Form | Meaning |
|------|---------|
| `out $kp` | Emit + register memory slot `kp` (+ next 1-based index) |
| `in $kp` | Load slot `kp` |
| `in 1` | Load first registered slot by registration order |
| `./x.pem`, `file:…` | Still rejected — disk is reached through `file.read` / `file.save`, not through a path in the recipe |

Rules:

- Duplicate `$label` in one recipe → error.
- Forward / missing refs → error.
- Only explicit `out` registers slots (dangling auto-emit does not).
- Default stem when omitted: `$output`.
- Bare `out kp` / `key=cek` → parse error; **Upgrade recipe** rewrites to `$`.

## Named slot args

Secondary live values (keys, peers) are passed as **slot-typed named args**,
not on the stem. The stem stays the payload.

```text
genkey aes/256 | out $cek

input | utf8 | aes-gcm key=$cek | out $ct

in $ct | aes-gcm -d key=$cek | utf8 | out $plain
```

| Op | Slot args |
|----|-----------|
| `aes-gcm` / `aes-cbc` / `aes-ctr` / `rsa-oaep` / `rsa-pkcs1` / `sign` / `unwrap` | `key=$…` |
| `aes-gcm` | also `aad=$…` (or UTF-8 literal) |
| `hkdf` / `pbkdf2` | `salt=$…` / `info=$…` (hkdf); literals still OK |
| `verify` | `key=$…` `signature=$…` (or bare base64url for `signature=`) |
| `gpg.verify` | `signature=$…` (detached; cleartext uses stem) |
| `gpg.symencrypt` / `gpg.symdecrypt` | `mode=master` (default, SSS) or `mode=passphrase` + `passphrase=$…` (`gpg -c`); passphrase alone does not flip modes |
| `ecdh` | `private=$…` `peer=$…` |
| `wrap` | `key=$…` (wrapping) `target=$…` (CEK) |
| `stream.seal` / `stream.open` | `key=$…` (wraps / unwraps the per-file key) |
| `age.encrypt` | `to=$…` (recipients) — or `passphrase=`, never both |
| `age.decrypt` | `key=$…` (an `AGE-SECRET-KEY-1…` identity) — or `passphrase=` |

Rules:

- Refs use `$label` (`key=$cek`). Bare `key=cek` is a parse error — Upgrade rewrites it.
- Forward / missing refs error at validate (same as `in`).
- When required slot args are present, the key/peer/wrap/signature panels are not required.
- Panels remain as fallback when slot args are omitted.
- Do not embed JWK JSON secrets in the recipe — only `$` refs (or panels).

```text
input | utf8 | out $msg
genkey ed25519 | out $kp

in $msg | sign key=$kp | base64url | out $sig
in $msg | verify key=$kp signature=$sig | out $ok
```

### Namespaces and cipher spellings

| Kind | Canonical | Also parses | Serialize |
|------|-----------|-------------|-----------|
| OpenPGP | `gpg.genkey` / `gpg.inspect` / `gpg.encrypt` / `gpg.decrypt` / `gpg.sign` / `gpg.verify` / `gpg.symencrypt` / `gpg.symdecrypt` | `gpg.encrypt -s` sign+encrypt; `key=$slot` on sign/verify/`-s` | dotted |
| Agent (My Keys) | `agent.unlock` / `agent.pub` / `agent.list` / `agent.save` | migrate `gpg.vault` → `agent.unlock`; emit `openpgp-key` | dotted |
| HKP (keyserver) | `hkp.get` / `hkp.search` / `hkp.filter` / `recipients.merge` | search → `recipients`; get → `openpgp-key/public` | dotted |
| WebCrypto AEAD/cipher/RSA | `aes-gcm`, `aes-cbc`, `aes-ctr`, `rsa-oaep`, `rsa-pkcs1` | `aes-256-gcm`, `AES/GCM/NoPadding` (live); `encrypt`/`decrypt` sugar via migrator only | hyphen |
| Chunked AEAD (files) | `stream.seal` / `stream.open` | — | dotted |
| age | `age.keygen` / `age.recipient` / `age.encrypt` / `age.decrypt` | — | dotted |
| File I/O | `file.read` / `file.save` | — | dotted |
| JOSE (JWS / JWE / JWT) | `jose.decode` / `jose.sign` / `jose.verify` / `jose.encrypt` / `jose.decrypt` | `key=$slot` on all but `decode`; alg/enc values are lowercase (`alg=es256` → header `ES256`) | dotted |

Write concrete cipher ops in recipes. Bare `encrypt` / `decrypt` are **migrator-only** (not OpenPGP): Upgrade recipe rewrites known sugar to `aes-gcm` / …; live parse hard-errors.

```text
input | utf8 | aes-gcm key=$cek | out $ct
in $ct | aes-gcm -d key=$cek | utf8 | out $plain
```

**Builder UX:** the ops drawer’s **Pick a cipher** strip (Encrypt | Decrypt) is a meta entry — it opens a subset of AEAD/cipher/RSA ops and inserts a **concrete** card (`aes-gcm`, …) with decode pre-filled for Decrypt. There is never a builder block named `encrypt` / `decrypt`.

OpenPGP signatures are **`gpg.sign` / `gpg.verify` only** — never bare `sign`/`verify`. OpenPGP encrypt stays **`gpg.encrypt`** (`-s` / `sign=true` = sign-then-encrypt). Prefer **`agent.unlock`** + `key=$slot` so recipes address My Keys by fingerprint/slot (not pasted armor). `hkp.get` loads remote public keys for verify. `gpg.genkey` emits `openpgp-key/private`; `gpg.inspect` summarizes armor without decrypting.

### Run receipts (`run.receipt` / `run.verify`)

A **receipt** is a signable record of what a run did, carrying **digests, never
values**: the recipe source, each cell's runtime-input and output SHA-256
digests, timestamps, and an op-registry fingerprint.

```text
random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share

run.receipt "Board key ceremony" | gpg.sign key=$me | out $receipt

input | run.verify | out $ok      # check a receipt against a re-run
```

| Op | Role |
|----|------|
| `run.receipt [label]` | Source → canonical JSON text. Pipe into `gpg.sign` / `out`. |
| `run.verify` (`-q`) | Transform: receipt text → `bool`. Fail-loud; `-q` emits `false`. |

- The receipt covers **every cell run this session**, not just its own: the
  kernel keeps a digested run log and hands it to the op through runtime
  bindings (like `input`/`shares`), so nothing kernel-level enters recipe text.
- Its own tile is excluded from the log — a receipt cannot contain its own digest.
- Comparison ignores `createdAt` / `durationMs` and compares recipe text,
  registry version, and every input/output digest in order.
- A recipe containing `random` / `genkey` **will not** re-verify — that is
  correct. Only a deterministic stretch (recombine a known secret, re-derive a
  known key) is re-checkable digest-for-digest.
- Signature validity is `gpg.verify`'s job; `run.verify` accepts a cleartext-
  signed receipt and reads the payload out of the armor.
### Files: `file.read` / `file.save`

Disk is a source and a sink, never a path in the recipe. `file.read` opens the
browser's picker — which *is* the permission moment, so unlike `clipboard.read`
there is no extra gate — and `file.save` is a passthrough sink like `out`.

```text
# Encrypt a file to an age recipient and write it back out
file.read | age.encrypt to=$pub | file.save

# Decrypt one, keeping the round trip symmetric
file.read | age.decrypt key=$id | file.save

# Filter the picker, and name the pipeline type
file.read ".pem,.asc" as=text | gpg.inspect | out $report
file.read as=bytes | digest | encode hex | out $sha
```

`file.read` emits `bytes`; `as=text` decodes the file as UTF-8 instead. Those
are the only two answers, and the recipe gives them — **the file is never
sniffed**. It cannot be: the type has to be known before the picker opens,
because that is when the drawer filters ops, the chips underline and the chain
is checked. A `as=auto` that read the MIME at run time used to disagree with
its own declaration, so `file.read accept=.pem | base64` compiled with no
errors and then threw `base64 expects bytes`. `as=auto` is retired; Upgrade
recipe rewrites it to `as=bytes`, which is what the declaration always said.

The filename and MIME ride along in meta — which is why
`file.read | age.encrypt | file.save` names the output `<original>.age` without
being told. `file.save name=` overrides; `mime=` overrides the type.

### Whole-file encryption: `stream.*` vs `age.*`

Two ways to encrypt a file, and they are **not** the same format.

```text
# Basilisk's own chunked AEAD — any AES key the notebook holds
genkey aes/256 | out $cek
file.read | stream.seal key=$cek chunk=65536 | file.save
file.read | stream.open key=$cek | file.save

# Real age — what `age -d` on someone else's machine reads
age.keygen | out $id
$id | age.recipient | out $pub

file.read | age.encrypt to=$pub | file.save
file.read | age.decrypt key=$id | file.save

# scrypt passphrase mode, and the armored text form
file.read | age.encrypt passphrase="correct horse" armor=true | out $armored
```

| | `stream.seal` | `age.encrypt` |
|---|---|---|
| Interop | none — Basilisk-only (`BSKSTRM1`) | full `age-encryption.org/v1` |
| Key | any AES `key=$slot` (`genkey`, `hkdf`, `ecdh`, `webauthn.prf`) | `age1…` recipients or a passphrase |
| AEAD | AES-256-GCM (WebCrypto has no ChaCha) | ChaCha20-Poly1305 |
| Chunking | STREAM, 64 KiB default, `chunk=` | STREAM, 64 KiB fixed |
| Armor | none — pipe through `base64` | `armor=true` |

Both use the STREAM construction, so both detect chunk reorder, splicing, and
truncation rather than only end-of-file corruption. Use `age.*` when the file
leaves Basilisk; use `stream.*` when the key already lives in the notebook and
you would otherwise have to invent an age identity to hold it.

| CLI | Recipe |
|-----|--------|
| `age-keygen` | `age.keygen` |
| `age -r age1… -o doc.age doc` | `file.read \| age.encrypt to=age1… \| file.save` |
| `age -a -r age1… …` | `… \| age.encrypt to=age1… armor=true` |
| `age -p -o doc.age doc` | `… \| age.encrypt passphrase=…` |
| `age -d -i key.txt doc.age` | `file.read \| age.decrypt key=$id \| file.save` |

### Pipeline types: `recipients` / `openpgp-key`

| Type | Meaning | Secrets? | Typical producers |
|------|---------|----------|-------------------|
| `recipients` | Ordered directory picks (pub armor + metas) | No | `hkp.search`, `hkp.filter`, `recipients.merge` |
| `openpgp-key/public` | Single OpenPGP public key | No | `hkp.get`, `agent.pub` |
| `openpgp-key/private` | Single OpenPGP private key | Yes | `agent.unlock`, `gpg.genkey`, `agent.save` |

Do **not** overload WebCrypto `key` / `keypair`. Recipients and vault keys are usually **side inputs** (`to=$…`, `key=$…`), not the encrypt/sign stem tip — the suggest drawer offers composition chips (“Encrypt message to this set”) that insert a blank-line chain.

### `gpg.encrypt to=`

| Token | Kind |
|-------|------|
| `to=$alices` | Slot (`recipients` / `openpgp-key/public` / armored text) |
| `to=fpr:AABB…` / `to=0xAABB…` / bare 40-hex | Exact fingerprint |
| `to=alice@example.org` / `to=email:…` | Unresolved until **Look up recipients** (search glyph); binds fingerprints in UI state |
| `policy=ask\|one\|all` | Multi-match (default `ask`) |
| `mode=separate\|combined` | Default `separate` = one ciphertext per recipient; `combined` = one message, N PKESKs |

When `to=` is set, the Run recipient binder is skipped. Recipe text holds emails / fingerprints / `$slots` only — never armor.

```text
input | utf8 | gpg.sign | out $signed
in $signed | gpg.verify | out $ok

agent.unlock AABBCCDDEEFF00112233445566778899AABBCCDD | out $me
input | gpg.sign key=$me | out $signed
in $signed | gpg.verify key=$me | out $ok

hkp.get AABBCCDDEEFF00112233445566778899AABBCCDD | out $bob
in $signed | gpg.verify key=$bob | out $ok

hkp.search alice@example.org | hkp.filter | out $alices
input | gpg.encrypt to=$alices
input | gpg.encrypt to=alice@example.org policy=one
input | gpg.encrypt to=fpr:AABBCCDDEEFF00112233445566778899AABBCCDD

gpg.genkey email="you@example.com" | agent.save protection=device | out $priv

input | utf8 | out $msg
in $msg | gpg.sign format=detached | out $sig
in $msg | gpg.verify signature=$sig | out $ok

input | gpg.encrypt -s
input | gpg.inspect format=packets | out $report
passphrase mode=char length=20 | out $pass
random 10 | base32 | out $id
```

WebCrypto `verify` is fail-loud by default; `verify -q` / `soft=true` emits bool `true` or `false` (setup errors still throw). Same soft mode on `gpg.verify`. Prefer fail-loud for auth decisions. `aes-cbc` / `aes-ctr` are **unauthenticated** — prefer `aes-gcm` for new work.

### JOSE (RFC 7515 / 7516 / 7519)

```text
genkey ec/p256 usage=sign | out $jwtkey

input | jose.sign key=$jwtkey alg=es256 | out $token
$token | jose.verify key=$jwtkey | out $claims

input | jose.decode | out $unverified

genkey aes/256 | out $cek
input | jose.encrypt key=$cek | out $jwe
$jwe | jose.decrypt key=$cek | out $plain
```

Typed as refined **`text`** — `text/jws`, `text/jwe`, and `text/json` for a
decoded or verified body. A compact JWS is a string on the wire, so no new base
type: `text/jws` is the same call `text/pem` makes.

| Rule | Behavior |
|------|----------|
| `jose.decode` | Never checks a signature; output leads with `"verified": false` and the tile renders with an unverified banner |
| `jose.verify` | Fail-loud, **no soft mode** — an unverified payload is attacker-chosen. Refuses `alg=none`, and refuses any header that disagrees with the bound key (algorithm confusion) |
| `expiry=` | `check` (default) enforces `exp`/`nbf` after the signature checks out; `ignore` reports them without failing |
| `alg=` / `enc=` | Lowercase in the recipe, uppercase on the wire (`es256` → `ES256`, `a256gcm` → `A256GCM`) |
| Sensitivity | A signed token and a JWE are bearer material (masked, revealable via `out`); decoded/verified claims are not |

Not implemented: `alg=none`, RSA1_5, `A*CBC-HS*` content encryption, ECDH-ES,
PBES2. The first is refused on principle; the rest need composition
SubtleCrypto does not do in one call.

RSA sign keys: `genkey rsa/2048 padding=pss` (default) or `padding=pkcs1` (discouraged RSASSA-PKCS1-v1_5); optional `hash=sha-256|384|512`. Content encrypt stays `rsa-oaep` (optional `label=`); key wrap uses `wrap mode=rsa-oaep`. `unwrap` yields a live **`key` tip** — pipe `export raw` / `export jwk` before `to hex`. SubtleCrypto knobs: `aes-gcm tagLength=`, `aes-ctr length=` (counter bits; IV packing stays 16 bytes), `sign`/`verify` `saltLength=` (RSA-PSS) and `hash=` (ECDSA override; `auto` = curve default). Symmetric sizes include `aes/192` and `hmac/sha384`.

`ecdh` defaults `bits=0` (curve-aware: P-256/X25519 → 256, P-384 → 384, P-521 → 528) and accepts `as=aes/256` etc. like `hkdf`.

### Discouraged algorithms

Supported for interop, but compile warns and result tiles are tagged `legacy` / `discouraged`:

| Op | Prefer instead |
|----|----------------|
| `digest sha-1` | `digest` / `sha-256` |
| `rsa-pkcs1` (RSAES-PKCS1-v1_5; pure-JS) | `rsa-oaep` |
| `genkey`/`import` `padding=pkcs1` (RSASSA-PKCS1-v1_5) | `padding=pss` |

On `genkey`/`import` for ed25519, x25519, aes/*, hmac/*: non-`auto` `usage=` is ignored and emits a compile warning.

## Casts (`as`)

Stage form only: `… | as TYPE`. Three kinds:

| Kind | Crypto? | Forms | Behavior |
|------|---------|-------|----------|
| **Retag** | No | `as master`, `as scalar`, `as opaque`, `as public`, `as private` | Same payload; change refined tip / `which` |
| **Materialize** | Yes | `as key`, `as keypair` | Import DER/PEM/JWK into WebCrypto **CryptoKey** / keypair tips |
| **Coerce** | No | `as int`, `as bool` | Parse/convert tip to `int` or `bool` (from text / bytes / int / bool). Postfix `1234 as int` deferred — use stem lit or `"1234" \| as int` |

```text
random 16 | digest | as master | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share

:public | export spki | pem | out $pub
in $pub | der | as key
# or: in $pub | as key
# or: in $priv | as keypair
```

| Form | Meaning |
|------|---------|
| `as master` | Tag as `bytes/master` (must be 16 or 32 bytes) |
| `as scalar` | Tag as `bytes/scalar` |
| `as opaque` | Tag as `bytes/opaque` |
| `as public` / `as private` | Set `which` on `bytes/der` or `text/pem` (no SubtleCrypto) |
| `as key` | Materialize a single **CryptoKey** tip (`which` from tip/PEM label or prior retag) |
| `as keypair` | Materialize a **keypair** tip from private material (pkcs8 / private PEM / JWK-with-`d`) |
| `as int` | Coerce tip to `int` (decimal/hex text, big-endian bytes ≤6, bool→0/1) |
| `as bool` | Coerce tip to `bool` (`true`/`false`/`yes`/`no`/`0`/`1`, nonzero bytes/int) |

Live `key` / `keypair` tips are backed by WebCrypto `CryptoKey` handles (artifacts still export JWK/PEM/DER — handles are never persisted). Explicit `import` / `export` remain for spelled-out formats. Never: `as jwk` (use `export jwk` / `import jwk`).

### Homonyms (document once — do not rename)

| Tokens | Meaning A | Meaning B |
|--------|-----------|-----------|
| `to` | *(retired encoding verb — use `encode <alphabet>`)* | Recipients: `gpg.encrypt to=$…` / `to=email:…` |
| `from` | *(retired — use `decode <alphabet>`)* | *(retired slot load — use `in` / `$label`)* |
| `as` | Cast stage: `as master` / `as key` / `as int` | KDF param: `hkdf … as=aes/256` → live `key` tip |
| `encrypt` / `decrypt` | *(migrator-only sugar)* | Prefer `aes-gcm` / `gpg.encrypt` |
| `mode=` | Cipher unwrap modes (`wrap`/`unwrap`) | `gpg.symencrypt mode=master\|passphrase` |

Teach the concrete form; Upgrade recipe rewrites retired sugar.

## Selectors

Bare selector stages become `select` under the hood; under `tee` / `foreach`
they also appear as branch prefixes (`- :public | …`).

### Projectors (stem or branch)

These change the tip type:

| Selector | Tip before | Tip after |
|----------|------------|-----------|
| `:public` / `:pub` | `keypair` | `key` (CryptoKey) + `which=public` |
| `:private` / `:priv` / `:secret` | `keypair` | `key` (CryptoKey) + `which=private` |
| `:key` | `item` | `text/opaque` |
| `:value` | `item` | `text/mnemonic` or `bytes/opaque` |
| `[n]` / `at n` | `shares` | one share (`text/mnemonic` or `bytes`) |
| `[n:m]` / `at n:m` | `shares` | `shares` slice |

After `:public`, use `export spki` (not `export pkcs8`). After `:private` or on a
full keypair stem, use `export pkcs8` / `export scalar`. The projected `key` tip
selects the half — do **not** write `export which=…` (discouraged; compile warns).
`format=spki` already means public; `pkcs8` / `scalar` already mean private.

OpenSSL analogs ([`pkey -pubout`](https://docs.openssl.org/1.1.1/man1/pkey/),
[`ec`](https://docs.openssl.org/1.1.1/man1/ec/) / [`rsa`](https://docs.openssl.org/1.1.1/man1/rsa/)
`-pubout`):

| OpenSSL | Basilisk |
|---------|----------|
| `openssl pkey -pubout` | `:public \| export spki \| pem` |
| private PEM (default) | `export pkcs8 \| pem` or `:private \| export pkcs8 \| pem` |
| `openssl pkey -text` | `inspect` / `peek` (prefer on the full keypair or after a selector) |

ASCII-armored round-trips keep the half through `pem` / `der`
(`BEGIN PUBLIC KEY` ↔ SPKI, `BEGIN PRIVATE KEY` ↔ PKCS#8):

```text
:public | export spki | pem | out $pub
in $pub | der | import spki
# or: in $pub | as key

:private | export pkcs8 | pem | out $priv
in $priv | der | import pkcs8
# or: in $priv | as keypair
```

### Iteration views (`foreach` only)

| Form | Meaning |
|------|---------|
| `foreach :items` | iterate `{key,value}` items |
| `foreach :values` | iterate share values |
| `foreach :keys` | iterate share keys |

Stem `:items` / `:keys` / `:values` are rejected — use `foreach`.

### Casts vs selectors

Selectors project live keypair halves (`:public`). Retag casts set `which` on
serialized material (`as public`). Materializing casts (`as key`) import into
CryptoKey tips. They are not interchangeable with selectors.
## Blocks

### `tee`

Side pipelines on a **clone** (or projected member). Stem value is unchanged.

```text
genkey ec/p256 | tee
  - :public | export spki | pem | out $public
| export pkcs8 | pem | out $private
```

Brace form is equivalent: `tee { - :public | … }`.

### `foreach`

Map a body over a shares collection. Optional selector before the body.
The tip after `foreach` is a **`bundle`** of per-item tips (side effects via `out` / auto-emitted shares) — do **not** pipe the bundle into cipher/KDF ops; use `$slot`s written in the body.

```text
… | blip39 | foreach
  - out $share

… | blip39 | foreach :items
  - :value | out $share
```

Nested `tee` / `foreach` inside a body is rejected in v1.

### `peek`

Side inspect snapshot; stem unchanged. Prefer this over an empty `tee`.

```text
genkey ec/p256 | peek keypair | export pkcs8 | pem | out $private
```

## Keywords

| Keyword | Role |
|---------|------|
| `tee` | Side pipelines on clone/projection; stem unchanged. **Requires** a body. |
| `foreach` | Map body over a sequence. Optional `:items` / `:values` / `:keys`. |
| `peek` | Side inspect snapshot; stem unchanged. |
| `at` | Same as `[n]` / `[n:m]` — share index or slice. |
| `in` | Source: load a prior `out` slot by `$label` or 1-based index (also written bare as `$label`). |
| `encode` / `decode` | Base-alphabet conjugate (`encode hex` / `decode base64`). |
| `out` | Emit a tile, register a slot, pass the value through. After `$x` / `in $x`, bare `out` inherits `$x`. |
| `as` | Retag refined bytes kind (`master` / `scalar` / `opaque`). |
| `input` | Free-form text at run time (not a slot). Legacy `paste`/`cat` migrate via Upgrade recipe. |
| `select` | Internal name for a bare selector stage (usually written as `:public`). |

## EBNF

```ebnf
(* Lexical *)
letter       = "A" … "Z" | "a" … "z" ;
digit        = "0" … "9" ;
ident        = letter , { letter | digit | "_" | "-" } ;
number       = digit , { digit } ;
string       = '"' , { char - '"' } , '"' | "'" , { char - "'" } , "'" ;
ws           = " " ;
nl           = "\n" ;
comment      = "#" , { char - "\n" } ;
space        = { ws } ;

(* Recipe = chains separated by blank lines *)
recipe       = chain , { blank_line , { blank_line } , chain } ;
blank_line   = space , nl ;
chain        = { comment_line | pipeline_line } ;
comment_line = space , comment , nl ;
pipeline_line = space , [ "|" ] , space , pipeline , space , nl ;

pipeline     = stage , { space , "|" , space , stage } ;
stage        = block | apply | selector | slot_source | literal ;
literal      = string | hex_int | number | bool_lit ;
hex_int      = "0x" | "0X" , hexdigit , { hexdigit } ;
bool_lit     = "true" | "false" ;

apply        = name , { space , arg } ;
name         = ident | dotted_name | hyphen_name | jce_name ;
dotted_name  = ident , "." , ident , { "." , ident } ;  (* ops only: gpg.encrypt *)
hyphen_name  = ident , "-" , ident , { "-" , ident } ;
jce_name     = letter , { letter | digit | "/" | "-" } ; (* allowlisted JCE transforms only *)
arg          = flag | binding | positional ;
flag         = "-" , ident ;
binding      = ident , "=" , value ;
positional   = value | slot_ref ;
value        = string | number | bare_value | slot_ref | "true" | "false" ;
bare_value   = letter , { letter | digit | "_" | "-" | "/" | "." } ;

slot_ref     = "$" , ident | ident | number ;   (* legacy "@" , ident still reads, with a warning *)
slot_source  = "$" , ident ;  (* ≡ in $ident ; serialize prefers this form.
                                 "@" , ident here is RESERVED (peer assignment)  *)

(* Members use colon — dot is reserved for dotted_name ops *)
selector     = ":" , ident
             | "[" , number , [ ":" , number ] , "]" ;

block        = tee_block | foreach_block ;
tee_block    = "tee" , space , body ;
foreach_block = "foreach" , [ space , selector ] , space , body ;

body         = brace_body | indent_body ;
brace_body   = "{" , space , [ nl ] , { branch_line | blank_line | comment_line } , space , "}" ;
indent_body  = nl , { branch_line | blank_line | comment_line } ;

branch_line  = indent , "-" , space , branch , space , nl ;
indent       = "  " , { "  " } ;
branch       = [ selector , space , "|" , space ] , pipeline ;
```

Parser alternatives are **ordered** (first match wins). Dot-prefixed members (`.public`) are **rejected** — use `:public` (Upgrade recipe rewrites old recipes).

## Semantics

```text
chains       blank-line separated; run in order; share a slot registry
pipeline     left-to-right within a chain
out $x       emit tile + register cloned pipeline value as slot x
in $x / in N load cloned slot (typed); must refer to an earlier out
key=$x       named slot arg — resolve live value into the op (not the stem)
as kind      retag bytes refined type (allowlisted)
tee body     side branches on projection/clone; stem unchanged
foreach      over values (default) or :items / :keys / :values
peek         side inspect; stem unchanged
```

Runtime input panels (`shares`, `input`, GPG recipients, envelopes, bound JWKs)
are never stored in the recipe text.

## Serialization

Paste / blur canonicalize via `canonicalizeRecipe`:

- lowercases step names and expands aliases
- rewrites bare slot idents to `$label`
- migrator (Upgrade recipe): bare `hex` → `to hex`, `unhex` → `from hex`, slot `from $…` → `in $…`
- joins chains with a blank line
- formats `tee` / `foreach` bodies with indented `-` lines

## Migration notes

| Old habit | Current form |
|-----------|--------------|
| Flat `foreach \| out` | `foreach` with a body: `- out $share` |
| Trailing `merge` / `collect` | Omit — body closes by dedent or `}` |
| Side-export / mid-stem fork | `tee` with `- :public \| …` (or multi-chain `out $kp` + `$kp`) |
| Dot member (`.public`) | Colon member (`:public`) — Upgrade recipe rewrites |
| `in $x` only | Bare `$x` also loads the slot; serialize prefers `$x` |
| Side inspect without a body | `peek $label` |
| `encrypt gpg` / `gpg` / `decrypt gpg` | `gpg.encrypt` / `gpg.decrypt` |
| `encrypt AES/…` / `decrypt aes-gcm` | concrete `aes-gcm` / … (migrator-only; live parse rejects) |
| `symencrypt` / `symdecrypt` | `gpg.symencrypt` / `gpg.symdecrypt` (`mode=master` default; `mode=passphrase` for gpg -c) |
| `aesgcm` / `aescbc` / `aesctr` | `aes-gcm` / `aes-cbc` / `aes-ctr` |
| `rsaoaep` / `rsapkcs1` | `rsa-oaep` / `rsa-pkcs1` |
| `sss` / `recover` | `sss.split` / `sss.combine` |
| `wa-*` | `webauthn.*` |
| `gpg.vault` / `gpg.vault.pub` | `agent.unlock` / `agent.pub` |
| `hex` / `unhex` | `to hex` / `from hex` |
| `from $slot` (slot alias) | `in $slot` (`from` is encoding only) |

Use `migrateRecipe(text)` (or the toolkit **Upgrade recipe** button) for a one-shot rewrite. The parser does not accept legacy tokens.

## See also

- [CLI.md](./CLI.md) — running these recipes headlessly under Node (`basilisk run` / `check` / `list-ops`), and which ops are browser-only
- [CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md) — algorithms, toolbox inventory, example recipes
- `web/src/lib/toolkit/registry.js` — step docs / params (Reference panel)
- `web/src/lib/toolkit/recipe.js` — validate / serialize / presets
