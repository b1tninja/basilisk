# Basilisk toolkit recipe language

Normative syntax for Crypto Toolkit pipelines. The parser is a hand-rolled
recursive descent matching the EBNF below (PEG-style ordered choice).

Implementation: `web/src/lib/toolkit/recipe-parse.js` (parse),
`recipe.js` (validate / serialize / presets), `engine.js` (run).

## Quick examples

```text
# Linear stem
genkey ec/p256 | export pkcs8 | pem | out $private

# Mid-stem fork (tee): one `-` line is one branch, run on a clone; stem continues
genkey ec/p256 | tee
  - private | inspect
  - public | export spki | pem | out $public
| export pkcs8 | pem | out $private

# The selector is optional — a branch without one forks the whole value
random 32 | tee
  - encode hex | out $hex
  - digest sha-256 | out $digest
| base64 | out $secret

# Multi-chain: blank line starts a new pipeline; $slot loads a prior out
genkey ec/p256 | out $kp

$kp | public | export spki | pem | out $public
$kp | export pkcs8 | pem | out $private

# Shares collection → foreach body (the quorum is the verb's object: any 2 of 3 recover)
random 32 | sss.split 2/3 | blip39 | foreach
  - out $share

# Dict view + per-item projection
… | blip39 | foreach :items
  - :value | out $share

# One share (1-based index) — an ordinary slot, readable in a later cell
… | blip39 | [1] | out $share-1

in $share-1 | qr
```

## Design rules

- A recipe is one or more **chains** separated by blank lines.
- Within a chain: flat `|` stem; a newline between stem lines is the same as `|`.
- Blocks: `tee` / `foreach` take a **body** (braces `{ … }` or indented `-` lines).
- **One `-` line is one branch, always.** Under `tee`, every line forks the stem — opening with a projection (`- public | …`) or without one (`- encode hex | out $a`, which forks the whole value). Lines are never joined: a branch of several steps is written along its own line with `|`. `foreach` has exactly **one** body line, because the loop threads each item through it and there is no second thing a second line could be; a second `- ` there is refused.
- Keypair halves are **steps**: `public` / `private` (`:public` / `:private` still read and canonicalize to them). Item and loop projections keep their colon (`:value`, `foreach :items`). Dot (`.`) is reserved for namespaced ops (`gpg.encrypt`, `sss.split`) — never for members.
- Slots: `out $label` registers a live pipeline value — always, whatever the value carries (a share selected with `at N` / `[n]` included); load with bare `$label` (preferred) or `in $label` / `in 1`. Inside a `foreach` body, `out $label` binds the label once, to a bundle of every iteration's value. `$kp | out` re-emits as `$kp`.
- Named slot args pass live values into ops: `aes-gcm key=$cek` (stem stays the payload).
- Namespaced product ops use dots (`gpg.encrypt`, `sss.combine`, `webauthn.prf`); cipher ops use hyphens (`aes-gcm`). OpenSSL-sized (`aes-256-gcm`) and JCE (`AES/GCM/NoPadding`) parse to the same canonical hyphen name — **serialize preserves** size/hash as `keyBits=` / `hash=` when implied by those forms. Bare `encrypt`/`decrypt` sugar is migrator-only.
- Bare `out kp` / `in kp` / `key=cek` do **not** live-parse — use `$label` (`out $kp`, `key=$cek`). Upgrade recipe / `migrateRecipe` rewrites bare forms. A pre-swap `@label` still loads (with a compile warning) and re-serializes as `$label`; `@` at the head of a chain names a **peer** (see Cell headers).
- Stem literals: `"hello"` / `'…'` → text; `255` / `0xff` → int (serialize ints as decimal); `true` / `false` → bool. Example: `"hello world" | out $var`.
- Prefer **positional** args: `out $public`, `export pkcs8`, `genkey ec/p256`.
- **The quorum is `sss.split`'s object**: `sss.split 2/3` — any 2 of 3 shares recover. `sss.split 3` is an *input form only* — a majority of 3, `floor(3/2)+1` — and serializes as `2/3`, so a reader of a shared recipe never needs the majority rule. `threshold=` / `shares=` still read and converge on the fraction; writing both the object and a named pair member is refused. `1/3` refuses (one share recovers — a copy, not a quorum); `4/3` refuses (unrecoverable by construction); `3/3` is legal and has no redundancy.
- Casts: retag (`as master` / `as public` / …), coerce (`as int` / `as bool`), or materialize (`as key` / `as keypair` → WebCrypto handles). Literal postfix (`1234 as int`) is not shipped — use `"1234" | as int` or `1234` stem lit.
- Empty `tee` is invalid; use `peek` for a side inspect snapshot.
- List marker is only `-`. Leading tabs are errors.
- File paths (`./x.pem`, quoted paths, `file:…`) stay reserved as *tokens* — files enter and leave through the `file.read` / `file.save` **ops**, whose picker the browser owns. A recipe never names a path, so a shared recipe cannot reach into someone else's disk.
- Comments: `# …`, full-line or trailing a step line. A comment belongs to the **cell** it is written in and **survives serialization** — see [Comments](#comments).
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

## Cell headers (`@peer`)

A chain may open with a header naming the party the cell is written for.
`@` is who; `$` is what. The header answers **one** question — *whose machine* —
and what leaves that machine is said by the [`publish`](#publish) step, beside
the value it is said about.

```text
chain     := header? pipeline
header    := "@" peer                    # at the chain head
peer      := LABEL | "*"                 # "*" = every participant (rendezvous)
LABEL     := /^[A-Za-z][A-Za-z0-9_-]*$/  # the slot label grammar, shared
```

```text
@alice
genkey x25519 | out $kpA

@alice
$kpA | public | out $pubA | publish

@bob
random 32 | out $nonce
```

| Form | Meaning |
|------|---------|
| `@alice` | This cell belongs to the peer named `alice` |
| `@*` | Rendezvous: every participant, together — **parses, and this build refuses to plan it** (see below) |

`@alice publish` and `@alice publish=$a,$b` are the retired spelling. They still
parse, so a link written before the change opens into the notebook it meant, and
they are **rewritten into `publish` steps on the way in** — `publish` after every
`out` the header covered. Canonical text only ever carries the step form.

### `@*` is refused, not performed

The grammar accepts `@*` and the planner understands it: a rendezvous cell is
placed on everyone, and `planRun` records the barrier as a wait
(`{ peer: "*", reason: "rendezvous" }`). What does not exist is anything that
*performs* it. Nothing makes the participants arrive together.

That gap is worse than a missing feature. A cell that plans as a rendezvous and
then simply runs would have you enter alone while believing the room entered
with you — which is the exact failure `buildOfferFor` already refuses a
rendezvous handoff to avoid, reached by pressing Run instead of by handing a
cell over. So `planRun` refuses the header, before the run rather than during
it, and says what to write instead.

Write one cell per participant with `@`their label, or drop the header and let
everyone run the cell as an ordinary mirrored cell. Neither claims a barrier.

Performing one would need a wire protocol this build does not have: peers
announcing arrival at a cell, and agreement on *what* they must match before
one counts as arrived — cell index alone would let two different notebooks
rendezvous on position. That is a coordination layer, and it is not being
invented to satisfy a header nobody has needed yet.

A cell often writes several things with different destinations. A verifiable
split writes commitments the room needs, shares that must never leave, and a
digest to check against later — all three nested under `tee` / `foreach`,
because a fan-out is how one cell writes several things. Only the commitments
carry a `publish`:

```text
@mara
random 32 | tee
  - digest | encode hex | out $expected
| vss.split threshold=2 shares=3 | tee
  - vss.commitments | out $commitments | publish
| blip39 | foreach
  - out $share | qr
```

Rules:

- One peer per cell; a header with no steps under it is an error.
- The header owns its own line in pretty form and is space-joined in compact
  form (`@alice random 32|out $x`), so it survives `#r=` unchanged.
- A published slot is public; **every other `out` of that cell is that peer's
  private value**. So publishing fewer slots narrows what a plan will let
  travel, and a cell that reads an unpublished one is refused with
  `two-owners`.
- `*` is spelled `*` rather than `all` because it cannot be a label, so the
  wildcard can never collide with a participant actually called `all`.
- **A peer is a name, never a fingerprint.** A hex label of 16 characters or
  more is refused at compile *and* at share: the room is derived from a digest
  of the audience precisely so fingerprints never travel, and a fingerprint in
  shared recipe text would hand the room to anyone holding the link. A
  fingerprint remains an ordinary argument everywhere else (`hkp.get 4F2A…`).
- The header is **inert**. It records who a cell is for; it does not run
  anything, anywhere, for anyone.

### `publish`

`publish` is the step that says a value may leave the machine that made it.
Anything that leaves is a verb; nothing about disclosure is a decoration on a
header or on naming.

```text
@mara
random 32 | digest | encode hex | out $expected | publish
```

| Rule | Behavior |
|------|----------|
| Binding | Publishes the slot the **immediately preceding `out`** named, and nothing else |
| Not after an `out` | Compile error. `encode hex \| publish` has a value and no name for it to travel under, and a handoff is addressed by slot label |
| No peer | Compile error. Leaving is a claim about a boundary, and an unassigned cell has not drawn one |
| Depth | Anywhere an `out` can be written — a `tee` branch, a `foreach` body. A nested `out` is the cell's output, so it is the cell's disclosure |
| Type | Accepts anything and passes it through unchanged. *Whether* a given value may travel is the planner's question, refused as `publish-secret` with the type named |
| At run time | Nothing. `planRun` reads it to decide what a handoff may carry, and `buildResultFor` refuses a slot the cell did not publish |

The last two rows are the point of the split. A `publish` that sent something
itself would be a second road out of the cell, past the gate that already
exists; what it does instead is *declare*, in the text both ends digest, and the
gate is the one thing that moves a value.

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
- `tee` / `foreach` bodies as one-line braces — only when the body is a single `-` line: `foreach{ - out $share }`. A `tee` with two branches keeps its newlines, because folding them onto one line would merge them into one branch
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
| Named | `sss.split threshold=2 shares=3` | `ident=value` — **unknown `name=` rejected at parse**. (This pair still reads and canonicalizes to the object form `sss.split 2/3`) |
| Flag | `aes-gcm -d`, `base64 -d` | Sets the param with `flag: "-d"` to `true` (ciphers + encoding twins) |
| Encode / decode verb | `base64.encode`, `base64.decode` | Encoding `decodeTwin` steps — serialize as `.encode` / `.decode` (AST still `{ decode }`) |
| Armor conjugate | `pem`, `der` | Armor / dearmor — not `.encode`/`.decode` twins |
| Base alphabet conjugate | `encode hex`, `decode base64` | Bytes ↔ text in `hex` / `base64` / `base64url` / `base32` |

Canonical serialize omits redundant `name=` for the primary positional when the
value is not the registry default (slot names always serialize as `$label`).
Encoding twins canonicalize to `name.encode` / `name.decode` (not `-d`).
PEM armor serializes as bare `pem` / `der`; base alphabets as `encode <alphabet>` / `decode <alphabet>`.

**Vocabulary aliases** read live and converge on the namespaced canonical: `split` → `sss.split`, `words` → `blip39` (`words -d` / `words.decode` too), `send` → `quorum.send`. Parse-only — `serializeRecipe` always writes the namespaced name, so the short forms never become a second dialect. One asymmetry, on purpose: **bare `send` refuses**, naming the missing recipient, where bare `quorum.send` broadcasts to every verified peer — an absent recipient deciding "everyone" is an absence deciding a security property, and the short verb never inherits it.

Retired-token aliases resolve at parse time only via Upgrade recipe (`paste` → `input`, …). Slot load is **`in $label` / bare `$label`**; `from` and `to` were retired in favour of `decode` / `encode`, which removes the ambiguity that made `from base64` unparseable. Basilisk-legacy step tokens (`aesgcm`, `wa-prf`, `recover`, bare `hex` / `unhex`, `to` / `from`, bare `encrypt`/`decrypt` sugar, …) do **not** parse — use `migrateRecipe()` / **Upgrade recipe**.

### ParamSpec (registry)

`web/src/lib/toolkit/registry.js` declares each step’s params. Parser, serialize,
Reference, and toolcards all read this schema — toolcards are views of
`getStep()`, not a second DSL. At most one `positional` param per step.

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Kwarg key and AST `params` key |
| `type` | yes | The value kind only: `enum` \| `int` \| `string` \| `bytes` \| `bool` \| `flag` — CLI flags use `bool` + `flag` |
| `doc` | no | Reference / toolcard blurb |
| `default` | no | Filled when omitted; usually omitted from serialize |
| `enum` | no | Allowed values when `type === "enum"` |
| `min` / `max` | no | Int bounds (docs / UI) |
| `positional` | no | First bare token binds here (≤1 per step) |
| `flag` | no | Bare CLI flag (e.g. `"-d"`) → sets bool `true` |
| `slot` | no | How the value may be supplied: absent/`false` literal only, `true` literal or `$ref`, `"required"` `$ref` only. Defaults to literal-only, so a param that takes a ref has to say so |
| `slotOf` | no | The pipeline type(s) a ref must resolve to — checked at compile time. Omit only where any type is honest (`in $x`) |
| `allowIndex` | no | For slot params: allow 1-based index refs |
| `unresolvedInput` | no | Leaving this unbound leaves an input the *run* asks for: the engine falls back to a panel instead of failing. Which panel is not declared — it is rendered from `slotOf` (`openpgp-key` in the set → the OpenPGP panel, otherwise the keys tray), so a panel is a view of the type and not a second vocabulary |
| `requiredWith` | no | Names a sibling param whose truthiness arms the requirement (`gpg.encrypt key=` only when `sign` is set) |
| `serialize` | no | `"always"` — emit `name=value` even when equal to default. For a param whose value is a decision about *this* secret and *these* people rather than a build-wide policy: `sss.split` / `vss.split` `threshold=` `shares=`, `dkg.run threshold=`, `gpg.symencrypt` / `gpg.symdecrypt` `mode=`. A quorum that matched the default used to serialize away, so a 2-of-3 and a 2-of-16 were the same text and the manifest both ends digest held neither. `sss.split`'s pair now travels as the verb's **object** (`2/3`, a step-level `object` hook spelling both params in one token); the flag remains as the statement of the property the hook honours |

A recipe's runtime input needs are derived from these two fields plus the
step-level `unresolvedInputs` (the panel a step's *pipeline* value arrives
from, which no param can describe), by one walk in
`lib/toolkit/input-needs.js`. There is no list of ops that need the key panel:
adding an `unresolvedInput` param to an op makes the panel appear, and
`input-needs-declared.test.js` fails if an op's engine reads a panel its
registry entry does not declare — which is how `stream.seal` / `stream.open`
were found silently unrunnable.

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
random 32 | sss.split 2/3 | blip39 | foreach
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

# scrypt passphrase mode, and the armored text form — the passphrase is bound
# from Inputs and named, never written into the recipe (see `secret` params)
input | out $pw
file.read | age.encrypt passphrase=$pw armor=true | out $armored
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
| `age -p -o doc.age doc` | `… \| age.encrypt passphrase=$pw` |
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

**`mode=` decides what is left in the pipe, and it is the only thing that does.**
`separate` writes one message per recipient — a count no recipe text carries — so
there is no single value to hand on: the messages go to the artifact list and the
pipe is left empty (`artifact`). `combined` writes exactly **one** message however
many recipients it has, so it pipes that message on as `text/armored/openpgp`, the
same type `gpg.symencrypt mode=passphrase` produces.

An empty pipe cannot be named or moved: `out`, `publish`, `tee`, `peek`,
`clipboard.write` and `file.save` all refuse it at compile time. `… | gpg.encrypt
| out $sealed` used to register a slot whose runtime value was `null` while typing
as publishable — a `publish` on it passed the plan and handed the room nothing.
To seal a value and then do something with it, write `mode=combined`:

```text
in $share | gpg.encrypt mode=combined to=fpr:AABB… | out $sealed | publish
in $sealed | agent.decrypt | shares | blip39 -d | sss.combine | out $secret
```

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
random 16 | digest | as master | sss.split 2/3 | blip39 | foreach
  - out $share

public | export spki | pem | out $pub
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

A projection reads a member out of the pipeline value and hands the result on,
which is a verb's shape. **The keypair halves are therefore spelled as verbs** —
`public` and `private`, no sigil — in the stem and in a branch alike:

```text
genkey ec/p256 | public | export spki | pem | out $pub

genkey ec/p256 | tee
  - public | export spki | out $pub
| out $kp
```

`:public` and `:private` still read, wherever they used to, and **canonicalize
to the verb**: a link written before the change opens into the notebook it
meant, and comes back out as `public`. The branch prefix folds the same way —
`- :public | export spki` is one branch whose first step is `public`, which is
what it always meant, running on a clone of the stem like every other branch.

### Projectors

These change the tip type:

| Selector | Tip before | Tip after |
|----------|------------|-----------|
| `public` (`:public`) | `keypair` | `key` (CryptoKey) + `which=public` |
| `private` (`:private`) | `keypair` | `key` (CryptoKey) + `which=private` |
| `:key` | `item` | `text/opaque` |
| `:value` | `item` | `text/mnemonic` or `bytes/opaque` |
| `[n]` / `at n` | `shares` | one share (`text/mnemonic` or `bytes`) |
| `[n:m]` / `at n:m` | `shares` | `shares` slice |

**`:key` and `:value` keep their colon, and that is a distinction rather than
an omission.** They project a member of the *item* a `foreach :items` loop is
currently holding, so a step named `value` would be an error everywhere in the
language except inside one mode of one loop. `[n]` / `at n` keeps its bracket
because `at` is already the verb for it.

After `public`, use `export spki` (not `export pkcs8`). After `private` or on a
full keypair stem, use `export pkcs8` / `export scalar`. The projected `key` tip
selects the half — do **not** write `export which=…` (discouraged; compile warns).
`format=spki` already means public; `pkcs8` / `scalar` already mean private.

OpenSSL analogs ([`pkey -pubout`](https://docs.openssl.org/1.1.1/man1/pkey/),
[`ec`](https://docs.openssl.org/1.1.1/man1/ec/) / [`rsa`](https://docs.openssl.org/1.1.1/man1/rsa/)
`-pubout`):

| OpenSSL | Basilisk |
|---------|----------|
| `openssl pkey -pubout` | `public \| export spki \| pem` |
| private PEM (default) | `export pkcs8 \| pem` or `private \| export pkcs8 \| pem` |
| `openssl pkey -text` | `inspect` / `peek` (prefer on the full keypair or after a projection) |

ASCII-armored round-trips keep the half through `pem` / `der`
(`BEGIN PUBLIC KEY` ↔ SPKI, `BEGIN PRIVATE KEY` ↔ PKCS#8):

```text
public | export spki | pem | out $pub
in $pub | der | import spki
# or: in $pub | as key

private | export pkcs8 | pem | out $priv
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

Selectors project live keypair halves (`public`). Retag casts set `which` on
serialized material (`as public`) — same word, and the difference is the whole
reason both exist: `public` is a step that projects a live keypair, `as public`
is an argument to `as` that relabels serialized material without touching it.
Materializing casts (`as key`) import into CryptoKey tips. They are not
interchangeable with selectors.
## Blocks

### `tee`

Side pipelines on a **clone** (or projected member). Stem value is unchanged.

**Each `-` line is one branch.** The selector is the optional half of a branch
line: with one, the branch sees that member; without one, it sees a clone of the
whole stem value. Lines are never concatenated — a branch that needs several
steps writes them along its own line with `|`.

```text
genkey ec/p256 | tee
  - public | export spki | pem | out $public
| export pkcs8 | pem | out $private
```

Without a selector the branch sees the stem itself, so these are two branches
over the same 32 bytes and `$hex` and `$digest` are independent of each other:

```text
random 32 | tee
  - encode hex | out $hex
  - digest sha-256 | out $digest
| base64 | out $secret
```

Split across more lines they would be more branches. `- encode hex` and
`- out $hex` on two lines are two branches, and the second one writes the raw
bytes to `$hex` rather than their hex — which is what the count of `-`
characters says, and no longer something the parser quietly disagrees with.

Branches run in the order they are written, and serialize back in that order.

Brace form is equivalent: `tee { - public | … }`.

### `foreach`

Map a body over a shares collection. Optional selector before the body.
The tip after `foreach` is a **`bundle`** of per-item tips (side effects via `out` / auto-emitted shares) — do **not** pipe the bundle into cipher/KDF ops; use `$slot`s written in the body.

A body `out $x` emits one tile per iteration and binds `$x` **once**, to a
bundle of every iteration's value — the label is written once in the text, so
it names the whole emitted set rather than whichever iteration ran last.
`shares` collects bundles, so `$x | shares | blip39 -d | sss.combine` recovers
the set on the machine that split it. Two cells cannot both claim the label:
`Duplicate out slot $x` at compile, the same rule as everywhere else.

```text
… | blip39 | foreach
  - out $share

… | blip39 | foreach :items
  - :value | out $share

… | blip39 | foreach
  - inspect | encode hex | out $share   # one body, one line, steps joined with `|`
```

A loop body is **one** `- ` line. Unlike `tee`, `foreach` has nothing to fan out
into: the item's value threads through the body and comes back out, so a second
`- ` line is refused rather than glued onto the first.

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
| `at` | Same as `[n]` / `[n:m]` — share index or slice. When the share count is stated in the text (`sss.split 2/3` stamps `length: 3`, `blip39` carries it), an index or slice past it refuses at compile: `at 5` of a 3-share split selects nothing. A set counted only at run time (`shares`, `gpg.decrypt`) is not checked. |
| `in` | Source: load a prior `out` slot by `$label` or 1-based index (also written bare as `$label`). |
| `encode` / `decode` | Base-alphabet conjugate (`encode hex` / `decode base64`). |
| `out` | Emit a tile, register a slot, pass the value through. After `$x` / `in $x`, bare `out` inherits `$x`. |
| `publish` | Say the slot the preceding `out` named may leave this machine. Needs a `@peer`; inert at run time. |
| `as` | Retag refined bytes kind (`master` / `scalar` / `opaque`). |
| `input` | Free-form text at run time (not a slot). Legacy `paste`/`cat` migrate via Upgrade recipe. |
| `public` / `private` | Project a keypair's half — a `key` tip with `which` set. `:public` / `:private` still read. |
| `select` | Internal name for a projection stage (written `public`, or `:value` inside a loop). |

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
name         = half | ident | dotted_name | hyphen_name | jce_name ;
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

(* Keypair halves are step names; the rest use colon.
   Dot is reserved for dotted_name ops. *)
half         = "public" | "private" ;
selector     = ":" , ident
             | "[" , number , [ ":" , number ] , "]" ;

block        = tee_block | foreach_block ;
tee_block    = "tee" , space , body ;
foreach_block = "foreach" , [ space , selector ] , space , body ;

body         = brace_body | indent_body ;
brace_body   = "{" , space , [ nl ] , { branch_line | blank_line | comment_line } , space , "}" ;
indent_body  = nl , { branch_line | blank_line | comment_line } ;

(* One branch_line is one branch. A tee takes any number; a foreach takes one. *)
branch_line  = indent , "-" , space , branch , space , nl ;
indent       = "  " , { "  " } ;
branch       = [ selector , space , "|" , space ] , pipeline ;
(* A `half` prefix is not a case here: it is a step, so it is the first
   stage of the branch's own pipeline. A `:public` prefix folds into the
   same shape on parse. *)
```

Parser alternatives are **ordered** (first match wins). Dot-prefixed members (`.public`) are **rejected** — write the step (`public`); Upgrade recipe rewrites old recipes.

## Semantics

```text
chains       blank-line separated; run in order; share a slot registry
pipeline     left-to-right within a chain
out $x       emit tile + register cloned pipeline value as slot x
in $x / in N load cloned slot (typed); must refer to an earlier out
key=$x       named slot arg — resolve live value into the op (not the stem)
as kind      retag bytes refined type (allowlisted)
tee body     one branch per `-` line, on projection or clone; stem unchanged
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
- formats `tee` / `foreach` bodies with indented `-` lines — one line per branch, its steps joined with `|`
- writes each cell's comments back, as full lines above its header

## Comments

`# …` runs to end of line. It may be a whole line or trail a step line
(`random 32 | out $a  # keep`), and it may appear inside a `tee` / `foreach`
body.

**A comment attaches to the cell, not to a step**, and canonical text writes a
cell's comments as full lines at the top of it, above any `@peer` header, in
the order they were written:

```text
# deal 2-of-3 to the room
@mara
random 32 | sss.split 2/3 | out $set | publish
```

The cell is the unit because it is the unit everything else already uses — what
a peer is assigned, what an offer carries, what a manifest row digests, what the
notebook draws as one box. There is no finer attachment available: canonical
text collapses a multi-line stem onto one `|`-joined line, so a comment written
between two stem lines has no line left to sit above. Consequences:

| Written | Comes back as |
|---------|---------------|
| Trailing a step line | A full line above the cell (promoted, not dropped) |
| Inside a `tee` / `foreach` body | A full line above the cell |
| After the last cell | A full line above the last cell |
| Alone, with no steps | Nothing — a comment-only cell is not a recipe |

Parse → serialize is **idempotent** for every one of those: the first pass moves
a comment to the top of its cell and no later pass moves it again.

**A comment is part of what the recipe means to the two ends.** It is inside
`serializeRecipe`, so it is inside the per-cell digest and the `recipeSource`
digest that a run manifest carries — two notebooks differing only in a comment
are two agreements, and an offer between them is refused. That is the intent:
the text is the agreement, and a comment is part of what a person read before
agreeing. Prose that should *not* bind the agreement goes beside the recipe
instead — that is what `run.playbook`'s `purpose` is for.

## Migration notes

| Old habit | Current form |
|-----------|--------------|
| Flat `foreach \| out` | `foreach` with a body: `- out $share` |
| Trailing `merge` / `collect` | Omit — body closes by dedent or `}` |
| Side-export / mid-stem fork | `tee` with `- public \| …` (or multi-chain `out $kp` + `$kp`) |
| Dot member (`.public`) | Colon member (`:public`) — Upgrade recipe rewrites |
| `:public` / `:private` | `public` / `private` (read on parse, rewritten) |
| `in $x` only | Bare `$x` also loads the slot; serialize prefers `$x` |
| Side inspect without a body | `peek $label` |
| `encrypt gpg` / `gpg` / `decrypt gpg` | `gpg.encrypt` / `gpg.decrypt` |
| `encrypt AES/…` / `decrypt aes-gcm` | concrete `aes-gcm` / … (migrator-only; live parse rejects) |
| `symencrypt` / `symdecrypt` | `gpg.symencrypt` / `gpg.symdecrypt` (`mode=master` default; `mode=passphrase` for gpg -c) |
| `aesgcm` / `aescbc` / `aesctr` | `aes-gcm` / `aes-cbc` / `aes-ctr` |
| `rsaoaep` / `rsapkcs1` | `rsa-oaep` / `rsa-pkcs1` |
| `sss` / `recover` | `sss.split` / `sss.combine` |
| `sss.split threshold=2 shares=3` | `sss.split 2/3` (named pair reads on parse, rewritten) |
| `split` / `words` / `send` | live aliases for `sss.split` / `blip39` / `quorum.send` — read on parse, serialized namespaced. Bare `send` refuses (name the recipient); bare `quorum.send` broadcasts |
| `wa-*` | `webauthn.*` |
| `gpg.vault` / `gpg.vault.pub` | `agent.unlock` / `agent.pub` |
| `hex` / `unhex` | `to hex` / `from hex` |
| `from $slot` (slot alias) | `in $slot` (`from` is encoding only) |
| `@alice publish` (header modifier) | `out $a \| publish` after each `out` (read on parse, rewritten) |
| `@alice publish=$a,$b` | `out $a \| publish` on those `out`s only |

Use `migrateRecipe(text)` (or the toolkit **Upgrade recipe** button) for a one-shot rewrite. The parser does not accept legacy tokens.

## See also

- [CLI.md](./CLI.md) — running these recipes headlessly under Node (`basilisk run` / `check` / `list-ops`), and which ops are browser-only
- [CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md) — algorithms, toolbox inventory, example recipes
- `web/src/lib/toolkit/registry.js` — step docs / params (Reference panel)
- `web/src/lib/toolkit/recipe.js` — validate / serialize / presets
