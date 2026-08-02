# Agent boundary + SSH — design (§26–§31)

Design sections for the capability set in [BRIEF.md](./BRIEF.md). Numbered
§26 onward per the project convention so code comments can cite them
(`§27b` style). Where a section touches an existing design decision it cites
the design v2 series the code already references (`design v2 §21a` etc.) —
those are a separate numbering line; an unqualified § here means this
document.

Every op spec below is written in the registry's own vocabulary
(`web/src/lib/toolkit/registry.js` STEPS) and every claimed primitive was
checked against the code on 2026-07-31. Where a design needs something the
engine does not have today, it is named in
[IMPLEMENTATION-STATUS.md](./IMPLEMENTATION-STATUS.md) instead of being
assumed.

---

## §26 The agent boundary in the UI

### §26a The problem stated once

`agent.unlock AABB… | out @me` then `gpg.sign key=@me` and
`agent.sign AABB…` produce the same signature with opposite security
properties: the first moves the private key *through* the pipeline — into a
slot, into the kernel, into anything downstream that reads `@me` — and the
second never lets it out of the vault module. Today the UI renders both as
ordinary chips, so the distinction lives only in the reader's head. The
boundary has to be visible at the three places a user actually looks: the
shelf, the tool card, and the pipeline.

### §26b Two shelves inside the Agent toolbox

The `agent` toolbox gains a second shelf and reorders:

```
AGENT
  Boundary            ← order 0: agent.sign, agent.decrypt
  Vault               ← order 1: agent.unlock, agent.pub, agent.list, agent.save
```

`SHELF_META` additions: `boundary: { label: "Boundary", order: 0, glyph:
"agent-boundary" }`; the existing `vault` shelf moves to `order: 1`. The
shelf *order* is the steer the brief asks for: a user opening the Agent
toolbox meets the ops that keep the key inside before the one that exports
it. "Boundary" is deliberately the same word the docs, the brief, and this
document use — the drawer is where the term is taught, and the tool card
(§26d) explains it in one sentence. The rejected alternative was a friendlier
label like "Sign & decrypt", which reads fine in isolation but leaves the
concept nameless — and a concept you cannot name is one you cannot warn
about.

### §26c The pipeline: mark the leak, not the safe path

Two treatments, and the asymmetry is the design:

- **Boundary chips are ordinary chips.** `agent.sign` in a pipeline renders
  exactly like `digest` or `gpg.verify` — same `SuggestChip`, its own glyph,
  no extra chrome. Its output tile (a signature, a plaintext) is *not*
  sensitive and never masks. Safety is the default and looks like it.
- **The unlock path is marked where the key flows.** `agent.unlock` already
  emits `openpgp-key/private` with `sensitive: true`, so its tile masks under
  the existing reveal gate (HANDOFF: "Reveal is gated"). New: the chip itself
  carries `data-key-exposed` and renders a thin underline in `--warn` beneath
  the chip label, and **so does every later chip whose step consumes the
  exposed slot** (`key=@me`, `in @me`) — the underline literally traces where
  key material travels through the recipe. The consumer set is computable
  from the AST the same way `slot-graph.js` already walks cross-cell slot
  dependencies; no new analysis machinery.

CSP fit: `data-key-exposed` is a closed vocabulary (present/absent) with one
enumerated rule in `toolkit.css` (`[data-key-exposed]::after` underline,
`background: var(--warn)`, 1px). No inline styles, no continuous values.

Rejected: tinting the whole unlock chip red. An error tone on a legitimate,
sometimes-necessary op cries wolf; the codebase reserves `--error` for
things that failed. `--warn` underline says "live key material here" the way
the amber share-only tone says "nothing has been checked" — a fact, not an
alarm.

### §26d Tool cards: one sentence each, and a declared exposure

`StepSpec` gains one optional field:

```js
exposure: "exports-secret"   // agent.unlock only, today
```

`ToolCard` renders it as a warn-toned metadata chip in the existing chips
row: **"Hands the private key to the pipeline"** (tooltip: "Everything
downstream of this step can read the key. Prefer agent.sign / agent.decrypt,
which keep it in the vault."). Declaring it in the registry rather than
special-casing the name in the widget keeps the registry the single source
of truth and makes the treatment reusable if another exporting op ever
appears.

The boundary cards state the inverse in their `doc` first sentence (see
§26f) — no extra field needed; absence of the warn chip plus the doc line is
the contrast.

### §26e Glyphs

20×20 stroke, width 1.6, round caps, per `docs/GLYPHS.md`. Described as
metaphors; the SVG geometry is the implementer's.

| Id | For | Metaphor |
|----|-----|----------|
| `agent-boundary` | Boundary shelf | A rounded-square vault outline with a keyhole (circle + short stem) centered — the key is *inside* the wall and the wall is the subject. |
| `agent-sign` | `agent.sign` | The same vault outline, with the existing `sign` quill stroke emerging through a small gap in the right wall — the signature leaves, the key does not. |
| `agent-decrypt` | `agent.decrypt` | The vault outline with a short text line (two horizontal strokes) emerging right — plaintext out. Distinct from `gpg-decrypt`'s open-shackle envelope: nothing here opens; the wall stays closed. |

`agent.unlock` keeps the existing `unlock` open-padlock glyph — an open
shackle is exactly the honest picture of what it does.

### §26f Registry entries (normative)

```js
{
  name: "agent.sign",
  kind: "transform",
  toolbox: "agent",
  shelf: "boundary",
  glyph: "agent-sign",
  doc: "Sign the pipeline payload with a My Keys key — the private key never \
enters the pipeline; the unlock happens inside the vault with per-use \
approval (§27). `format=auto` follows the key's kind: PGP → OpenPGP \
signature, SSH → sshsig (`namespace=` names the domain, `git` for git). \
Prefer this over `agent.unlock | gpg.sign`. Example: \
`input | utf8 | agent.sign AABB… | out @sig`.",
  input: "text",
  output: "text",
  params: [
    { name: "fpr", type: "string", positional: true, default: "",
      doc: "Vault key id — PGP hex fingerprint or SSH SHA256:… fingerprint" },
    { name: "format", type: "enum", default: "auto",
      enum: ["auto", "gpg", "ssh", "raw"],
      doc: "auto = key kind decides. gpg = OpenPGP; ssh = sshsig; raw = raw signature bytes (base64url text)" },
    { name: "mode", type: "enum", default: "cleartext",
      enum: ["cleartext", "detached"],
      doc: "OpenPGP only: cleartext = signed message; detached = signature only (compile warning if set with format=ssh)" },
    { name: "namespace", type: "string", default: "file",
      doc: "sshsig only: signature domain (`file`, `git`) — shown verbatim in the approval prompt" },
  ],
  overloads: [
    { when: { base: "text" }, output: { base: "text" } },
    { when: { base: "bytes" }, output: { base: "text" } },
  ],
},
{
  name: "agent.decrypt",
  kind: "transform",
  toolbox: "agent",
  shelf: "boundary",
  glyph: "agent-decrypt",
  doc: "Decrypt an OpenPGP message with a My Keys key — ciphertext in, \
plaintext out; the private key never enters the pipeline (per-use approval, \
§27). PGP-kind keys only: SSH signing keys cannot decrypt. Example: \
`input | agent.decrypt AABB… | out @plain`.",
  input: "text",
  output: "text",
  params: [
    { name: "fpr", type: "string", positional: true, default: "",
      doc: "Vault key id (PGP hex fingerprint); the key's kind must be pgp" },
  ],
  overloads: [
    { when: { base: "text" }, output: { base: "text" } },
    { when: { base: "bytes" }, output: { base: "text" } },
  ],
},
```

Both are main-thread ops (passkey ceremony, IndexedDB, approval UI) —
`recipeNeedsMainThread` extends its name check, and the CLI's toolbox
pre-flight already covers `agent` wholesale (docs/CLI.md), with §27f carving
out the approved-headless path.

`agent.unlock`'s registry `doc` gains a leading steer: *"Exports the private
key into the run — use only when a recipe genuinely needs key material
(export, transformation). For signing or decrypting, prefer `agent.sign` /
`agent.decrypt`, which keep the key in the vault."* Plus
`exposure: "exports-secret"` (§26d).

`STEP_GLYPHS` additions: `"agent.sign": "agent-sign"`,
`"agent.decrypt": "agent-decrypt"`.

---

## §27 The approval moment

This is the pinentry moment, and the design's job is to keep "agent" from
degrading into "rubber stamp". The threat to design against is not a clumsy
user; it is a *malicious recipe* — pasted from a link, imported from a
library — that buries an `agent.sign` where the author hopes nobody looks.

### §27a Surface: an inline gate at the requesting cell, not a modal

The approval renders as an inline banner **inside the requesting cell**,
directly under its pipeline row, in the same visual grammar as the
`clipboard.read` permission moment (design v2 §32d: left border-l-2 in
`--warn`, warn-tinted background, buttons inline). The `RunBar` gains a
fifth state, `waiting-approval`, beside `idle | blocked | running |
waiting-peer` — a run pauses at the cell exactly as it pauses for a peer
(design v2 §21a), no new run-loop concept.

Why not a modal: a modal hides the very context the user needs to judge the
request — *which step in which recipe is asking*. Inline at the cell, the
requesting chip is visible two centimetres above the question, and the chip
highlight (the caret ring the pipeline already uses for the active step)
points at it. Modals also train click-through; a gate that lives where the
work lives reads as part of the run, not an interruption to dismiss.
Rejected: a global banner under the RunBar (where `clipboard.read` asks) —
right pattern, wrong place; clipboard reads are notebook-global, a signing
request belongs to a step.

### §27b What the banner shows

Every line is data the engine has at the moment of the request; nothing is
inferred or decorative:

```
▌ agent.sign wants to use a key                        [request 1 of 1 this run]
▌
▌ Step        cell 3 · agent.sign fpr=SHA256:Ur1h… namespace=git
▌ Key         justin@basilisk.dev · SSH ed25519 · SHA256:Ur1hPKBrJC3z…  [passkey]
▌ Payload     412 bytes · sha256 1a2b3c4d5e6f7a8b…            [show payload ▸]
▌ Namespace   git   (what a verifier must ask for — a `git` signature
▌              cannot be replayed as a `file` signature)
▌
▌            [ Deny ]                [ Approve once ]  □ for this session (5 min)
```

- **Step**: cell index plus the literal serialized step text. The user sees
  exactly what the recipe wrote, including the namespace it chose.
- **Key**: uid/label, kind badge (§28b), kind-formatted fingerprint,
  protection badge. The fingerprint is the identity claim; it renders in
  full on hover/expand, truncated with the head visible otherwise.
- **Payload**: byte count and the SHA-256 of the exact bytes that will be
  signed or decrypted. When the payload is text, **show payload** expands
  the first 256 characters inline — a digest alone is honest but
  unauditable; a preview is what lets a human notice "that is not my commit
  message". For binary payloads the digest and length are all there honestly
  is, and the banner says "binary payload — digest only".
- **Namespace** (sshsig only), with the one-line explanation of why it
  matters. For `format=gpg`, the line is **Mode** (`cleartext`/`detached`)
  instead.

For `agent.decrypt` the payload line reads "Ciphertext · N bytes · sha256 …"
and there is no preview (previewing ciphertext is noise).

### §27c Approve, deny, and the session grant

Three outcomes, two buttons and a checkbox:

- **Deny** (ghost weight) — the op fails loud with the §31c error; the run
  stops at this cell like any failed step. Deny is never remembered: a
  re-run asks again, because the recipe may have changed.
- **Approve once** (secondary weight, the visually primary action) —
  authorizes exactly this request: this key, this payload digest, this
  step. The next request, even an identical one, asks again.
- **□ for this session** — a checkbox modifying Approve, not a third
  button, so the strong default (once) stays the easy path. Checked, the
  grant is scoped to **(key id × kind of use × this notebook session)** and
  expires with the agent session TTL (`VAULT_SESSION_TTL_MS`, 5 min, the
  same clock as the unlock cache in `vault-session.js`) or with **Clear
  sensitive data** / **Lock** / idle scrub, whichever first. "Kind of use"
  is sign-vs-decrypt; a session grant for signing does not cover
  decryption.

An active session grant is *visible*: the Keyring tray row for that key
(design v2 tray, ToolkitShell keys tab) shows `approved: sign · 3 uses ·
4:12 left` beside the existing unlocked countdown, and its **Lock** button
revokes both the grant and the cached unlock. A grant that cannot be seen
or revoked is a rubber stamp with extra steps; this one is a visible,
counting, expiring object.

Honesty note, stated in the UI copy the first time the box is checked:
*"While this lasts, recipes in this notebook can use the key without
asking."* That is what the user asked for; the design's job is to make sure
they asked for it knowingly and can watch it being used (the use counter
ticks live).

### §27d Loops, and the buried-`agent.sign` attack

A `foreach` body containing a boundary op fires one request per item. The
banner must neither collapse these silently (that is the rubber stamp) nor
fire twelve identical modals (that is click-through training). Design:

- The first request in a run announces the run's total when it is knowable:
  at the moment a `foreach` executes, the collection length is known, so the
  header reads **"request 1 of 12 this run"** and a third action appears:
  **Approve the remaining 11** — scoped to *this run only*, this key, this
  op. It dies with the run; it never outlives Cancel or an error.
- Requests *outside* a known loop just count up ("request 3 this run") with
  no batch offer — a linear recipe asking three times is three decisions.
- The per-run batch is deliberately weaker than the session checkbox: it
  cannot be minted before seeing the first real payload of the loop, so a
  malicious recipe cannot pre-authorize; the user has seen one
  representative payload and the loop's true count before being offered the
  shortcut.

The buried-op attack in full: a shared recipe hides
`… | foreach` / `- agent.sign SHA256:… namespace=file | quorum.send …` deep in
a chain. Defenses, in order: the boundary chip is visible in the pipeline
like any chip (no invisible steps exist in this UI — Source view and chips
both render every step); the *first* use still asks, naming key, payload,
count; the batch grant requires the count be shown; the session grant
requires a deliberate checkbox whose consequences are stated; and every use
increments a visible counter on the Keyring row. What the design cannot do
— and says so — is protect a user who approves without reading. There is no
UI cure for that; there is only making the reading short and the facts
load-bearing.

### §27e Passkey-protected keys

For a `protection: "passkey"` key the WebAuthn ceremony is the *unlock*,
not the *approval* — the authenticator prompt cannot display what is being
signed, so it must never be the only gate. Sequence: banner first (the
pinentry text), then **Approve once** launches the PRF ceremony inside the
click's transient activation (same rule as the clipboard gate); the OS
prompt is the proof of presence, the banner was the informed consent. With
a session grant, the first approval runs the ceremony and caches the
unlocked key in the agent session (armored key in `vault-session.js`, never
in the pipeline); subsequent grant-covered uses touch neither the
authenticator nor the user — which is exactly what the checkbox said would
happen, and why it expires in five minutes.

Device/passphrase keys skip the ceremony step; passphrase keys resolve the
S2K passphrase through the existing Inputs binding
(`bindings.inputs.agent.passphrase`), asked for by the readiness system
before the run starts, as today.

### §27f Headless: the CLI does not pretend

The browser vault does not exist in Node; CLI keys arrive via
`--private-key` (or the future CLI store, §30d). Two honest positions:

- **`basilisk run` with a boundary op**: possession of the key file plus
  the explicit flag *is* the consent — an interactive approval replay in a
  terminal the user is already typing into would be theater. But it must be
  explicit: a recipe containing `agent.sign`/`agent.decrypt` **refuses to
  run** (exit 3, message names the flag) unless invoked with
  `--approve <keyid>[:sign|decrypt]` (repeatable) or `--approve-all`. Every
  boundary use then prints one audit line to stderr:
  `agent.sign: key SHA256:Ur1h… payload sha256:1a2b… namespace=git`. The
  flag is the approval moment moved to the command line, where a script
  author states intent once, visibly, in the invocation that ends up in CI
  config and shell history — which for *this* flag is a feature.
- **`basilisk agent --ssh` (the socket server, §30c)**: per-key `confirm`
  flag mirroring `ssh-add -c`. With a TTY, a confirm-flagged key prompts on
  the terminal per signature (key, client pid if the platform exposes it,
  payload digest); without a TTY, a confirm-flagged request fails with
  `SSH_AGENT_FAILURE` and a stderr line — refusing is the correct headless
  degradation for a gate whose whole point is a human. Non-confirm keys
  sign silently, exactly as OpenSSH's agent does; matching the established
  tool's default is the least-surprise choice, and `confirm` is the opt-in
  hardening, same as upstream.

`--approve` takes the key id (either fingerprint format); the optional
`:sign`/`:decrypt` suffix scopes it, mirroring §27c's kind-of-use scoping.

---

## §28 My Keys, multi-kind

### §28a The record

Vault records gain `kind: "pgp" | "ssh" | "raw"`; absent means `pgp`
(legacy). The id (store keyPath, `fpr=` value, display identity) is
kind-shaped:

| kind | id | display |
|------|----|---------|
| `pgp` | 40+ hex OpenPGP fingerprint | grouped hex (`nb.formatFingerprint`), as today |
| `ssh` | `SHA256:` + unpadded base64 of SHA-256 over the RFC 4253 public blob | verbatim, monospace, never grouped — `SHA256:Ur1hPKBrJC3z…` |
| `raw` | `SHA256:` over the SPKI DER, prefixed `spki:` in meta | verbatim |

This matches what `ssh-keygen -lf` prints, so a user can compare the row
against their server's log line character for character. Implementation
flag (see status doc): `normalizeVaultFingerprint` strips non-hex today and
must become kind-aware — base64 ids contain `+/` and case matters.

`agent.save` accepts `keypair` input in addition to `openpgp-key`: a
WebCrypto keypair whose algorithm maps to an SSH type
(ed25519, ec/p256/384/521, rsa) saves as `kind: "ssh"`; anything else
(x25519, aes, hmac) saves as `kind: "raw"` — storable and exportable but
listed without SSH affordances. The wrap layer is untouched: it encrypts an
opaque payload and never cared what it wrapped (BRIEF §3). For non-PGP
kinds the stored payload is the openssh-key-v1 text (ssh) or PKCS#8 PEM
(raw), and `publicArmored`'s counterpart is `publicLine` (the
`ssh-ed25519 AAAA… comment` string) / SPKI PEM.

### §28b The listing

One list, not per-kind tabs — a vault with three keys does not need
navigation, and the mixed list is what makes the kinds legible side by
side. Applies to both surfaces: the My Keys page
(`lib/my-keys-mount.js`, vanilla) and the Keyring tray tab
(`ToolkitShell`). Each row:

```
[PGP]  Justin Capella <justin@…>          passphrase
       AABB CCDD EEFF 0011 2233 …                      Unlock · Export · Delete

[SSH]  justin@workstation (ed25519)       passkey ✓verified
       SHA256:Ur1hPKBrJC3zF0Qw9pLmXaY…    ⧉ public line   Unlock · Export · Delete

[RAW]  x25519 keypair                     device-only
       spki:SHA256:9dQw4w9WgXcQz…                          Export · Delete
```

- **Kind badge**: closed vocabulary as `data-key-kind="pgp|ssh|raw"` with
  enumerated CSS. Tones: `pgp` → `--decode` (the OpenPGP purple the toolbox
  already owns), `ssh` → the new ssh toolbox accent (§29b), `raw` →
  `--muted-foreground`. Badge text is the kind, uppercase, 9px — same
  chip anatomy as the existing protection badges.
- **Protection badges** unchanged (device/passphrase/passkey + soft MDS
  descriptor). One honest constraint: passphrase mode for `ssh`/`raw` kinds
  is **unavailable at launch** — today's passphrase mode is OpenPGP S2K on
  the armor, which non-PGP payloads do not have, and encrypted
  openssh-key-v1 needs `bcrypt_pbkdf` (deferred, BRIEF scoping note). The
  radio renders disabled with: *"Passphrase protection for SSH keys needs
  an encryption this browser build does not ship yet — use passkey or
  device protection."* No silent fallback.
- **⧉ public line** (ssh rows only): one click copies the full OpenSSH
  public line — the single most common SSH key operation (authorized_keys,
  GitHub, `allowed_signers`). It sits on the row, not behind Export,
  because it is public material and the frequent path; Export remains the
  gesture for anything private. Confirmation is the existing
  clipboard-wrote toast weight.
- **Fingerprint copy**: the existing copy affordance, copying the id in
  its display format (hex for pgp, `SHA256:…` for ssh).

### §28c `agent.list` output

The JSON rows gain `kind` and, for ssh rows, `publicLine`. The artifact
tile renders as rows rather than raw JSON — kind badge, id in kind format,
protection, lastUsedAt — reusing the row anatomy above at tile scale
(the `NetworkArtifact` precedent: typed artifacts render as read-outs, not
JSON dumps). `meta.vaultList` already marks the artifact; the widget keys
off it. Raw JSON stays one toggle away (the tile's existing raw view), and
the CLI prints the JSON unchanged.

### §28d Unlock semantics per kind

Unlock (row button or session cache fill) produces: pgp → armored private
key (as today); ssh → openssh-key-v1 text; raw → PKCS#8 PEM.
`agent.unlock` on a non-PGP key emits `keypair` (materialized CryptoKey
pair) rather than `openpgp-key` — the honest type for what it is, and it
flows into `sign`/`ecdh`/`export` with no casts. The §26c
`data-key-exposed` treatment applies identically; a leaked SSH key is not
less leaked for being newer.

---

## §29 The `ssh.*` op family

### §29a Shape of the family

Five ops, pure JS end to end (the math is `@noble/curves` + SubtleCrypto;
the encodings are byte-shuffling), so every one runs headlessly in the CLI
— interop-testable against `ssh-keygen` on any developer machine.

| Op | In → out | One line |
|----|----------|----------|
| `ssh.encode` | keypair/key → text | OpenSSH public line, or (explicit) unencrypted openssh-key-v1 |
| `ssh.decode` | text → keypair/key | Public line or openssh-key-v1 PEM back to a live key |
| `ssh.fingerprint` | keypair/key/text → text | `SHA256:…`, matching `ssh-keygen -lf` |
| `ssh.sign` | text/bytes → text | sshsig armor (`ssh-keygen -Y sign`), key from a slot |
| `ssh.verify` | text/bytes → bool | sshsig check, fail-loud, `-q` soft |

`ssh.sign key=@slot` is the *pipeline* primitive — the key rides a slot,
same trust model as `gpg.sign key=@me`. The vault-boundary spelling is
`agent.sign format=ssh` (§26f). Both exist on purpose: the primitive is
composable and CLI-native; the boundary op is the recommended one when the
key lives in My Keys. Their tool cards cross-reference each other.

### §29b Placement: a top-level `ssh` toolbox

The brief left placement open (`encoding` vs `webcrypto`). Decision: a new
top-level toolbox, for the same reason `age` got one (registry comment at
`TOOLBOX_META.age`): SSH is a different wire format with a different key
container, and filing `ssh.sign` under WebCrypto's Sign shelf would imply
`sign` and `ssh.sign` are variants of one thing when they share nothing but
a verb. Splitting encode/decode into `encoding` and sign/verify into
`webcrypto` — the other candidate — scatters a five-op family across two
drawers and was rejected on findability alone.

```js
ssh: { label: "SSH", badge: "SSH", order: 6, glyph: "ssh", color: "#39c5cf" },
```

Sits directly after `age` (order 6; `agent` and later each shift +1) — the
formats block reads OpenPGP · age · SSH · Agent, which is also the
conceptual gradient from message format to file format to wire format to
keystore. The accent `#39c5cf` (teal) is new to the toolbox palette;
per the CSP rules it must be added to both `TOOLBOX_META` and the
enumerated `[data-toolbox-dot]` rules in `toolkit.css`
(`toolbox-dot-css.test.js` guards the pair).

Shelves:

```js
sshwire: { label: "Keys & wire", order: 0, glyph: "ssh-key" },   // encode, decode, fingerprint
sshsig:  { label: "Sign",        order: 1, glyph: "sign" },      // ssh.sign, ssh.verify
```

CAST: `toolboxToSuite` maps `ssh` → `"webcrypto"` — the signatures and key
material are SubtleCrypto/@noble math, which is the suite the self-test
actually qualifies. The dot on the SSH header therefore states a true
claim about the math; the *encodings* are not CAST's job and get exhaustive
verb-smoke plus interop fixtures instead (§29g).

### §29c Types

Three refined `text` kinds, following the JOSE precedent (`text/jws` — a
string on the wire needs no new base type):

- `text/ssh-public` — the single-line `ssh-ed25519 AAAA… comment` form
- `text/ssh-private` — an `-----BEGIN OPENSSH PRIVATE KEY-----` block
- `text/sshsig` — an `-----BEGIN SSH SIGNATURE-----` block

Producers/consumers derive from STEPS as always; `type-registry.js` gets
the three cards.

### §29d Registry entries (normative)

```js
{
  name: "ssh.encode",
  kind: "transform",
  toolbox: "ssh",
  shelf: "sshwire",
  conjugate: "ssh.decode",
  pairCaption: "Encode / decode",
  glyph: "ssh-key",
  doc: "Encode a keypair/key as OpenSSH — `format=public` (default) emits \
the one-line public form (`ssh-ed25519 AAAA… comment`) for authorized_keys \
/ GitHub; `format=private` emits an **unencrypted** openssh-key-v1 block \
and warns (§29f). ed25519, ec/p256|384|521, rsa. Example: \
`genkey ed25519 | ssh.encode comment=\"you@host\" | out @pub`.",
  input: "keypair",
  output: "text",
  params: [
    { name: "format", type: "enum", default: "public",
      enum: ["public", "private"],
      doc: "public = one-line public key; private = unencrypted openssh-key-v1 (explicit only, never a default)" },
    { name: "comment", type: "string", default: "",
      doc: "Trailing comment on the public line (openssh-key-v1 carries it too)" },
  ],
  overloads: [
    { when: { base: "keypair" }, output: { base: "text", kind: "ssh-public" } },
    { when: { base: "key" }, output: { base: "text", kind: "ssh-public" } },
  ],
},
{
  name: "ssh.decode",
  kind: "transform",
  toolbox: "ssh",
  shelf: "sshwire",
  conjugateOf: "ssh.encode",
  glyph: "ssh-key",
  doc: "Decode an OpenSSH public line or (unencrypted) openssh-key-v1 \
private block into a live key/keypair. Passphrase-protected private files \
are refused by name — see the tool card for why (§29f). Example: \
`input | ssh.decode | ssh.fingerprint | out @fp`.",
  input: "text",
  output: "keypair",
  overloads: [
    { when: { base: "text", kind: "ssh-public" }, output: { base: "key" } },
    { when: { base: "text", kind: "ssh-private" }, output: { base: "keypair" } },
    { when: { base: "text" }, output: { base: "keypair" } },
  ],
  params: [],
},
{
  name: "ssh.fingerprint",
  kind: "transform",
  toolbox: "ssh",
  shelf: "sshwire",
  glyph: "fingerprint",
  doc: "SHA-256 fingerprint of an SSH public key — `SHA256:` + base64, \
byte-identical to `ssh-keygen -lf`. Accepts a keypair, a key, or a public \
line. Example: `input | ssh.decode | ssh.fingerprint | out @fp`.",
  input: "keypair",
  output: "text",
  overloads: [
    { when: { base: "keypair" }, output: { base: "text" } },
    { when: { base: "key" }, output: { base: "text" } },
    { when: { base: "text", kind: "ssh-public" }, output: { base: "text" } },
  ],
  params: [],
},
{
  name: "ssh.sign",
  kind: "transform",
  toolbox: "ssh",
  shelf: "sshsig",
  conjugate: "ssh.verify",
  pairCaption: "Sign / verify",
  glyph: "sign",
  doc: "Sign the payload in sshsig format (`ssh-keygen -Y sign`) — also how \
git signs commits with SSH keys. `namespace=` is part of what is signed: a \
`git` signature can never verify as a `file` signature. Key from a slot; \
for a My Keys key prefer `agent.sign format=ssh` (§26). Example: \
`input | utf8 | ssh.sign key=@id namespace=git | out @sig`.",
  input: "text",
  output: "text",
  params: [
    { name: "key", type: "slot", default: "",
      doc: "Private key slot — a keypair, or `ssh.decode` output" },
    { name: "namespace", type: "string", default: "file",
      doc: "Signature domain (`file`, `git`); verifier must name the same one" },
    { name: "hash", type: "enum", default: "sha512", enum: ["sha512", "sha256"],
      doc: "Payload hash inside the sshsig envelope (ssh-keygen default: sha512)" },
  ],
  overloads: [
    { when: { base: "text" }, output: { base: "text", kind: "sshsig" } },
    { when: { base: "bytes" }, output: { base: "text", kind: "sshsig" } },
  ],
},
{
  name: "ssh.verify",
  kind: "transform",
  toolbox: "ssh",
  shelf: "sshsig",
  conjugateOf: "ssh.sign",
  glyph: "sign",
  doc: "Verify an sshsig signature over the pipeline payload \
(`ssh-keygen -Y verify`). `signature=@slot` holds the sshsig block, `key=` \
the public line or a slot; `namespace=` must match the signer's. Fail-loud; \
`-q` emits bool false instead. Example: \
`in @msg | ssh.verify key=@pub signature=@sig namespace=git | out @ok`.",
  input: "text",
  output: "bool",
  params: [
    { name: "key", type: "slot", default: "",
      doc: "Signer's public key — slot, or the literal public line" },
    { name: "signature", type: "slot", default: "",
      doc: "Slot holding the sshsig block" },
    { name: "namespace", type: "string", default: "file",
      doc: "Must equal the namespace the signature was made under" },
    { name: "soft", type: "bool", flag: "-q", default: false,
      doc: "Soft mode: emit bool true|false (never throw on bad signature)" },
  ],
  overloads: [
    { when: { base: "text" }, output: { base: "bool" } },
    { when: { base: "bytes" }, output: { base: "bool" } },
  ],
},
```

`STEP_GLYPHS`: `"ssh.encode": "ssh-key"`, `"ssh.decode": "ssh-key"`,
`"ssh.fingerprint": "fingerprint"`, `"ssh.sign": "sshsig-sign"`,
`"ssh.verify": "sshsig-sign"` (conjugates share one asset; direction is the
tile tint, per the existing convention).

### §29e Glyphs

| Id | Metaphor |
|----|----------|
| `ssh` (toolbox) | Terminal prompt chevron `>` with a horizontal key lying along the baseline to its right — "the shell's key". Distinct from `webcrypto`'s browser-window-plus-key: no window chrome, just prompt and key. |
| `ssh-key` | A key whose shank trails into three small linked rectangles — the RFC 4253 blob is literally a chain of length-prefixed fields, and the chain-of-blocks reads as "wire format" at 20px. |
| `sshsig-sign` | The `sign` quill stroke with a small `>` chevron tucked in the lower-left corner — the established signature metaphor, marked as the shell's. |

`ssh.fingerprint` reuses the existing `fingerprint` ridge-arc glyph — the
metaphor is format-agnostic and a second fingerprint icon would split it.

### §29f Deliberate omissions, and the warning that ships instead

Stated in the tool cards and this handoff so absence reads as decision:

- **Encrypted openssh-key-v1** (read and write): the KDF is
  `bcrypt_pbkdf`, which no Web API provides. `ssh.decode` refuses a
  passphrase-protected block with: *"This key is passphrase-protected with
  bcrypt, which Basilisk cannot run yet. Decrypt it outside
  (`ssh-keygen -p -N \"\"`) or import the key another way."* Write side:
  `ssh.encode format=private` is unencrypted only, and says so (below).
  Vault-side protection (§28) is the story for keys at rest; `bcrypt_pbkdf`
  lands later if demanded.
- **MD5 fingerprints** (`ssh-keygen -E md5`): legacy display format,
  omitted rather than shipped discouraged — nothing in this toolkit
  consumes it and emitting it invites pasting it somewhere load-bearing.
- **`allowed_signers` / principal matching** (`ssh-keygen -Y verify -f`):
  `ssh.verify` takes an explicit key. The principals file is policy, not
  cryptography; if it comes, it comes as a separate lookup op, not a param.
- **Certificates** (`ssh-ed25519-cert-v01…`), **DSA** (never), **FIDO sk-**
  key types (the browser cannot reach the authenticator the way OpenSSH
  does — `webauthn.*` is the browser-native equivalent).

**Unencrypted private export warning** — `ssh.encode format=private`
produces a compile warning and its artifact tile carries a warn-toned row
(same anatomy as the discouraged-algorithm tags, RECIPE.md):

> **Unencrypted private key.** This block has no passphrase — anything
> that can read this tile, your clipboard, or the saved file can use the
> key. Vault protection does not travel with an export. Prefer keeping the
> key in My Keys and signing with `agent.sign`.

The output is `sensitive: true` (masked, reveal-gated) like every private
artifact.

### §29g CAST / verb-smoke coverage

- Every `ssh.*` op and every enum value (`format=public|private`,
  `hash=sha512|sha256`, `-q`) appears in a compiling, running recipe in the
  verb-smoke catalog — `recipe-verbs.test.js` enforces this mechanically.
- Interop fixtures, checked in and byte-asserted (the `age-ops.test.js`
  precedent — assert the wire format, not a round trip through one
  library): an `ssh-keygen`-generated keypair per algorithm with its known
  public line and `SHA256:` fingerprint; an `ssh-keygen -Y sign` sshsig
  block that `ssh.verify` must accept; and — because RFC 8032 ed25519 is
  deterministic — an ed25519 `ssh.sign` output byte-compared against
  `ssh-keygen`'s for the same key, payload, and namespace.
- Round trips: `ssh.encode | ssh.decode` restores a working key (sign +
  verify through it); `genkey` × every mapped algorithm.

---

## §30 Agent status surface

### §30a Where it lives: the Keyring tray, not the TopBar

"Agent: N keys unlocked · soonest expiry" renders as one line in the
**Keyring tray tab header**, under the existing "Keyring" heading, fed by
`sessionList()` (data that exists today). The tray is where every fact it
summarizes already lives — per-key countdowns, Lock buttons, §27c grant
rows — so the summary sits one glance above its details.

Rejected: the TopBar. It carries exactly one status object (the worst-tone
suite pill, design v2 §21e) and its restraint is why that pill is legible;
a second live readout starts the accretion that ends in a system tray.
Rejected: the drawer (ops shelf) header — the shelf is about *available
ops*, not session state, and the CAST light already occupies its one
status slot with a different kind of claim.

When nothing is unlocked and no grants exist, the line is absent — not
"agent: idle". An indicator that is always present and never means
anything is how signals die (the CastDot comment says it best).

### §30b What the browser can honestly say about the CLI agent

Nothing, until something tells it — and phase 1 ships exactly that:
**no browser surface claims CLI agent state**. No "agent offline" badge
(the browser cannot distinguish offline from never-existed), no stale
"last seen". The CLI is self-serving for status:

```
$ basilisk agent --status
agent: running (pid 4211, \\.\pipe\openssh-ssh-agent)
  3 keys · SHA256:Ur1h… (ed25519, confirm) · SHA256:9dQw… (rsa) · …
  last signature 2m ago (SHA256:Ur1h…, namespace git)
```

### §30c The socket server, minimally

`basilisk agent --ssh` binds `$SSH_AUTH_SOCK` (Unix) or
`\\.\pipe\openssh-ssh-agent` (Windows), answers
draft-miller-ssh-agent (request-identities, sign-request; add/remove if
keys are loaded at runtime), backed by keys loaded from a recipe run or an
`agent.save`-style CLI store. Per-key `confirm` per §27f. Everything else
about it is implementation, not UX — the one designed surface is the
status output above and the confirm prompt.

### §30d The mesh-forwarding phase (designed now, built later)

When forwarding lands, the status channel is **the quorum mesh roster** —
no new transport, no polling endpoint. The CLI agent joins the room as a
peer whose roster entry carries `role: "agent"`; the existing
`basilisk:quorum-state` event delivers it, and the Connections tray renders
it as a peer row (badge "agent", key count, same
connectivity-vs-authentication split every peer row already has —
THREAT-MODEL: the two are never conflated). A sign request arriving from
the CLI rides the sealed-envelope path and surfaces as a §27 approval
banner — pinned to the Connections tray rather than to a cell, since no
cell asked — with one extra line naming the requesting peer's verified
identity. Approval releases the signature back over the same channel; the
passkey-protected vault is the approver, which is the gpg-agent-forwarding
analogue the brief names.

Until that phase, the design deliberately shows nothing rather than a
placeholder: a dead "agent" row in Connections would be the decorative
indicator §30a just argued against.

---

## §31 DSL touches

### §31a Recipe surface

- `agent.sign` / `agent.decrypt` serialize like any step; `fpr=` values are
  public identifiers (a fingerprint is the thing you print on a business
  card) and ride Copy link / Export / the workspace library freely — the
  same reasoning that made `age.encrypt to=` a string while `age.decrypt
  key=` is a slot (HANDOFF). SSH ids containing `+`/`/` serialize quoted:
  `agent.sign "SHA256:Ur1h…"`.
- `namespace=` is a real param on `agent.sign` and `ssh.sign` (§26f, §29d),
  default `file`. It appears in the approval banner verbatim because it is
  part of what is signed.
- No recipe syntax exists for pre-granting approval — deliberately. A
  recipe that could carry `approve=session` would be a recipe that
  authorizes itself; approval lives only in the UI (§27c) and the CLI
  invocation (§27f).
- Run receipts: a boundary op's output digest already lands in
  `run.receipt` like any step output. Approval events are session UI, not
  run data, and are not receipt material — noted here so nobody adds them
  "for completeness" and turns the receipt into a consent log it was never
  designed to be.

### §31b How approval interacts with `run`

Run all / Run from here proceed cell by cell as today; a boundary op
pauses its cell in `waiting-approval` (§27a). Cells before it are
committed; cells after it wait, exactly like `waiting-peer`. Cancel (the
RunBar's existing gesture) resolves the pending request as a deny without
recording anything. A session grant (§27c) lets the run pass the gate
without pausing — the RunBar never enters `waiting-approval` and the
Keyring counter ticks instead.

### §31c Error copy (exact strings)

| Condition | Message |
|-----------|---------|
| Denied in UI | `agent.sign: approval denied — nothing was signed. (key SHA256:Ur1h…, payload sha256:1a2b…)` |
| Cancelled with the run | `agent.sign: run cancelled while waiting for approval — nothing was signed.` |
| Idle scrub while waiting | `agent.sign: the idle scrub ended this session while approval was pending — run again to re-request.` |
| Headless, no flag | `agent.sign needs per-use approval, which has no interactive surface here. Re-run with --approve SHA256:Ur1h…:sign (or --approve-all) to consent on the command line.` (exit 3) |
| Wrong kind | `agent.decrypt: key SHA256:Ur1h… is an SSH signing key — it cannot decrypt. Only pgp-kind keys decrypt.` |
| Namespace mismatch (`ssh.verify`) | `ssh.verify: signature was made under namespace "git", but namespace="file" was requested — a signature never transfers between namespaces.` |

The denial strings name the key and digest so a transcript of a refused
run is still an audit record of *what asked*. All follow the codebase's
error voice: state what happened, what did not happen, and the one next
step.

### §31d Migration

No retired names, no aliases (`agent.sign` is new). `migrateRecipe` needs
no entry. The one guard: `agent.unlock … | gpg.sign key=…` remains fully
valid and un-warned in the *validator* — the steer is docs, shelf order,
and the §26c underline, not a lint. A recipe that legitimately exports a
key must not compile noisily; noise there would teach users to ignore the
treatments that matter.
