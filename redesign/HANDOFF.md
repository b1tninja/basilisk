# Basilisk Toolkit — handoff

For an agent picking this up cold. Everything here is either non-obvious or
was learned the hard way; the rest you can read from the code faster than I
can describe it.

Repo: `b1tninja/basilisk`, branch `feat/toolkit-redesign`, work in `web/`.

---

## What it is, in one paragraph

A browser-only cryptography notebook. You write a **recipe** — steps joined by
`|` — and each cell runs it against WebCrypto / OpenPGP.js / WebRTC and
produces artifacts. Nothing server-side holds key material.

```
genkey ec/p256 | export spki | pem | out @pub
random 32 | encode base64 | out @cek
```

118 steps across 14 toolboxes, 23 pipeline types, 32 widgets.
(Counted from the registry: `STEPS.length` and `Object.keys(TOOLBOX_META)`. If
you change either, recount rather than adjusting by hand.)

---

## The three things most likely to trip you

**1. The dev server's CSP is weaker than production.** Strict CSP breaks HMR,
so `basilisk-dev-server.js` relaxes `script-src`/`style-src` for `serve`. This
means a CSP violation can be *invisible in dev and fatal in the build*. That is
how 23 inline styles accumulated behind a test literally named
"no-inline-styles". The production policy now also rides along **report-only**
(HTTP header — the `<meta>` form of report-only is parsed and then ignored by
every browser), and `lib/boot-diagnostics.js` reports those as "would break in
production" rather than as live failures. If you add a page, add the header.

**2. Verify in the browser, not by reading the diff.** Several things in this
session type-checked, built, passed tests, and were still wrong: a suggestion
that offered `aes-cbc` as the fix for "add export pkcs8"; a `key` prop React
silently consumed; a peer filter matching a field that did not exist. The
catalog at `/toolkit-widgets` is the cheapest way to see a widget's real states
— twice it exposed defects nothing else caught. Add a section for any widget
you create.

**3. `screenshot` compositing is unreliable here.** Assert with
`getComputedStyle`, DOM queries, and geometry instead. "Measured the colour"
beats "looks right", and it is what caught the expiry-escalation and peer-dot
states being correct.

---

## Invariants someone will otherwise break

- **Three layers, not two: `rtc.*` raw, `peer.*` managed, `quorum.*` the
  identity-bound mesh — and an op lives in the layer that owns the key it
  uses.** `quorum` owns `offer`/`join`/`close` — room, roster, lifecycle — *and*
  `quorum.send`/`quorum.recv`, because that traffic is encrypted and decrypted
  under the pairwise session key `derivePairwiseSessionKey` mints. **`peer.*` is
  the middle layer added in §55**: named connections that outlive the op that
  made them, so two browsers can connect with no PGP audience and no relay;
  `peer.send`/`peer.recv` are its raw verbs, DTLS and nothing else.

  **The drawer now matches the layering, and this is a second axis — read it
  as one.** `rtc.*`, `peer.*` and `stun.check` are the `webrtc` toolbox; the
  five `quorum.*` ops are the `quorum` toolbox directly beneath it. The test is
  whether an op is a WebRTC built-in, and quorum is a *consumer* of WebRTC
  rather than a division of it: design as though quorum did not exist and the
  WebRTC surface must still stand on its own. `lib/webrtc/` is the same
  statement in code — link registry, ICE defaults, negotiation rule and
  candidate stats live there and quorum imports them, where previously
  `lib/toolkit/peer-ops.js` had to import `lib/quorum/` to run an op with no
  PGP audience in it. `dkg.run` went to `sss`, beside the `vss.*` ops whose
  Feldman VSS over P-256 it runs.

  **No op was renamed and none should be.** `rtc.*` *is* the spec's prefix —
  `RTCPeerConnection`, `RTCCertificate`, `RTCDataChannel` — so inventing a
  `webrtc.*` namespace would move these names away from the specification's own
  vocabulary, not toward it. `step-names.js` was untouched.

  Two consequences that bite if you do not know them:

  - **`rtc.offer`/`rtc.answer` no longer exist.** They are `peer.offer` /
    `peer.answer`, retired and migrated, because each closed the very
    `RTCPeerConnection` whose SDP it returned — two shipped templates described
    a flow that could not complete.
  - **The five diagnostics enumerate the link registry, not the mesh.**
    `rtc.state`/`check`/`stats`/`quality`/`restart` used to open with
    `requireSession()`, so the mesh *was* the definition of "what is connected"
    and they refused outright for anything else. `QuorumSession` registers its
    peers into `lib/quorum/link-registry.js` now. `getLiveSession()` survives
    for the DKG transport and the roster projection; it is no longer how the app
    answers that question.

  Full argument in `redesign/design_handoff_peer_connections/`.

  **Do not re-split the channel ops out of `quorum.*`; it was tried.** They were
  `rtc.send`/`rtc.recv` for several turns, on the reasoning that reading and
  writing a data channel is a transport primitive and `quorum.*` should cover
  only the exchange. The stated payoff was that they would then "work on any
  data channel rather than being married to a quorum room". That payoff never
  existed: both names always dispatched to `execQuorumSend`/`execQuorumRecv`,
  which open with `requireExchange`, address peers by PGP fingerprint, and
  encrypt under the pairwise session key — `rtc.send`'s own doc string said
  *key-confirmed channels only* for the whole of its life. §55c then made the
  contradiction explicit by declining to widen them to `peer.*` links for
  exactly that reason, which left a transport-named op that could not be used at
  the transport layer. The names went back. What the split was reaching
  for is real and now exists separately: `peer.send`/`peer.recv` are the verbs
  that do work on any managed channel, and their namespace is the warning that
  nothing authenticates the far end.

  **This block is about the op *namespace*. Do not read the toolbox split above
  as a partial reversal of it.** They answer different questions and the
  answers point in different directions, which is exactly why conflating them
  re-derives the wrong lesson. The namespace question is *whose key protects
  this traffic* — `quorum.send`'s, so it is `quorum.send`, permanently. The
  toolbox question is *which drawer category does a user look in* — the
  `webrtc` one is for WebRTC built-ins and a PGP-derived room is not one.
  `quorum.send` therefore keeps its name **and** its "Data channel" shelf and
  its two-arrow mark; only the category header above it changed. If a future
  turn cites the toolbox move as precedent for renaming the channel ops back to
  `rtc.*`, that is the mistake this paragraph exists to stop.
- **Types are three-way.** DATA is inert and publishable; HANDLE (`session`,
  `channel`) is a live object meaningful only inside the run that made it;
  OBSERVE (`connstate`, `stats`) is a read-out that can be displayed but never
  consumed. `resolveStepType` enforces it. Designs that ignore this produce
  screens the type system refuses to render.

  **Being a HANDLE is about what may consume a value, not about whether it may
  be drawn.** `channel` gained its first producer in `peer.wait` (§56) and is on
  `NETWORK_BASES` beside `session`, which has always been a handle with a tile.
  If you give a type a producer, the role and the renderer move in the same
  commit — a producer without the role stamps `text` on a live object, and a
  role without a renderer resolves to `network-value` and draws nothing.
- **`any` is a signature marker, not a value.** The universal passthroughs
  (`out`, `tee`, `peek`, `inspect`, `text`, `select`) declare `input: "any"`,
  stamped from `POLYMORPHIC_STEPS` in types.js. They previously claimed `bytes`
  while the checker special-cased them by name, so the type browser reported
  that *nothing* consumed `stats` or `candidate`.
- **Reveal is gated.** A sensitive artifact may be unmasked only when the author
  explicitly asked to see it — `out`, `text`, or `inspect` set `revealable`.
  Incidental tiles stay masked. Do not "fix" this by revealing everything.
- **Retired names are removed, not aliased.** `to`/`from`, `rtc.send`/`rtc.recv`,
  `hex`/`unhex` all fail live parse and are rewritten by `migrateRecipe` /
  Upgrade recipe. One name per operation.
- **Producers/consumers are derived from STEPS**, never hand-listed, so the
  type docs cannot claim an op that no longer exists.
- **Reference links live in `step-docs.js`**, not the registry — a URL is
  documentation, not part of a step's contract.
- **Three layers own an artifact, and a fact derived in two places is a bug.**
  The boundary is stated in full in the header of
  `lib/toolkit/artifact-readouts.js`; this is the short form.

  | Layer | Owns | Where |
  | --- | --- | --- |
  | **Engine** | *facts* — content, filename, mime, role, tags, traits, sensitive. Computed once, at emit. Digested by the receipt. | `engine.js` and the ops |
  | **Representation** | *read-outs* — what a human reads off those facts (fingerprint, key type, packet map, code + expiry instant), and how they are shaped. Pure, total, node-testable. Called by the card **and** by the action. | `lib/toolkit/artifact-readouts.js` |
  | **View** | *layout only* — where a read-out sits, what is masked, what a `publicView` may draw. No parsing, no derivation. | `toolkit/widgets/**`, `artifact-kinds/registry.tsx` |

  This was not a new idea; it was written down in one file and applied nowhere
  else, and **six defects in one session are traceable to its absence**:
  `publicOnly` captioning as well as hiding (a masked *private* tile said
  "public half"), `OpenPgpKeyCard` captioning a private key "public" whenever
  the lazy `openpgp` import had not resolved, the badge rendering the role while
  `resolvedKind.label` sat one line above (three roles were added partly to fix
  badge text), `glyph` declared on fourteen kinds and rendered by nothing, a
  second download namer nearly shipping, and two disabled reasons living as
  literals in `artifact-actions.js` beside the module that exists to hold them.

  **How a reviewer enforces it — three checks, in order.**

  1. **Does a widget parse?** Grep `toolkit/widgets/**` for `JSON.parse`,
     `atob`, `TextDecoder`, `readKey`, `await import(` of a codec, or a regex
     over `content`. Every hit is either a call into `artifact-readouts.js` or
     a defect. `InspectorArtifact`, `JwtArtifact` and `NetworkArtifact` render
     structured data the *engine* attached (`inspectSnapshot`, `jose`,
     `netData`) — there is nothing there to parse, so they are not exceptions.
  2. **Does one fact have two spellings?** Name the fact, then grep for it.
     "Which half is this OpenPGP armor" was answered in three places — the
     card's parse, `hasPrivateKeyMaterial`, and the engine's `openpgp`/`private`
     tags — which is how a private key captioned itself public. If two sites
     answer one question, one of them calls the other.
  3. **Does an action need what the card shows?** If a card displays a fact and
     an action's `available()` or `run()` needs the same fact, both reach it
     through the same exported function. `sshKeySummary` is the worked example:
     `SshKeyCard` draws it and `key.copyFingerprint` copies it.

  **A read-out reads `content`, `traits`, `role` and `tags`, and nothing else.**
  That is the boundary's answer to the mapped-shape trap below: those four are
  what all three hops carry, `traits` because it is the one open bag copied
  wholesale. A read-out that reaches for a named field can be silently
  disconnected by a projection nobody edited — `shareIdentity` reads
  `artifact.shareIndex`, no `ToolkitShell` mapping copies it, and the share tile
  only works because the function prefers `traits.shareOf`.

  **What it does not mean.** Not every parse in a widget is misplaced. A
  derivation with one consumer, whose output is only ever laid out, is view-local
  and moving it "on principle" would be a worse codebase than the scattering.
  The test is check 3: two consumers, or a fact an action also needs.

---

## Traps that look like bugs but are not, and vice versa

- **`applyCellRecipeText` used to reject any ill-typed recipe** — set a
  page-level error and never committed. So you could not *type* an ill-typed
  pipeline, which made the per-cell error banner unreachable from Source view
  by construction. Now only a *parse* failure is refused. If you find yourself
  unable to reproduce a validation state, check whether the editor is refusing
  the input.
- **`OutputList` resolves kinds against a *mapped* `OutputArtifact`, not the
  engine's artifact — and a field the mapper drops makes a feature silently
  inert while engine-backed tests stay green.** This is the single most
  expensive trap in this codebase: **four separate defects** so far. Read the
  next entry with it; they are one trap seen from two ends.

  There are **three** hops between an engine artifact and a tile, and each is
  an explicit field list that drops anything not named in it:

  1. `engine.js` emits a `ToolkitArtifact`.
  2. `useNotebook.ts`'s `cellOutputs` maps it to `ArtifactTile`
     (`notebook-types.ts`).
  3. **`ToolkitShell.tsx` maps *that* to `OutputArtifact`, twice** — the cell
     list and the tray Outputs tab, both `outputs={rows.map(...)}` on an
     `<OutputList>` — and it is this third shape that `resolveArtifactKind(...)`
     and every kind's `view` / `publicView` actually receive. (Grep
     `<OutputList` rather than trusting a line number; the file moves.)

  Every kind-matching test in the suite builds artifacts from `runRecipe` and
  resolves against the **engine** shape, which is the right call for the
  resolver and completely blind to hops 2 and 3. So a kind can match, render,
  and be asserted green in vitest while the shipped page resolves the same
  artifact to `FALLBACK_KIND` because hop 3 never copied the field it matched
  on. Nothing fails. The tile just quietly becomes the wrong tile.

  What survives by construction: **`traits`**, which is the one open bag every
  hop copies wholesale, and `tags` / `role`, which the registry matches on and
  which were added to all three lists when §32 landed. That is why
  `OTP_META_TRAITS` puts `otpStep`/`otpPeriod`/`otpLabel` in `traits` rather
  than in fields of their own, and why `notebook-types.ts` widened `traits` to
  `Record<string, unknown>`. **Put new artifact metadata in `traits` unless you
  have a reason not to** — and if you must add a named field, add it to all
  three lists in the same commit and then look at the page.

  Latent right now, as an example of the shape: `ShareIdentity` reads
  `artifact.shareIndex`, and **neither** `ToolkitShell` mapping copies it. It
  is harmless only because the engine also stamps `traits.shareOf`, which
  `shareIdentity()` prefers — the field is dead, and the bag saved it.

- **`useNotebook`'s `cellOutputs` projection copies named fields.** Anything the
  engine adds is silently dropped until listed there. Cost two debugging rounds
  on its own (`revealable`, `inspectSnapshot`) before `pipeType` — which had
  ridden on every artifact since the type system landed and was dropped here —
  turned out to be why the UI had grown `netType` / `jose` / `inspectSnapshot`
  as parallel discriminators for a discriminator it already had.

- **`runRecipe` and `compileRecipe` do not return what their names suggest, and
  both produced false passes this session.**

  - `runRecipe(ast, bindings)` returns **the artifact array directly**, not
    `{ artifacts }`. `const { artifacts } = await runRecipe(...)` gives
    `undefined`, and `(artifacts || []).find(...)` then finds nothing — which
    reads as "the recipe produced no such artifact" rather than as a typo.
  - `compileRecipe(source)` returns `{ ast, validation }`, and the errors are
    at **`result.validation.errors`**, not `result.errors`. Any "there are no
    errors" check written against the shallow path — `!result.errors?.length`,
    `expect(result.errors ?? []).toEqual([])`, a truthiness guard — passes
    vacuously on a recipe that does not compile at all.

  Both failure modes look identical from the test output: **an empty array read
  as "nothing wrong."** When a test asserting an absence passes on the first
  try, check the path it read before believing it.
- **`vitest.config.js` now mirrors vite's `@` alias.** Before, importing any
  component failed on `@/lib/cn`, so helpers had to be relocated to `lib/` just
  to be testable. They no longer do.
- **`fetchJson` assumed any 2xx body was JSON.** An SPA fallback answers 200
  with `<!DOCTYPE html>`, surfacing `Unexpected token '<'` for what is a routing
  failure. Fixed, but the pattern may exist elsewhere.
- **The engine withholds `inspectSnapshot` for sensitive values on purpose** —
  a snapshot retains raw private JWK fields the masked text dump does not. Its
  absence is a decision, not a gap.
- **No cell-writing mutation may read an ambient "current cell"** — `49cd286`.
  Every chip handler used to do `setFocusedCell(i)` and then call a mutation;
  the setter is React state and does not land until the next render, so the
  mutation ran in a closure where `steps` was still the *previously* focused
  cell's. With cell [0] focused, the x on cell [1]'s first chip deleted a step
  from cell [0]. Every cell-writing mutation now takes the cell as its **first
  argument** and reads through `stepsAt`; the two callers that genuinely mean
  "wherever the caret is" (the shelf append, the slot-tray Insert) pass
  `focusedCell` out loud at the call site, where it is a fact rather than a
  pending setter. If you add a mutation, give it the cell — do not reintroduce
  the ambient one.
- **A recipe that compiles must serialize back to a recipe that compiles** —
  `6d2faf8`. `serializeStep` quoted a positional only for whitespace, `|` or
  `=`, but a bare positional also has to *begin* the way the parser's argument
  loop expects: a letter, a digit, or `@`. So `file.read accept=.pem` — the
  op's own documented example — serialized bare and came back `Unexpected "."`.
  Not a rare path: the chip flow re-serializes on **every** mutation and Copy
  link serializes to build the URL. The durable half of the fix is a sweep that
  round-trips every self-contained `Example:` in the registry, so the next op is
  covered the day it lands. Verify a serializer change by removing the fix and
  watching the sweep fail, not by reading it.

---

## Verification workflow that works here

```bash
npx tsc --noEmit        # filter out pre-existing memory-safety.js noise
npm run build
npm test
```

**Baseline: green. Every test passes.** The three long-standing
failures (`conjugate-stitch`, `toolkit-engine`, `webauthn-mds`) were fixed —
and all three were **stale tests, not broken code**, which is why they
survived so long:

- `conjugate-stitch` string-matched `in @ct` after the serializer deliberately
  switched to the canonical bare `@ct` (RECIPE.md's own multi-chain examples
  use it). Now asserted on the parsed AST via a `loadsSlot` helper, so a
  future printer change cannot break it again.
- `toolkit-engine` used `out name=label`, retired from live parse when slot
  labels started requiring `@`. Recipes updated, plus a new test pinning the
  actual invariant: the legacy form must *fail* parse and be repaired by
  `migrateRecipe`, never silently aliased.
- `webauthn-mds` asserted `status === "true"`; the API returns
  `"verified" | "unverified" | "unavailable"` (a corrupted assertion — its
  sibling test had it right).

**Any failure is now a real one.** Do not re-introduce a tolerated baseline —
if a brief you were handed says "expect 3 pre-existing failures", it predates
this and is wrong.

Two gates will catch you and are worth knowing about rather than fighting:
`recipe-verbs.test.js` demands every op and every enum value appear in the verb
smoke catalog, and `no-inline-styles.test.js` is a ratchet with a per-file
baseline that may go down but never up.

---

## The agent boundary and SSH (§26–§31) — shipped, and what it changed

`redesign/design_handoff_agent_ssh/` is built end to end. Read that folder's
`IMPLEMENTATION-STATUS.md` for the unit-by-unit state and the four recorded
deviations; this section is only what a cold reader would otherwise get wrong.

**The vault is multi-kind now.** Records carry `kind: "pgp" | "ssh" | "raw"`
(absent means pgp — legacy records predate it). The id shape follows the kind:
hex for pgp, `SHA256:` + unpadded base64 for ssh, `spki:SHA256:` for raw.
**Two functions used to destroy the non-hex ids** by stripping non-hex
characters — `normalizeVaultFingerprint` and `formatFingerprint` — and four
more inline copies inside `vault.js` were the same bug waiting. They all route
through one normalizer now. If you add a vault lookup, do not hand-roll the
hex cleanup; `SHA256:Ur1h…` becomes `A256` and every lookup silently misses.

**`agent.sign` / `agent.decrypt` are the boundary ops, and the boundary is
literal**: the unlocked key lives in one call frame and is never bound to a
slot. That is why they resolve their own OpenPGP material instead of reusing
the engine's slot-based key path — do not "simplify" that into
`resolveGpgPrivateKey`, it would put the key in the pipeline and delete the
feature.

**The approval gate is designed against a malicious recipe, not a clumsy
user.** Nothing in recipe syntax can pre-grant approval; the per-run batch
cannot be offered until the first real payload and the loop's true count have
been shown; session grants are scoped to key × sign-vs-decrypt and are
visible, counting and revocable. `approval-gate.test.js` is adversarial on
purpose — if a change there makes a test feel pedantic, that test is the
feature.

**`ssh.*` interop is byte-asserted, not round-tripped.** Fixtures under
`web/src/test/fixtures/ssh/` came from real `ssh-keygen`; the directory is
pinned `-text` in its own `.gitattributes` because a CRLF conversion would be
silent test corruption. ed25519 sshsig output is compared byte-for-byte
against `ssh-keygen`'s (RFC 8032 is deterministic), so a change that still
"round-trips" can still be wrong.

**`basilisk agent --ssh` is a real ssh-agent** over `$SSH_AUTH_SOCK` (a named
pipe on Windows). It signs the raw RFC 4253 format the agent protocol carries,
**not sshsig** — sshsig is the detached-file envelope. Conflating the two is
the classic way an ssh-agent reimplementation passes its own tests and fails
against `ssh`.

**`saveKey` no longer downgrades key protection silently** — fixed in
`6b0ec96`. It used to `put` on a `fingerprint` keyPath without reading the
existing record, so re-saving a passkey-protected key as `device` produced a
record with **no outer PRF wrap at all**: the vault listed it as device and
`unlockKey` handed back the armored private key with no authenticator in the
loop. Nothing warned. `saveKey` now takes `onConflict`, and **the default is
the refusal** — an unspecified option must not be the one that weakens a key,
so a caller that means to has to say the word, and an unrecognized value throws
rather than falling through to the safe branch. Two details that are load-
bearing and easy to undo by "simplifying":

- **The read and the write share one transaction.** A check-then-save in the
  caller leaves open exactly the window a second tab enrols the passkey in,
  which is the case the guard exists for. The `put` is issued from the `get`'s
  success callback, and IndexedDB gives the atomicity for free.
- **Protection is read off the record's outer wrap, not its `protection`
  label.** The wrap is the property that actually holds; a hand-edited label
  must not be able to argue it away.

Only a genuine weakening counts (passkey > passphrase > device). Equal-protection
re-saves stay routine, because that is how `publicArmored` and the key-id
backfill land. `patchKeyMeta`, `touchKeyUsed` and `unlockKey`'s backfill never
rebuild the record, so they do not go through the guard — pinned by a test
rather than left as an assumption. `agent.save` passes `"replace"` on both its
paths; the `keyring.add` button passes nothing, and that asymmetry is the point.

**`bcrypt_pbkdf` is built** (`8ce5544`): `web/src/lib/ssh/bcrypt-pbkdf.js` over
its own `blowfish.js`, so encrypted `openssh-key-v1` blocks both **read and
write** (`aes256-ctr`, 48 derived bytes), with real `ssh-keygen` fixtures for
ed25519/ecdsa/rsa under `web/src/test/fixtures/ssh/`. Two things a cold reader
gets wrong here:

- **Passphrase protection now works for vault kind `ssh`, not for `raw`.** An
  ssh-mappable key stores as openssh-key-v1, which has a passphrase form; a
  `raw` key (x25519) stores as a bare private JWK, which has none. So the
  refusal survives for exactly that case, and `NON_PGP_PASSPHRASE_MESSAGE`
  names the kind rather than saying "SSH keys are not supported" — which was
  the old sentence and is now the wrong one.
- **`ssh.encode` still writes unencrypted, deliberately.** It has no
  `passphrase=` param: a recipe that silently produced a protected container
  would be a different artifact than the one it asked for. `agent.save
  protection=passphrase` is the op that writes a protected block.

Outstanding here:

- **`agent.list` has no typed tile** (§28c). The op emits `kind`/`publicLine`
  and the CLI shape is done; only the widget is missing. Confirmed still true:
  no kind in `artifact-kinds/registry.tsx` claims it.
- **Mesh forwarding of approvals** (§30d) is designed and unbuilt, blocked on
  the live two-browser mesh check that was already open.
- **CLI `--approve`** is deliberately *not* shipped: `basilisk run` refuses the
  whole `agent` toolbox at pre-flight (exit 4, verified) because Node has no
  vault, so the flag could never fire. Do not add it before the CLI key store.

## Artifact kinds and actions (§32–§46) — in progress

`redesign/design_handoff_artifact_actions/` (plus `visual/VISUAL-DESIGN.md`).
Shipped: the role vocabulary and projection floor, the kind resolver and
table, `OutputList` wired to it, the two tile foundations, the action tiers,
the key tiles (§35), the Activity log (§36), the rest of the inventory (§37 —
every role in `ARTIFACT_ROLES` is claimed, and `UNCLAIMED_ROLES` in
`artifact-kinds-table.test.js` is empty), `ArtifactTile` as its own component
(§33a), the `GateBanner` / `ConsequenceBanner` pair with Publish moved onto it
(§34c), and migration (§38, asserted in `artifact-migration.test.js`).

**`keyring.add` and Download are built too**, so unit 4 is nearly closed:
Download (`2dda2af`) through `download-service.js` — not `file.save`, whose
File System Access path opens a picker a tile should not — under the filename
the *engine* gave the artifact, corrected only where a kind declares
`download.ext`. `keyring.add` (`f800a9b`) once `saveKey({onConflict})` landed.
Three kinds arrived after the checklist was written because real artifacts were
landing on the wrong tile: `ssh-public` / `ssh-private` (`d379b3d`), `keypair`
(`83ef038`, the tip of a bare `genkey`, which used to be drawn by the card that
means "the public half"), and `otp-code` (`51a8cb1`).

**§34d's overwrite confirmation is not built and is no longer blocked** — what
shipped has no Replace to confirm. The vault refuses a weakening re-save
outright and the tile shows `protectionDowngradeMessage` verbatim; a re-save at
*equal* protection is not a conflict and goes through, with the receipt saying
"Already in My Keys". `ConsequenceBanner`'s overwrite shape and its catalog
state still exist, and nothing reaches them. Adding Replace to the button would
mean offering the single click the vault's default exists to refuse — treat it
as a decision to revisit, not a gap to fill.

Four things a cold reader should know:

- **`artifactMetaFromType` had zero callers** before this work. Two role
  vocabularies existed and could not produce each other's words. There is now
  one frozen `ARTIFACT_ROLES` list, and `artifact-roles.test.js` greps the
  engine — both `role: "x"` and `a.role = "x"` — to keep them reconciled.
- **The projection is a floor, the emit site is the override.** Role is a
  property of the artifact, not of the value: the same `text` from `inspect`
  and from `out @msg` are one type and two different artifacts. Do not make
  the projection authoritative; `receipt` and `diagnostic` encode *why* an
  artifact exists and no type can know that.
- **`RECEIPT_VERSION` is 2** because `role` is inside `digestArtifact`. A v1
  receipt gets a sentence saying the description changed and the run did not —
  not "digest mismatch".
- **An emit site's `text`/`secret` is the sensitivity ternary, not an
  identity**, and `TYPE_OWNED_ROLES` in `attachPipeMeta` is what stops it
  outranking the projection. Without it `role: "sshsig"` was unclaimable and
  the shipped `jose-token` kind matched nothing at all — the JWT reader was
  unreachable from a notebook while 1618 tests passed. The set is closed on
  purpose: `pem`/`der` project to `key`, and `KeyCard` reads JWK, so widening
  it would trade a readable armor body for an emptier card.

### The representation pass (§47–§53's D2, D4, D6, D7)

The boundary above is the headline; these are the defects its absence caused,
and what is now true. All five were measured in the built page at
`/toolkit-widgets`, not only in vitest.

- **D2 — `inspect | out @x` keeps its card.** `materializeOutArtifacts`' text
  branch derived `role` from sensitivity alone and never asked whether the
  value was a snapshot, so identical bytes had two identities: bare it resolved
  `inspect-snapshot`, named it resolved `text` (or `secret`). It now honours
  `value.meta.inspect` the way the dangling-tip branch always has, and carries
  `inspectSnapshot` / `inspectFormat` through. `share` still outranks it.
- **D4 — the QR is scannable, and Expand gives it room.** It was `max-h-40
  max-w-40` against a 95px intrinsic SVG, so the cap was decoration and the
  rendered code was 103px in the row **and 103px in a 560px Sheet**. The size
  is the tile's now (`QR_TILE_EDGE`, 192px) and the Sheet overrides it with a
  descendant rule. Measured: 192px in the row, 527px in the Sheet, against a
  29-module code at `devicePixelRatio` 1.5 — 9.9 and 27 device pixels per
  module against the ~3 phone scanning wants. **Note the research's arithmetic
  was off**: it read the 95px SVG edge as 95 modules; a `moduleSize: 3`,
  `margin: 4` code of that size is 29 modules. The defect was real, the ratio
  was not.
- **D6 — both tables have a ceiling; recipients has a filter.** `max-h-44` with
  `overflow-y: auto` on the scroll box (a `max-height` on a `<table>` is
  ignored by the table layout algorithm — it reads as capped and renders
  unbounded). Past `FILTER_ROWS` (8) the recipient card offers a search box;
  the receipt table gets neither filter nor sort, because it is read in
  `run.verify`'s order and "cell 1 · output 2" is a coordinate into it.
  `filterRecipientRows` owns *which rows match* — a fingerprint is displayed
  grouped and pasted rather than typed, so an inline `includes` matches nothing
  on the one field it matters for. Measured with a 14-row fixture: 266px of
  table inside a 176px box, 14 → 3 on `ingrid`, 14 → 1 on `3322 9988`.
- **D7 — every kind now has a catalog row**, gated in
  `artifact-kinds-table.test.js`. Measured on the built page: 24 distinct
  `data-artifact-kind` values, no new row falling to `fallback`. Two findings
  came out of closing it:
  - **`jose-token` is masked in a tile**, and the catalog now shows it that
    way. `jose.sign` emits `sensitive: true`, the kind declares no
    `publicView`, so the best read-out in the codebase sits behind a Reveal
    the list re-masks after 15s. That is *correct* under §34b — every fact on
    the card is decoded from the token — and the honest fix is to the reveal
    timer, which is list-scoped. **Do not "fix" it with a `publicView`.**
  - **`key` and `public-key` are unreachable from a real run.** The keypair
    emit sites tag `keypair`, so `keypair-public` always outscores
    `public-key`; PEM/DER exports keep the emit site's `text`/`secret` because
    `key` is not in `TYPE_OWNED_ROLES`. Their catalog rows are built by calling
    `artifactMetaFromType`, so they cannot be a hand-written claim about an
    engine that does not agree, and the gate resolves that projection rather
    than scanning for a literal.
- **The two stray disabled reasons** are `ACTION_REASONS.noKeyToFingerprint`
  and `.noKeyToEncode`; `artifact-actions.test.js` now fails on any
  `disabled: "…"` literal in the table (comments stripped first).
- **D5 — every expiry date now carries a verdict.** Landed after the pass
  above skipped it; see the next section for where it lives and why.
- **Skipped, deliberately:** D3 and D1 (the OTP agent's), D8 (filed, recipe
  layer). The `envelope` row still truncates its label; it now carries
  `title={a.label}` so the clause that matters — "(not a share)" — is
  reachable, which is the fix that does not restructure the row.

### The three findings the representation pass reported rather than built

All three were deferred as "a behaviour change, not polish", which was right at
the time and stopped being right once the boundary above was written down.
Measured in the built page, and in a **real run** at `/toolkit`
(`genkey aes/256 | out @k`), not only in the catalog.

- **A disabled action's reason was unreachable by keyboard, and now is not.**
  `ArtifactAction` carried the `disabled` attribute and, one line above it, a
  comment stating that `title` alone is unreachable by keyboard — while
  `disabled` removed the button from the tab order and made the
  `aria-describedby` sentence unreachable by keyboard too. The whole feature of
  a disabled artifact action is its reason string; the attribute that made it
  *look* disabled was the thing hiding it.

  It is `aria-disabled` now, plus an explicit refusal in the click handler,
  because **an aria-disabled button is still clickable** and the old
  `onClick={disabled ? undefined : onClick}` is not a refusal — the click still
  fires and still bubbles. Measured on the same page, one click each: the
  refused Download reaches neither `document` nor `window` and writes nothing;
  an enabled Copy fingerprint reaches both and writes once. Nothing above the
  button was ever listening anyway — no ancestor of a tile carries a React
  `onClick`, checked live — so the `stopPropagation` is the belt, not the fix.
  The stylesheet moved with it: `.artifact-action:disabled` →
  `.artifact-action[aria-disabled="true"]`, including the three
  `:hover:not(:disabled)` guards, which would otherwise have silently stopped
  matching and lit a refused Publish on hover.

  Note the near miss. `501cf4f` — the same day — fixed 9 of 10 disabled actions
  announcing *another artifact's* reason, because the description id was derived
  from the label. That was latent **only because nothing could reach the
  descriptions**. Fixing reachability first would have made it loud and wrong.

- **A row that refuses in its entirety states its guard.** `secret-key` is the
  case and the decision was: **no third action belongs there.** A symmetric key
  has no public half, so `key.copyFingerprint` and `key.copyPublicLine` would be
  permanently disabled — a *third* dead button — and `keyring.add` would be a
  button the vault refuses outright, since a `raw` record is indexed by
  `spki:SHA256:` off a public half. The suggested "third ungated action" would
  have been a control that exists to make a stylesheet look better.

  So the row says what guards it. `gatedRowReason(actions, ctx)` in
  `artifact-actions.js` — beside the table, because "is this available, and why
  not" is the table's question — returns the sentence only when **every**
  rendered action refuses and they all give the **same** one; anything else is
  null and each button keeps its own private description. It invents no string:
  it is `ACTION_REASONS`' own sentence, promoted from a `title` to the screen,
  and both buttons' `aria-describedby` point at *that* element rather than at
  private `sr-only` copies, so one refusal is announced once. Measured on the
  catalog: 4 tiles fully gated (`secret-key`, `share`, `secret`, the masked
  `fallback`), 11 mixed rows unchanged, and in the tray's second copy of a row
  the ids stay unique and each pane resolves within itself.

- **Expiry dates get a verdict, in the representation layer.** §47b tier 1:
  recomputed at render against `Date.now()`, resolution in days, **no timer** —
  the text cannot differ one second later, which is the whole test.

  `expiryNote` and `daysUntilExpiry` moved out of `GpgKeyBinder.tsx` into
  `artifact-readouts.js`, unchanged, and `gpg-key-binder.test.js` still passes
  every assertion verbatim — which is the point of moving rather than rewriting.
  They were view-local while the binder was the only consumer; `OpenPgpKeyCard`
  and `NetworkArtifact`'s `CertificatePanel` make three, which is check 3.
  `expiryInstant` is the new part and the reason a widget must not do this:
  the key card holds milliseconds and `rtc-ops.js` serializes the DTLS
  certificate's expiry as an **ISO string**, so a `Date.parse` in the panel
  would have been the second derivation of one fact on day one. An unreadable
  date is *no known expiry*, never `expired`.

  The card keeps its date and gains the verdict beside it, in
  `.artifact-expiry[data-expiry-tone]` — two enumerated values mirroring
  `.jwt-value[data-jwt-tone]`, no inline write. Measured (black-on-white sanity
  = 21.00 first): warn **9.01** dark / **4.61** light, error **6.95** / **5.07**,
  the gate sentence 6.15 / 6.39, and the disabled label and its dotted mark
  unchanged at 6.15 and 4.18 dark. The catalog's certificate fixture was pinned
  to `2026-08-29T00:00:00.000Z` — D3's mistake in another artifact — and is now
  two rows dated relative to `Date.now()`, at +20 days and +3 days, so both
  tones are on the page on purpose and neither rots. A gate in
  `artifact-kinds-table.test.js` keeps it that way.

## Traps learned the hard way (2026-07-31)

- **`site.css` is unlayered and beat every Tailwind utility.** Five element
  rules (`code`, `label`, `pre`, `input`, `textarea`) are now wrapped in
  `@layer base` *at their source*. Layering the `@import` in `toolkit.css`
  does **not** work: `Layout.tsx` imports `site.css` for every page, so the
  toolkit pages get it as a separate unlayered stylesheet too. The build showed
  correct layer geometry while the page rendered unchanged — trusting the
  artifact over the browser would have shipped a no-op.
- **tsc can resolve a symbol the bundle cannot.** Removing an import from
  `OutputList.tsx` left one caller behind; `widgets/index.ts` re-exports the
  symbol, so tsc and all 1555 tests passed while the widgets catalog threw
  `hasNetworkRenderer is not defined` and rendered an empty root. Nothing in
  the suite looks at that page. Verify render-path changes in the built page.
- **Contrast probes need their own sanity check.** A probe reporting 4.04 was
  wrong: badge backgrounds are `color(srgb …)` with 0-1 components and an
  alpha, and the probe assumed `rgb(0-255)` and skipped compositing. Assert
  black-on-white returns exactly 21.00 before believing any figure.
- **`disabled:opacity-50` renders a reason at 2.20:1.** Since a disabled
  action's whole feature is its reason string, that is an absent reason. The
  artifact actions remove the *affordance* instead and keep the label legible.
- **A widget with no catalog section cannot be refactored safely.**
  `ApprovalBanner` had none — the shell mounts it only while a real
  `agent.sign` is suspended mid-run — so "renders identically afterwards", the
  literal acceptance criterion for extracting its shell, was a claim nothing
  could check. Adding the states came first, and the measurement was worth it
  twice over: it caught two places `VISUAL-DESIGN.md` §43a describes the
  shipped banner and the shipped banner disagrees. **Before extracting
  anything, check the component has states someone can look at.**
- **Design docs describe behaviour components do not have.** §33g says
  `ApprovalBanner` moves focus on open and resolves Escape as cancel. It never
  has. Reading that as "it does, so the shell can" would have added focus theft
  and an Escape binding to a signing gate as a side effect of a refactor. When
  a doc attributes existing behaviour to shipped code, grep for it.
- **The scroll lock was CSP-blocked on every menu, not just the `Sheet`** —
  fixed in `34b3a2f`. `react-remove-scroll-bar` injected an inline `<style>`
  that `style-src-elem` blocked with disposition `enforce`, so the lock
  silently did not apply in production. It was invisible in `serve` (weaker
  policy) and looked cosmetic on `/toolkit` (masked by
  `body.layout-app { overflow: hidden }`) — but `@radix-ui/react-menu` pulls
  in the same package, so on `/my-keys`, where `<body>` genuinely scrolls, the
  page scrolled behind every open dropdown. The fix aliases the package to
  `src/lib/scroll-lock.js`, which sets a reference-counted
  `body[data-scroll-locked]` and injects nothing; the rules live in
  `site.css`. **No CSP exemption was added, and none may be** — a test asserts
  no `sha256-` appears in any page's `style-src`.

  Two dead ends, both measured, both worth not rediscovering:
  `scrollbar-gutter: stable` reserves the gutter even where the platform draws
  overlay scrollbars that took no width, turning a zero-shift case into a
  7.5px shift on every open; and porting the library's own compensation
  rewrites `<body>`'s margins into padding, which throws this app's centred
  `max-width: 1000px` body against one edge for as long as a menu is open.
  Padding the scroll container by the measured gap is what holds it still.

## What is outstanding

**Recipe-language turns 46/47 are implemented** (gap ambiguity + selector
grammar): scope-named nested gaps ("+ step in :public" / "in loop body"),
containers always render their nest region, the continue gap hides while a
tee/foreach is empty, inserting a container auto-focuses its body gap, foreach
bodies anchor on a static "↻ each item" chip, tee stems offer ghost selector
branches from the closed projector table (`selectorGhostsFor` in suggest.js)
plus "+ branch" and "peek instead", an armed branch materializes atomically
with its first step (`addBranchWithStep`), and tee/foreach are absent — not
dimmed — from shelf and fit for any nested caret (enforced in `nestOp` too,
against drag-drops). Tests: `selector-ghosts.test.js`; catalog section
"RecipeChipFlow" shows the new states. Still unbuilt from 47: a chip
affordance for `foreach`'s own `:items`/`:values`/`:keys` gap (source-view
only today, stored as `foreachSelector`), and per-item selector ghosts inside
a body (the caret offers fit-checked ops incl. `select`, just not a dedicated
ghost row).

Design turns **36–39 have no handoff README** — read them from
`Basilisk Toolkit v2.dc.html` directly via the claude_design MCP. Everything
else has one in `redesign/design_handoff_*/`.

~~**Files were the biggest gap between this and a tool people use for real
work**~~ — closed. `file.read` / `file.save` (`lib/toolkit/file-ops.js`, File
System Access API with an `<input type=file>` / download-anchor fallback; no
permission gate, because the browser's picker *is* the consent — contrast
`clipboard.read`), `stream.seal` / `stream.open` (`lib/toolkit/stream-aead.js`,
chunked AES-GCM in the STREAM construction, since `SubtleCrypto.encrypt` is
one-shot), and **full age interop** — `age.*` through typage, so `age -d` on
someone else's machine reads what this writes. `age` is a new toolbox beside
OpenPGP; `files` is a new shelf. Tests: `stream-aead.test.js` (reorder,
splice, truncation both ways, modified header), `age-ops.test.js` (asserts the
C2SP *wire format*, not just a round trip through one library),
`file-ops.test.js`. Catalog section: `#fileops`.

Three things worth carrying forward from it:
- **`stream.*` is deliberately not age**, and says so everywhere — module
  header, registry doc, RECIPE.md, CRYPTOGRAPHY.md all carry the divergence
  table. Do not "improve" it toward partial age compatibility; that is the one
  outcome worse than either honest option.
- `age.encrypt to=` is `type: "string"` (a recipient is public, and `to=age1…`
  is how everyone writes it) while `age.decrypt key=` is `type: "slot"` — a
  literal identity in recipe text would ride out through Copy link, Export, and
  the workspace library.
- The catalog caught another one, exactly as advertised: `site.css` has a
  global `input[type=file] { display: none }`, which would have made the
  fallback picker click-inert on the browsers that need it. Measured with
  `getComputedStyle`; no stubbed-DOM test could see it.

**Surfaces for the capability that shipped without one** —
`redesign/CAPABILITY-SURFACES.md`, four designs, three of them built. The
custodian verification moment is done: `ShareCheck` over
`lib/toolkit/share-check.js` (More ▸ Check a share…, and rehearsed inside the
ceremony's cards stage), cards now print the split id and a *derived* recovery
line, and the ceremony's split stage tells the room to publish the commitments.
Verify-this-deployment is done: `IntegrityPanel` over
`lib/toolkit/deployment-check.js`, presentation only — the comparison is still
`verifyModuleRootAgainstPins`. `qr.scan` got its first surface, composed from
`file.read | qr.scan`, degrading honestly where `BarcodeDetector` is absent. The
DKG session is **designed, not wired**: `lib/quorum/dkg-session.js` +
`DkgPanel`, catalog-only, with its assumptions about the missing op layer
written down. Files/age/stream progress remains design-only and is specced in
the same document.

Three things worth carrying forward:

- **The card was telling custodians to run the wrong op.** `ShareCards`
  hard-coded `sss.combine` while the ceremony has been splitting with
  `vss.split` since bd3bb44. Derived now. Look for this class of bug wherever a
  string was written before the thing it describes changed.
- **The catalog caught two more.** `IntegrityPanel` printed a 64-hex "Loaded
  root" beside a verdict saying nothing could be checked — the self-digest
  fallback, which looks exactly like the number a reader is meant to compare.
  And `toolkit-widgets.html` had no CSP meta while `toolkit-widgets` was missing
  from `STATIC_PAGES`, so the catalog was the one page with no report-only
  policy. Both fixed; the header is now measured live there.
- **`share-only` must never render green.** A BLIP39 mnemonic decoding cleanly
  proves transcription, nothing more. The tone enumeration in `toolkit.css` is
  what makes that structural rather than remembered.

Roughly in value order:

1. **P2P mesh** — `redesign/p2p-dkg/DESIGN.md` has the researched plan.
   **Perfect negotiation is done**: `lib/quorum/rtc.js` now runs the MDN
   pattern (lower fingerprint is polite; `offerCollisionAction` is the pure,
   tested rule in `quorum-negotiation.test.js`), and offers ride a single
   `onnegotiationneeded` path — which also made "Restart connection" real,
   since `restartIce()` previously fired an event nobody handled. Note the
   design doc overstates the remaining gaps: `QuorumSession` is already
   N-party, and `derivePairwiseSessionKey` already binds room + both fprs +
   audience + nonces + both DTLS fingerprints (the RFC 8844 shape) at the
   *pairwise* level. **Mesh self-bootstrap is now in**: signaling is
   channel-first (`_sendTo` prefers a live direct link, then a one-hop relay
   over kc-verified links, then the mailbox), sealed envelopes ride data
   channels as `{v, env, hops}` frames with hop cap + bounded dedupe
   (`lib/quorum/relay.js`, tested in `quorum-relay.test.js`), and members
   forward frames addressed to peers they hold links to — so only the first
   join needs the mailbox, and renegotiation survives it dying. `rtc.restart`
   makes ICE recovery chainable, and ConnectionsPanel states mesh degree with
   the DESIGN §1 soft-cap warning past 8 participants. Caveat, stated
   honestly: the relay path is verified at the pure-rule and compile level;
   a live two-browser relay run has not been performed.

   **DKG round arithmetic is now implemented and tested** in
   `lib/quorum/dkg.js` — Feldman VSS / joint-Feldman over P-256, using
   `@noble/curves` (declared explicitly; WebCrypto exposes no EC point
   arithmetic, and the existing SSS is GF(256) so it could not carry this).
   `round1` / `verifyShare` / `finalize` / `reconstruct`, with 20 tests
   including the one that matters: shares reconstruct to a secret whose
   public key equals the jointly published one, and equals Σ of the
   participants' own contributions.

   **What remains is the op/transport layer**, deliberately not half-built.
   An op has to run the rounds over the live exchange: broadcast commitments,
   deliver shares pairwise, wait for contributions, `finalize`. Two notes for
   whoever takes it — the protocol needs *ordered rounds*, so it wants the
   wait-for-peers machinery `quorum.offer` already has rather than a bare
   `quorum.recv`; and there is **no complaint round**, so a bad share makes
   `finalize` refuse and name the dealer, with restart-without-them as the
   only remedy. The UI must say that plainly, and label the whole thing
   experimental: it produces a shared key, not threshold signing.
   Also applied: the 48a naming audit — seven camelCase ops renamed
   (`rtc.gather/check/state/stats/offer/answer/quality`; `rtc.statsReport`
   was a seventh the audit missed), old names retired + migrated, and a
   convention test in `rtc-channel-ops.test.js` now locks
   `namespace.singlelowercaseword` for every registered op.
2. ~~**Feed real peers into `ConnectionsPanel`**~~ — done. `quorum-ops`
   projects the live roster through `lib/quorum/roster.js`
   (`projectRosterPeers`) onto the `basilisk:quorum-state` event;
   `authenticated` demands *both* pgpVerified and kcVerified, and `via` is a
   best-effort async `getStats` enrichment that patches in after the row first
   renders. Tests in `quorum-roster.test.js`.
3. ~~**32d clipboard ops**~~ — done. `clipboard.read` (source, gated: the
   shell registers a permission surface via `setClipboardReadGate`, asked
   every run, Allow reads inside the click's transient activation) and
   `clipboard.write` (passthrough sink in `POLYMORPHIC_STEPS`, toast-weight
   confirm via `basilisk:clipboard-wrote`). `lib/toolkit/clipboard-ops.js`,
   tests in `clipboard-ops.test.js`. Note for e2e: a *scripted* Run click has
   no transient activation, so `writeText` is denied — drive Run with a real
   input event. Still open: **33d artifact diff**, **36b/36c**, **37a/37b**,
   **38a/38b** — see the handoff READMEs.
   Also new since: **cross-cell slot gating** (`lib/toolkit/slot-graph.js`) —
   a later cell's unmet inputs no longer block the producing cells; runFrom
   gates per cell (checkpoint semantics) and the `shares` panel op falls back
   to indexed share slots a foreach emitted this session (see
   `split-recover-e2e.test.js` for the real round trip). And **session-only
   keys for e2e**: dev-only `window.__basiliskE2E.mintSessionKey()`
   (`lib/e2e-hooks.js`, tree-shaken from production), resolved by
   `unlockVaultForUse` via the session cache without vault membership.
4. ~~**TOTP (turn 43) deserves its own scope.**~~ — done, and the premise was
   wrong in a useful way. This entry said "a value that mutates on a local timer
   is new for this engine", and treated that as the engine change to budget for.
   **No such change was needed, and making it would have been the defect.** The
   `otp.*` toolbox (`74fdf3d` — `lib/otp/hotp.js`, `lib/otp/uri.js`,
   `lib/toolkit/otp-ops.js`, RFC vectors + `otpauth://` round trips) computes a
   code exactly once, at run time, like every other value. What ticks is the
   **clock**, in the widget (`51a8cb1` — `OtpCodeCard`, kind `otp-code`): the
   run stamps `otpStep`/`otpPeriod` into `traits`, the card turns them into an
   absolute expiry instant, and a one-second tick against `Date.now()` drains
   the bar and then says **expired** while still showing the value the run
   receipt digested. A Refresh button is what §37a exists to refuse — a
   recomputed code would be a value with no step behind it in the recipe,
   nothing in the receipt describing it, and nothing the CLI could reproduce.
   Re-running the cell is what produces the next code, and the tile says so
   instead of offering to do it. Two policy calls worth not re-litigating: the
   `otpauth://` URI is **sensitive** (the URI *is* the secret, plus a label)
   and the code is **not** (six digits that expire in half a minute and exist
   to be read off the screen); and HOTP gets no countdown at all — not a
   disabled one, not a zeroed one — because it answers to a counter, not a
   clock, and §33d answers "is this meaningful for this object" by omission.
5. **Work down the inline-style baseline** — now 11 sites in 7 files. TopBar
   (was 6) and OpsShelf (was 4) are converted: `data-suite-tone` /
   `data-toolbox-dot` plus enumerated rules in toolkit.css.
   `toolbox-dot-css.test.js` guards the registry↔stylesheet colour
   duplication against drift. Remaining: index (3), NetworkArtifact (3),
   ToolkitShell (2), Glyph / RunBar / SessionStrip / toolkit.tsx (1 each).
6. ~~**Wire `boot-diagnostics` into the other nine pages**~~ — done, all ten
   entries (redirect stub included). Bonus find: the dev server never sent
   the report-only CSP header for `/` and `/search` (the early-return skipped
   the header block), so index — which holds 3 of the remaining inline-style
   sites — was blind to exactly the failures the header exists to predict.
   Fixed in `basilisk-dev-server.js`; verified the predicted-violation banner
   fires on `/`.

The `CellTypeErrors` banner and the RunBar blocker no longer word type errors
independently — `b57e64c`. `cellErrors` used to call
`validateRecipe({ chains: [chain] })` **per cell**, which throws away the slot
table each cell builds for the ones below it, so 33 shipped multi-cell templates
opened under a wall of red (`in @kp: unknown slot`, plus the cascade behind it)
before any run and still after a successful one. Every word of it was fiction:
`@kp` is written one cell up. The notebook is now validated **whole, once**
(`cellErrorsForChains`, pure and exported so the node suite can call it), and
the errors are dealt back to the cell they came from. Three things about that
choice are worth not undoing:

- It is the **same** validation the run gate performs, so the banner and the
  Run button can no longer hold two opinions about whether a cell is wired.
- Filtering the cascade afterwards was rejected: recognising a downstream
  message would mean matching it by its wording, which this codebase asserts
  verbatim elsewhere and which would rot on the first rephrasing.
- **Nothing is suppressed.** `in @typo` that nothing ever writes still reports,
  and so does a slot written only *below* the cell that reads it. Suppressing
  unknown slots outside the first cell would trade a false positive for a false
  negative, which is the worse direction.

`stepIndex` anchoring survives because `validateRecipe` numbers top-level steps
continuously across cells, so subtracting the cell's start offset recovers the
per-cell index exactly — the same chip lights up, including from inside a
`foreach` body.

---

## How to work

Read `docs/TOOLKIT-WIDGETS.md` and `docs/RECIPE.md` first; they are current.
Reuse existing primitives — if a design needs a window, it is a `Sheet`. Do not
invent registry ops or types to satisfy a mockup; the registry is the source of
truth and a design that needs a new one should say so explicitly.

Design handoffs are high quality but written against a partly fictional
registry. Prior ones flag which mock details bind and which illustrate — honour
that distinction, and check the claim against the code before implementing it.
One handoff in this project retracted an entire turn as fabricated because it
had been written without reading the source first.
