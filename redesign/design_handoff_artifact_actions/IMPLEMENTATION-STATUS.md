# Artifact kinds + actions — implementation status

Checklist for building [ARTIFACT-ACTIONS-DESIGN.md](./ARTIFACT-ACTIONS-DESIGN.md),
in dependency order: the type/engine plumbing first (testable headlessly, no
UI), then the registry and the tile, then actions by tier, then the kinds that
motivated the request. Every unit lists acceptance criteria measurable by test
or by browser measurement (`getComputedStyle` / DOM, per HANDOFF — screenshots
are unreliable here).

**Status as of 2026-08-01: units 1, 2, most of 3, most of 4, and §35/§36/§37
are built.** Shipped: the role vocabulary, projection floor, keypair/recipients
role stamping and `RECEIPT_VERSION` 2 (unit 1); the resolver, the kind table
with the three existing renderers folded in unmodified, and `OutputList` wired
to both (unit 2); the two §39 foundations, the three-tier action row and
disabled-with-reason (unit 3); the global action table with injected services
and the `copy` / `download` / `key.copyFingerprint` / `key.copyPublicLine` /
`keyring.add` / `key.publish` actions, mask gating and `saveKey({onConflict})`
(unit 4 — 4.3 through 4.7, leaving 4.1's own acceptance test, the rest of 4.2
and 4.8); the §35 key tiles (`keypair-public`, `keypair-private`, `key`,
`openpgp-public`, `openpgp-private`) with `publicView` so a masked private key
is not blank; and the §36 Activity log with its tray tab.

Checkboxes below are ticked **only where the unit's own acceptance criteria
were checked against the code**, and a tick that carries a deviation says so
in the entry. Several unticked units are covered by the prose above — the
prose describes what exists, the boxes record what was verified against the
list, and where the two disagree the box is the conservative one. A blanket
find-replace over this file once ticked three unbuilt items and had to be
walked back; do not repeat it.

Six were ticked in a later pass — **1.1, 2.1, 2.2, 2.3, 4.1, 6.1** — each with
the evidence written into its entry. Two that looked ready were deliberately
left open, and their near-misses are worth knowing rather than rediscovering:

- **1.4** is *built* — `cellOutputs` carries every field the registry needs and
  a test names them — but its acceptance asks for the projection's key set to
  **equal** a declared list, so that a future engine field is a failure rather
  than an invisible omission. The shipped test checks a subset, which catches
  a field being removed and not a field never being added. That is the exact
  trap HANDOFF says has cost two debugging rounds, so the box stays open until
  the guard is the one the unit asked for.
- **6.2** holds its property by a *stronger* mechanism than its criterion
  names. The criterion is a test that runs every action with stubs and asserts
  one entry each; what shipped asserts `recordActivity` appears exactly once in
  the tile, inside the `.then` and before the `.catch`. That makes "a new
  action cannot forget" structural rather than sampled — but it is not the
  stated criterion, and this file's rule is that the box records what was
  checked against the list.

Several remaining units (3.3, 3.5, 3.6, 3.7, part of 6.3) have acceptance
criteria written as `getComputedStyle` / DOM-query measurements, and this suite
runs in node with no renderer. Source assertions stand in for them today, which
is a real gap and not a bookkeeping one — see the verification notes at the end
about the catalog and the built page.

**§37 is now built too.** Every role in `ARTIFACT_ROLES` is claimed:
`ciphertext` and `envelope` share a packet read-out over `packet-map.js`;
`recipients`, `sshsig`, `receipt` and `qr` have their own cards; `diagnostic`
draws through `NetworkArtifact`; `share` contributes a `publicView` so a masked
share tile says which share it is; `text` and `secret` are claimed with no view
at all, which is the honest answer rather than a widget invented to fill a row.
`UNCLAIMED_ROLES` in `artifact-kinds-table.test.js` is empty and the coverage
gate now has teeth in both directions.

Two things §37 turned up that this document assumed away. **`role: "sshsig"`
was unreachable** — the `out` text branch stamped `text`/`secret` from
sensitivity, and that outranked the projection, so the role sat in the
vocabulary with nothing able to claim it. **The same bug made the shipped
`jose-token` kind inert**: it matches `role: "token"`, nothing emitted it, and
the JWT reader was unreachable from a notebook while every test passed — the
exact "resolvable but absent from the page" failure HANDOFF warns about, one
layer down. Both are fixed by `TYPE_OWNED_ROLES` in `attachPipeMeta`: a
projected `sshsig`/`token` outranks an emit site's `text`/`secret`, which are
the sensitivity ternary and not a claim about identity. Deliberately a closed
set — `pem`/`der` project to `key`, and the key card reads JWK, so promoting
them would swap a readable armor body for an emptier card (see 5.6).

**The JWT reader was still unreachable after that, and the second half is now
fixed too.** Making `jose-token` resolve got the kind a tile; what it did not
get was a *visible* card, because `jose.sign` emits `sensitive: true` and the
kind declared no `publicView` — so the most complete read-out in the codebase
sat behind a Reveal the list undoes fifteen seconds later, on the only tile
that ever renders it. The question that deferred it was whether a JWS is a
secret at all, and the answer is **both, on different axes**: a JWS is signed,
not encrypted, so its header and payload are readable by anyone holding it —
but a signed token is a bearer credential and `sensitive` is the
*displayability* axis (the same axis on which `keyring.add` stays enabled while
masked). So the flag stays and the kind declares a `publicView`, which is
`ssh-private`'s shape exactly: header, claims and validity are drawn, the
**signature** is withheld, and the reader has no path to it — it is handed
`meta.jose`, and the compact token is not in it. A JWE needs no exception:
`jose.decrypt`'s plaintext is a different artifact that projects to `secret`,
so decrypted claims never reach this kind. Argued on the kind, pinned in
`artifact-kinds-table.test.js`, and seen masked in the built catalog.

**§33a, §34c and §38 are built as well.** `ArtifactTile` is its own component;
`GateBanner` is `ApprovalBanner`'s chrome extracted with no behavioural change
and `ConsequenceBanner` is its second user; `key.publish` is an entry in the
action table at `tier: "outward"`, declared by `openpgp-public` alone, and it
confirms in the banner rather than the popover. §38's clauses are asserted in
`artifact-migration.test.js` — the section is all negatives (an op not added, a
name not retired, a store not bumped), and negatives do not fail loudly on
their own.

**`keyring.add` is built** (`f800a9b`), and with it the last of unit 4's load-
bearing gates. It became possible when `saveKey({ onConflict })` landed in
`6b0ec96` — see unit 4.7 — and it deliberately passes *no* `onConflict`, so the
vault's default refusal stands: one click may not throw away a passkey binding,
and a key already held behind one gets `protectionDowngradeMessage` verbatim
through the banner's footnote. It is **enabled while masked**, which is the
opposite call from Copy and for the same reason (§34b gates on *leaving*, and
this stores without displaying).

**§34d's overwrite confirmation is therefore not built, and no longer waiting
on anything** — the design imagined a Replace path to agree to, and what
shipped has none. The vault refuses a weakening re-save outright and the tile
states the refusal; a re-save at *equal* protection is not a conflict at all and
goes through, with the receipt saying "Already in My Keys" rather than claiming
to have added something. `ConsequenceBanner`'s overwrite shape still exists and
still has its catalog state (unit 4.4), and it is now a state nothing reaches.
That is a decision to revisit, not an omission to fill: adding Replace to the
button would mean the single click the vault's default exists to refuse.

The `Add to keyring` half of §38a's doc steer was held back because the button
did not exist. It does now, so the steer can gain its second sentence — **still
owed**, and the one thing on this page that `f800a9b` made possible without
doing.

Four places the design and the code disagreed, found by measuring:

- **§43a's shell spec is not what shipped.** It says "1px `--border`
  elsewhere" — the other three edges have no border at all; `border-l-2` sets
  only the left width, and the `border-[var(--border)]` beside it colours edges
  with zero width. It says the buttons are "both 22px at 10.5px" — they are the
  `Button` primitive's `sm` height, 24.79px (ghost) and 26.13px (secondary),
  which differ from each other. `GateBanner` reproduces what shipped.
- **§33g says `ApprovalBanner` moves focus on open and resolves Escape as
  cancel.** It has never done either. Both are opt-in on the shell and the
  approval banner does not opt in — unit 4.4's contract is that its behaviour
  does not change, and a keystroke that used to do nothing must not start
  denying a signing request.
- **Unit 4.4's acceptance criterion referred to `ApprovalBanner`'s "existing
  catalog states".** There were none: the shell renders it only while a real
  `agent.sign` is suspended mid-run. Three states were added first, so
  "renders identically" became checkable.
- **§34c's mock shows a user id on the publish banner's Key line.** `traits`
  carries only `fingerprint`; the uid would need a second parse of the armor
  that the tile's own card, two lines above, has already done. The banner names
  the artifact and the fingerprint in display shape instead.

One defect found in passing was filed here rather than fixed, and **has since
been fixed in `34b3a2f`**: opening any Radix `Sheet` in the *built* app inserted
an inline `<style>` that `style-src-elem` blocked with disposition `enforce`, so
the dialog's scroll-lock silently did not apply in production. It was wider than
this page said — `@radix-ui/react-menu` pulls in the same
`react-remove-scroll-bar`, so every dropdown was affected too, and on `/my-keys`
(where `<body>` genuinely scrolls) the page scrolled behind them. `vite.config.js`
now aliases the package to `src/lib/scroll-lock.js`, which sets a
reference-counted `body[data-scroll-locked]` and injects nothing; the rules live
in `site.css`. **No CSP exemption was added, and none may be.** HANDOFF carries
the two measured dead ends.

**`saveKey({ onConflict })` landed in `6b0ec96`, and `keyring.add` with it in
`f800a9b`.** The bug this page recorded as blocking both was real and is fixed:
`saveKey` built a fresh record and `put` it into a store keyed on the
fingerprint, so re-saving a passkey-protected key at `protection=device`
produced a record with no outer PRF wrap and `unlockKey` returned the private
key with no authenticator in the loop. The guard reads and writes in **one**
transaction — a check-then-save in the UI would leave open the window a second
tab enrols the passkey in, which is the case the guard exists for — and only a
genuine weakening (passkey > passphrase > device) counts, so the equal-protection
re-saves that `publicArmored` and the key-id backfill depend on stay routine.

One correction to this document's own premises stands: `artifactMetaFromType`
had **zero callers**, so "the type system can already drive it" was aspirational.

Engine/registry capabilities this design needs that do not exist today are
marked ⚙ — do not discover them mid-implementation. There are nine of them, and
three (1.1, 1.3, 1.4) are the load-bearing ones: without them the registry keys
off a field that half the artifacts do not carry.

---

## 1. Types and engine plumbing (no UI) — §32

- [x] ⚙ **1.1 `ARTIFACT_ROLES` in `types.js`** — the one frozen list of the
  fifteen roles in §32c, exported. Accept: a unit test asserts every `role:`
  string literal appearing in `engine.js` is a member (a source grep in the
  test, the `toolbox-dot-css.test.js` style of guarding a duplication
  mechanically); adding an unlisted role fails.

  **Checked**: `ARTIFACT_ROLES` is exported and `Object.isFrozen`, asserted;
  `artifact-roles.test.js`' first test greps `engine.js` and fails on a literal
  outside the list. One gap found and closed while verifying: the grep read
  only the literal immediately after `role:`, so a **ternary** — `role: isShare
  ? "share" : "ciphertext"`, and four more like it — was seen as neither
  branch. It now reads the whole line, which puts a small constraint on
  `engine.js` in return (a `role:` line carries role literals and nothing
  else).
- [ ] ⚙ **1.2 `artifactMetaFromType` gains the missing branches** — `text/sshsig`
  → `sshsig`; `text/jws` and `text/jwe` → `token`; the seven network bases
  (`candidate`, `sdp`, `stats`, `connstate`, `endpoint`, `certificate`,
  `session`) → `netvalue` with the base as a tag. Accept: a table test maps
  every `RefinedType` the registry can produce as an output to a role in
  `ARTIFACT_ROLES`, with no fall-through to `text` for a type that has a
  dedicated role.
- [ ] ⚙ **1.3 `attachPipeMeta` stamps role/tags from the projection** when the
  emit site left them unset (§32c). Accept: `genkey ed25519 | out @kp` yields
  artifacts with `role: "key"` where they are `"secret"`/`"text"` today;
  `role: "receipt"` and `role: "diagnostic"` still win over the projection
  (assert both, they are the override cases); no artifact in the verb-smoke
  catalog comes out role-less.
- [ ] ⚙ **1.4 `cellOutputs` carries `pipeType`, `tags`, `traits`, `shareIndex`,
  `mime`, `filename`, `bytes`** — `useNotebook.ts:354` copies named fields and
  silently drops everything else (HANDOFF names this trap; it has cost two
  debugging rounds already). Accept: a test asserts the projection's key set
  equals a declared list, so a future engine field is a test failure rather
  than an invisible omission.
- [ ] ⚙ **1.5 Keypair export sites tag their half** — the two `parts.push` in
  `materializeOutArtifacts`' keypair branch (`engine.js:4387-4440`) add
  `tags: ["keypair", "public"|"private"]` and `traits: { alg }`. Accept:
  `genkey ec/p256 | out @kp` yields one artifact matching `keypair-public` and
  one matching `keypair-private`; `content`, `label`, `filename` and the
  artifact *count* are byte-identical to before (assert against a fixture — this
  is the "nothing may change what a recipe computes" guard).
- [ ] ⚙ **1.6 Recipients emit sites stamp `role: "recipients"`** —
  `engine.js:4294` and `:4645` say `"text"` today. Accept: a recipients export
  matches the `recipients` kind; the JSON body is unchanged.
- [ ] ⚙ **1.7 `RECEIPT_VERSION` → 2 and a v1-receipt message in `run.verify`**
  (§38c). `role` is inside `digestArtifact`, so 1.3/1.5/1.6 change receipt
  digests for unchanged runs. Accept: a v1 receipt compared against a current
  run reports the §38c sentence verbatim, not "digest mismatch"; a v2 receipt
  round-trips.

**Verification for this unit is CLI-shaped**: `node web/cli/basilisk.js run …`
prints `role=` in `artifactHeader` and in `--json`, so the role changes are
directly observable headlessly, before any widget exists.

## 2. The kind registry and the resolver — §32

- [x] **2.1 `toolkit/artifact-kinds/resolve.ts`** — matcher per §32b (most
  matched tags wins) plus `FALLBACK_KIND`. Accept: unit tests for exact match,
  tag-subset match, specificity ordering, and fallback; a resolver call on an
  artifact with an unknown role returns the fallback and never throws.

  **Checked**: `artifact-kinds.test.js` covers all four — exact role match, tag
  subset scored by count, specificity beating declaration order, and the
  fallback for both an unknown role and an artifact with no role at all. Ties
  throw *by design* and are their own describe block, and
  `artifact-kinds-table.test.js`' "never throws on anything the engine emits"
  is the guard that no real artifact reaches one.
- [x] **2.2 `artifact-kinds/registry.tsx`** with the three existing renderers as
  entries (§32e). Accept: `NetworkArtifact`, `InspectorArtifact` and
  `JwtArtifact` are imported unmodified — a diff touching their internals means
  the abstraction is wrong; the seven network types are matched via the role
  projection, not via `hasNetworkRenderer`.

  **Checked**: all three are imported and asserted unmodified; `CODE_ONLY` (the
  comment-stripped table) is asserted not to mention `hasNetworkRenderer` at
  all, and `NETWORK_BASES` in `types.js` is what defines `role: "netvalue"`.
  `hasJoseRenderer` survives as a *body* check inside the view, which is the
  question it answers.
- [x] **2.3 `artifact-kinds.test.js` — the coverage gate.** Every role in
  `ARTIFACT_ROLES` is claimed by at least one entry; no two entries can both
  match any `(role, tags)` the engine emits. Accept: the test fails when a role
  is added without a kind, and when a duplicate matcher is introduced.

  **Checked**: `UNCLAIMED_ROLES` is `[]` and the assertion is an equality
  against it, so a role added without a kind fails; `ambiguousPairs` over
  the table alone covers the duplicate-matcher half. The gate has teeth in both
  directions, as the §37 note above says.
- [x] **2.4 Catalog section — `#artifacttiles`** on `/toolkit-widgets`,
  rendering one row per §37 kind plus a deliberately unknown role so the
  fallback is visible beside them. Fixtures are captured from `runRecipe`
  rather than written by hand: a fixture that merely *looks* like what the
  engine emits is how a tile passes its catalog and falls through to the
  fallback in production. Still owed: an `empty`/`failed` state per kind —
  neither is rendered by `OutputList` yet (they arrive with §33a's
  `ArtifactTile`), so there is nothing to show them in.

## 3. `ArtifactTile` and the common base — §33

- [x] **3.1 `ArtifactTile` component** — identity line, body, action row,
  receipt line (§33a). Measured before and after at 1026x1258 across all four
  `OutputList` mounts, 16 rows: list radius `10px`, padding `4px`, 1px
  `--border` on `--surface`; row padding `8px 10px`, row gap `4px`; divider
  0.667px `--border` @55% and absent on the last row; actions 22px at 10px,
  radius 5px. Every row height matched to three decimals, as did every
  `data-artifact-kind`, button label, tier, disabled state and reason string.
  The reveal set and its 15s timer stayed in `OutputList` deliberately: the
  timer re-masks every revealed row at once, and N per-tile timers would be a
  different behaviour wearing the same code.
- [ ] **3.2 Both `OutputList` call sites feed the same tile** — the cell list
  (`ToolkitShell.tsx:1788`) and the tray Outputs tab (`:2274`) currently compute
  *different* badge mappings for the same artifact. Accept: a test renders one
  fixture artifact through both surfaces and asserts identical
  `data-artifact-kind` and identical badge text.
- [ ] **3.3 `data-action-tier` CSS** — three enumerated rules in `toolkit.css`
  (§33b). Accept: `getComputedStyle` on one button per tier matches the token
  values; `no-inline-styles.test.js` baseline does not move.
- [ ] **3.4 Action row grouping and overflow** — three groups, outward last,
  overflow past four inert actions into `MenuPopover`. Accept: DOM order test
  (outward action is the last `<button>` in the group); a catalog fixture with
  eight actions shows the More menu and keeps local/outward visible.
- [ ] **3.5 Disabled-with-reason** — `available()` returning `{ disabled }`
  renders `disabled`, `title`, and `aria-describedby`. Accept: reason strings
  asserted verbatim (the `share-check.js` wording-is-the-feature precedent); no
  rendered `disabled` button anywhere in the catalog lacks a reason (assert by
  querying the catalog DOM).
- [ ] **3.6 Masking and `publicView`** — §33e. Accept: a sensitive tile without
  `revealable` shows no Reveal and a disabled Copy with the "not asked for"
  reason; a `keypair-private` fixture shows algorithm/fingerprint/public line
  *while masked* and the masked line beneath; the 15s auto-hide still fires.
- [ ] **3.7 Keyboard** — §33g. Accept: tab order View → Inert → Local → Outward
  asserted in a DOM test; Sheet returns focus to Expand on close; no action is
  hover-only (relevant: this repo has had sessions where the browser pane
  reported a 0×0 viewport and hover could not be exercised at all).

## 4. Actions, by tier — §33c, §34

- [x] **4.1 Action table + injected `ActionServices`** (§33c). Accept: the table
  imports no vault, clipboard, network or file module; a unit test drives every
  action with stub services and asserts the `ActionResult`.

  **Checked**: "imports no clipboard, vault, network or filesystem of its own"
  asserts the first half against the source. All six entries — `copy`,
  `download`, `key.copyFingerprint`, `key.copyPublicLine`, `keyring.add`,
  `key.publish` — are run with stubs and their results asserted (the last two
  against a real `fake-indexeddb` vault and a stub directory). Two structural
  guards beside them: every `available()` returns a sentence rather than a bare
  `false`, and every id a kind names resolves in the table.
- [ ] **4.2 Inert actions** — `copy`, `download`, `expand`,
  `key.copyFingerprint`, `artifact.showQr`, `diag.configureTurn`. Accept: Copy
  routes through the existing `basilisk:clipboard-wrote` event so the shipped
  toast fires (clipboard test needs a *real* input event — a scripted click has
  no transient activation, per HANDOFF); Download routes through `file-ops.js`
  and fires `basilisk:file-saved`.

  **Partial, so still open.** In the table: `copy`, `download` (`2dda2af`),
  `key.copyFingerprint`, `key.copyPublicLine`. Not in the table:
  `artifact.showQr` and `diag.configureTurn` — the latter is still passed into
  `OutputList` as a `diagnosticAction` prop by both shell call sites rather than
  declared. `expand` is not a table entry by design: it is the tile's own
  affordance and its Sheet renders the same widget the row does. **Download
  deviates on its route** — it goes through a new `download-service.js`, not
  `file-ops.js`, because `file.save`'s File System Access path opens a picker
  and a tile Download should not; it fires the same `basilisk:file-saved` event,
  so the notification weight is unchanged. The filename is the engine's
  (`downloadNameFor`), corrected per kind only where a kind declares
  `download.ext` — `ssh-private` claims `.key`, and the reasoning against
  `.txt` (hands a private key to a text editor) and `.pem` (claims PKCS#8 it is
  not) is recorded on that kind.
- [x] **4.3 Mask gating** (§34b) — **one deviation, argued.** Copy is disabled
  on a masked value with the verbatim reason, and fingerprint/public-line are
  enabled (both derive from public material — a fingerprint is a digest of the
  wire blob, public even inside a private block). **Download is disabled, where
  this unit said enabled.** The design read Download as "no display, therefore
  no exposure"; §34b gates on whether the value *leaves*, and a file is where a
  secret goes to be kept where the clipboard is where it goes to be pasted once.
  `activity-log.js` had already named the two together as "how a secret leaves
  the notebook" and logs both. The contrast that keeps the axis legible is
  `keyring.add`, which stays *enabled* while masked because it moves the secret
  into storage without ever displaying it. Asserted on one fixture, plus a test
  that Download's `available()` is `toEqual` Copy's across all three masked
  cases; `expect(SRC).not.toMatch(/setRevealed|revealed\s*=\s*true/)` pins that
  no code path lifts the mask from inside an action.

  A consequence of the shared branch, recorded because it was a live untruth for
  a while: `ACTION_REASONS.maskedButRevealable` used to say "a masked value
  cannot be **copied**", which was a sentence about a button a Download user had
  not pressed. It now says "cannot **leave the notebook**" and names neither
  action — one reason for one condition, which is what `artifact-reasons.js`
  exists to enforce.
- [x] **4.4 `GateBanner` extraction + `ConsequenceBanner`** (§34c). The
  approval banner had *no* catalog states — it renders only while a real
  `agent.sign` is suspended mid-run — so three were added first and measured,
  then re-measured after the extraction: container 2px `--warn` / 0px on the
  other three edges / `color(srgb .890196 .701961 .254902 / .08)` / padding
  `10px 14px`; heights 203.917 / 187.125 / 163.167; header 11.5px/600; the
  meta's computed `margin-left` 207.583 / 174.594 / 187.010; `<dl>`
  `68px 406px` with 8px/4px gaps at 10.5px; Deny 24.792x42.583 ghost, Approve
  once 26.125x85.729 secondary, the batch 24.792x139.417; innerText
  byte-identical in all three. `ConsequenceBanner` has three states — publish,
  publish-failed, and §34d's overwrite shape — and measures identically on
  every shared figure, with the checkbox, the meta and the batch simply absent
  (§43b).
- [x] **4.5 `key.publish`** — outward, confirming in the banner, replaced by
  `publishedAs` + link on success. Declared on `openpgp-public` alone
  (asserted, twice: no other kind declares it, and no other action is
  `outward`). Publish stops being brand-filled per §34a — it renders through
  `data-action-tier="outward"`, measured `rgb(227,179,65)` on a
  `color(srgb ... / 0.55)` border with no fill. The `publishable` flag and
  `publishConfirmLabel` are gone: the kind table already said which artifacts
  are publishable and the shell was recomputing it beside `publishArtifact`'s
  own throw, three statements of one fact. The tray's Outputs tab had to be
  given the route too, or a public key there would render a disabled Publish
  whose stated reason was not the true one. Verified live on /toolkit.html
  against a dev server with no directory: "Request failed (404)" verbatim in
  `--error`, banner open, button live.
- [x] **4.6 `keyring.add`** — §35f, `f800a9b`. Every criterion met, against a
  real `fake-indexeddb` vault with bodies taken from real `runRecipe` output
  rather than fixtures (`keyring-add.test.js`): `genkey ed25519` files as kind
  `ssh` under a `SHA256:…` id with a listable `ssh-ed25519 AAAAC3…` public line;
  `genkey x25519` files as `raw` under an `spki:SHA256:` id; a symmetric key
  never renders the action, by omission and not as a disabled button — the four
  kinds that declare it are `key`, `keypair-private`, `openpgp-private` and
  `ssh-private`, asserted, and the three public kinds are asserted not to; the
  receipt reports `My Keys SHA256:…`, which is the line the Activity log prints.
  Two things beyond the criteria are worth knowing: the encoder is `agent.save`'s
  own, lifted out as `vaultMaterialFromPrivateJwk` and shared, with a test
  pinning the click-path and recipe-path ids **equal** (two encoders would mean
  one key growing two rows); and the least-specific `key` kind answers "does
  this body have a private half" at runtime with a sentence, because it is the
  one kind that by construction cannot know.
- [x] ⚙ **4.7 `saveKey({ onConflict })`** — `6b0ec96`. `"refuse"` is the
  **default**, so the tile path gets it without asking, and `agent.save` passes
  `"replace"` on both its paths. The judgement worth preserving: an unspecified
  option must not be the one that weakens a key, so a caller that means to has
  to say the word — and an unrecognized value throws rather than falling through
  to the safe branch, which is how a caller ends up believing it asked for
  replace. Protection is read off the record's **outer wrap**, not its label,
  since the wrap is the property that actually holds. `agent.save`'s behaviour
  is unchanged and asserted (`agent-multikind.test.js`); `patchKeyMeta`,
  `touchKeyUsed` and `unlockKey`'s backfill do read-modify-write, never rebuild
  the record, and never reach the guard — pinned by a test rather than assumed.

  **Deviation on the last criterion.** "A conflicting tile save refuses and
  raises the overwrite banner" — it refuses, and the refusal is terminal. There
  is no Replace to raise a banner for, because offering one would put the single
  click the default exists to refuse behind one more click (`f800a9b`). Replace
  re-wraps correctly and is exercised by `agent.save`; what is not built is a
  UI that asks for it. See the §34d note above.
- [ ] **4.8 `pubkey.import`, `shares.print`, `key.copyPublicLine`.** Accept:
  import writes through `cachePut` and the row reflects it without a reload;
  Print cards opens `ShareCards` with its own reveal still armed (the tile must
  not pre-reveal); the public line copied is byte-identical to `ssh.encode`'s
  output for the same key.

## 5. The kinds — §35, §37

- [ ] **5.1 `KeyCard` + `keypair-public` / `keypair-private`** (§35c/§35d).
  Accept: catalog fixtures for ed25519, ec/p256, rsa, and x25519 (the last
  showing *no* public-line row and no public-line action); fingerprint rendered
  in kind shape for pgp / ssh / raw.
- [ ] **5.2 `openpgp-public` / `openpgp-private`** (§35e). Accept: Publish
  declared on `openpgp-public` only; the private kind masks and offers no
  Publish at any state.
- [x] **5.3 `ciphertext` / `envelope` view** over `packet-map.js`.
  `PacketMapCard` maps the framing — SKESK vs PKESK, the SEIPD, byte spans —
  with the armor one toggle down. `packet-hex-view.js` is *not* used: a hex
  dump of a sealed body is the decrypt inspector's job, and in a list row it
  would be the same wall of characters the armor already was. The envelope
  tile keeps the engine's "required for recovery (not a share)" label, which
  is the artifact's own label.

  **Two corrections since, both about that label.** It *did* need help: in a
  narrow panel the row cuts it at "OpenPGP envelope — required f…", and the
  half that gets cut is the half that stops a witness counting the envelope
  toward the threshold. The row's `title` makes it reachable on hover, which
  is not an answer for someone reading a printed sheet or a phone.
  Restructuring the identity row was rejected as the wrong size of fix — it
  would change every tile's measured anatomy to serve one label — so the kind
  states the instruction as a caption in the card, at full width, with no
  `truncate`. And it could only be unconditional once the second correction
  landed: **both `gpg.symencrypt` modes stamped `role: "envelope"`**, so a
  `mode=passphrase` message badged **ENVELOPE** while its own label called it
  "OpenPGP symmetric ciphertext". `mode=master` is the ceremony's branch and
  keeps the role; the passphrase branch is a `ciphertext`, which is what it
  always was. Nothing about either artifact moves — same body, same `.asc`,
  same `PacketMapCard` — only the word the badge says.
- [x] **5.4 `share` kind — and it is not `ShareCards`.** Deviation, argued:
  `ShareCards` is the *set's* surface, with its own per-mount reveal and its
  own print warning, and mounting it per-tile would put a second reveal gate
  behind the tile's first and print one card at a time. What the tile was
  missing is not a card, it is the one public fact a masked share tile could
  not state — which share, and how many recover the secret — so the kind
  declares a `publicView` (`ShareIdentity`) and **no `view`**. A revealed
  share therefore keeps the tile's own format bar, Hide button and 15s
  auto-hide, all three of which a body widget would have silently removed.
  `ShareCards` and the `share-only` tone rules are untouched.
- [x] **5.5 `recipients`, `sshsig`, `qr`, `receipt` kinds** (§37b). One catalog
  state each under `#artifacttiles`; the QR tile renders via a
  `data:image/svg+xml;base64,` `<img>` (measured live: 95×95 natural, no
  console error, and the page's own policy reads `img-src 'self' data:`).
  No per-row *Import to key cache* on `recipients` and no *Print* on `qr`:
  neither service is injected into a tile action yet, and a button whose
  handler does not exist is worse than the absence.
- [x] **5.6 `text` and `secret` claimed with no view.** The raw body, its
  format bar and its reveal gate are already the right rendering of an opaque
  value. Claiming them buys `data-artifact-kind="text"` instead of
  `"fallback"`, a label for the badge, and a sentence for the no-body case —
  and it puts the fallback back to meaning what §32f says it means: an
  artifact the table does not know about. **Known gap kept honest here:** a
  `pem`/`der` export still lands as `text`. The projection calls it `key`
  (§35e), but `KeyCard` parses JWK, so promoting it today would replace a
  readable armor body with a nearly empty card. That widening waits on a
  `KeyCard` that can read PEM.

### Kinds that shipped outside this checklist

Three arrived after the list was written, each because a real artifact was
landing on the wrong tile. They are recorded here rather than given unit
numbers, because the design did not ask for them.

- **`ssh-public` / `ssh-private`** (`d379b3d`, typed by `7d563cd`) —
  `SshKeyCard`. The one-line public form had **no kind at all**: it resolved as
  `text`, so its whole body was one unreadable base64 run and Download wrote
  `pub.txt`, a kind being the only thing allowed to correct an extension. Two
  *roles* rather than `text`/`secret` plus a tag, and the reason is recorded in
  `types.js`: `role` is stamped from **sensitivity** at both text emit sites, so
  the same private block came out `secret` through `out @priv` and `text`
  through a dangling tip, while `ArtifactMatch.role` is exact — a kind matching
  one spelling silently disowned the other. This is the same failure
  `TYPE_OWNED_ROLES` fixed for `sshsig` and `token`, met a second time.
  `ssh-private` downloads as `.key` and declares no `key.publish` at any state.
- **`keypair`** (`83ef038`) — the tip of a bare `genkey`, before any `out` has
  asked for a half. It resolved to the least-specific `key` kind, **whose masked
  body is the public-half card** — so a keypair was drawn by the card that means
  "the public half" and read as a public key. The type was never wrong; the
  rendering was. It declares no `keyring.add`: the body is empty by design, so a
  disabled button reading "carries no key material" would be true of the
  artifact and false of the keypair, which is the worst kind of accurate.
- **`otp-code`** (`51a8cb1`, over `74fdf3d`'s `otp.*` ops) — `OtpCodeCard`,
  matching `role: "text"` + tag `otp-code`. The design decision worth keeping is
  a refusal: **the countdown recomputes nothing.** A Refresh button is exactly
  what §37a forbids — a freshly computed code would be a value with no step
  behind it in the recipe and nothing in the receipt describing it — so what
  ticks is the *clock*, against an absolute expiry derived from the run's own
  `otpStep`/`otpPeriod`. The tile drains, says **expired**, and keeps showing
  the value the receipt covers. The facts it needs ride `traits`, which is the
  one bag every projection copies wholesale (see HANDOFF's `OutputList` trap).
  The code is deliberately **not** `sensitive`; the `otpauth://` URI is, because
  the URI *is* the secret.

## 6. Auditability — §36

- [x] **6.1 Activity log store** — session-scoped, append-only, digests only.
  Accept: a unit test asserts no entry can carry `content`; entries clear with
  Clear session / Clear sensitive data.

  **Checked**: `activity-log.test.js` asserts an entry records a digest and
  never the content, that it is the *same* digest function receipts use so the
  two cross-read, that the module names no `localStorage` / `sessionStorage` /
  `indexedDB` (asserted comment-stripped, and again in
  `artifact-migration.test.js` §38d), and that Clear sensitive data empties it
  alongside the outputs.
- [ ] **6.2 Appended by the action runner, not by handlers.** Accept: a test
  runs every action in the table with stub services and asserts each produced
  exactly one entry — so a new action cannot forget to log.
- [ ] **6.3 Tray tab + copy-as-text.** Accept: catalog state; the copied text
  contains digests and ids and no artifact content.

## 7. Not being built, and why

- **`hkp.publish` op** — §38b. Recipes must not publish on the runner's behalf.
- **Upstream keyserver publish** — no write path exists (`upstream-hkp.js` is
  lookup-only). Separate capability; already open question 5 in
  DESIGN-ITERATION-PROMPT.
- **Promote-to-recipe** — §36c, rejected with reasons, not deferred.
- **"Set as signing key"** — §35g, rejected: it would make a recipe's meaning
  depend on device state.
- **Decrypt with… / Verify threshold / Send to peer / Save as group** — §37a,
  all excluded by the one rule (a button may move an artifact, never compute a
  new one); `Send to peer` additionally impossible because `channel` is a HANDLE
  type that does not outlive its run.
- **A persistent activity record** — §36d. It names key ids and directory URLs;
  `workspace-store.js` already states why that does not go in localStorage.

## 8. Verification notes for whoever builds this

- The catalog at `/toolkit-widgets` is the cheapest way to see a widget's real
  states, and it has caught two defects nothing else did (HANDOFF). Add states
  before wiring, not after.
- The dev server's CSP is weaker than production. A `data:` image and a new
  enumerated CSS block can both look fine in `serve` and fail in the build —
  check `npm run build` output and the report-only banner from
  `boot-diagnostics.js`.
- Clipboard actions need a real input event; a scripted Run click has no
  transient activation and `writeText` is denied.
- This design pass measured the shipped `OutputList` live on
  `http://localhost:4188/toolkit-widgets.html` (viewport 1026×1258, working
  pane) — the numbers in §33a and unit 3.1 are from that session, not from
  reading the source.
