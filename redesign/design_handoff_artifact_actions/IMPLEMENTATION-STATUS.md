# Artifact kinds + actions — implementation status

Checklist for building [ARTIFACT-ACTIONS-DESIGN.md](./ARTIFACT-ACTIONS-DESIGN.md),
in dependency order: the type/engine plumbing first (testable headlessly, no
UI), then the registry and the tile, then actions by tier, then the kinds that
motivated the request. Every unit lists acceptance criteria measurable by test
or by browser measurement (`getComputedStyle` / DOM, per HANDOFF — screenshots
are unreliable here).

**Status as of 2026-07-31: units 1, 2, most of 3, part of 4, and §35/§36 are
built.** Shipped: the role vocabulary, projection floor, keypair/recipients
role stamping and `RECEIPT_VERSION` 2 (unit 1); the resolver, the kind table
with the three existing renderers folded in unmodified, and `OutputList` wired
to both (unit 2); the two §39 foundations, the three-tier action row and
disabled-with-reason (unit 3); the global action table with injected services
and the `copy` / `key.copyFingerprint` / `key.copyPublicLine` actions (unit 4,
partial); the §35 key tiles (`keypair-public`, `keypair-private`, `key`,
`openpgp-public`, `openpgp-private`) with `publicView` so a masked private key
is not blank; and the §36 Activity log with its tray tab.

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

**§33a, §34c and §38 are built as well.** `ArtifactTile` is its own component;
`GateBanner` is `ApprovalBanner`'s chrome extracted with no behavioural change
and `ConsequenceBanner` is its second user; `key.publish` is an entry in the
action table at `tier: "outward"`, declared by `openpgp-public` alone, and it
confirms in the banner rather than the popover. §38's clauses are asserted in
`artifact-migration.test.js` — the section is all negatives (an op not added, a
name not retired, a store not bumped), and negatives do not fail loudly on
their own.

Not built: `keyring.add`, still blocked, and with it §34d's overwrite
confirmation — the banner *shape* exists and has a catalog state so its wording
can be argued, but nothing raises it. The `Add to keyring` half of §38a's doc
steer is held back for the same reason: pointing a doc at a button that does
not exist is the failure HANDOFF records as "the card was telling custodians to
run the wrong op". The steer ships with its *reason* (a recipe containing
`agent.save` writes to the reader's keyring) and gains its second sentence when
the button does.

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

One defect found in passing and filed rather than fixed: opening any Radix
`Sheet` in the *built* app inserts an inline `<style>` that `style-src-elem`
blocks with disposition `enforce`, so the dialog's scroll-lock silently does
not apply in production. Reproducible on any tile's Expand.

**`keyring.add` is blocked, not merely unscheduled.** It needs
`saveKey({onConflict})` — the fix for a live bug where re-saving a key
silently replaces its protection, so a passkey-protected key can be
downgraded to device-only with no warning. Shipping the button first would
mean its failure mode is weakening a key. Check `grep onConflict
web/src/lib/vault.js` before starting it.

Two corrections to this document's own premises, found by measuring:
`artifactMetaFromType` had **zero callers**, so "the type system can already
drive it" was aspirational; and unit 4.7's `saveKey({onConflict})` is blocked
on a live protection-downgrade bug being fixed in a separate session — check
`grep onConflict web/src/lib/vault.js` before starting it.

Engine/registry capabilities this design needs that do not exist today are
marked ⚙ — do not discover them mid-implementation. There are nine of them, and
three (1.1, 1.3, 1.4) are the load-bearing ones: without them the registry keys
off a field that half the artifacts do not carry.

---

## 1. Types and engine plumbing (no UI) — §32

- [ ] ⚙ **1.1 `ARTIFACT_ROLES` in `types.js`** — the one frozen list of the
  fifteen roles in §32c, exported. Accept: a unit test asserts every `role:`
  string literal appearing in `engine.js` is a member (a source grep in the
  test, the `toolbox-dot-css.test.js` style of guarding a duplication
  mechanically); adding an unlisted role fails.
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

- [ ] **2.1 `toolkit/artifact-kinds/resolve.ts`** — matcher per §32b (most
  matched tags wins) plus `FALLBACK_KIND`. Accept: unit tests for exact match,
  tag-subset match, specificity ordering, and fallback; a resolver call on an
  artifact with an unknown role returns the fallback and never throws.
- [ ] **2.2 `artifact-kinds/registry.tsx`** with the three existing renderers as
  entries (§32e). Accept: `NetworkArtifact`, `InspectorArtifact` and
  `JwtArtifact` are imported unmodified — a diff touching their internals means
  the abstraction is wrong; the seven network types are matched via the role
  projection, not via `hasNetworkRenderer`.
- [ ] **2.3 `artifact-kinds.test.js` — the coverage gate.** Every role in
  `ARTIFACT_ROLES` is claimed by at least one entry; no two entries can both
  match any `(role, tags)` the engine emits. Accept: the test fails when a role
  is added without a kind, and when a duplicate matcher is introduced.
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

- [ ] **4.1 Action table + injected `ActionServices`** (§33c). Accept: the table
  imports no vault, clipboard, network or file module; a unit test drives every
  action with stub services and asserts the `ActionResult`.
- [ ] **4.2 Inert actions** — `copy`, `download`, `expand`,
  `key.copyFingerprint`, `artifact.showQr`, `diag.configureTurn`. Accept: Copy
  routes through the existing `basilisk:clipboard-wrote` event so the shipped
  toast fires (clipboard test needs a *real* input event — a scripted click has
  no transient activation, per HANDOFF); Download routes through `file-ops.js`
  and fires `basilisk:file-saved`.
- [ ] **4.3 Mask gating** (§34b) — Copy disabled on a masked value with the
  verbatim reason; Download enabled; fingerprint/public-line enabled. Accept:
  the three cases asserted on one fixture; a test asserts *no* code path sets
  `revealed` from an action handler.
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
- [ ] **4.6 `keyring.add`** — §35f. Accept: an ed25519 keypair tile save lists
  in My Keys as kind `ssh` with a fingerprint equal to `ssh-keygen -lf`'s; an
  x25519 keypair saves as `raw`; a symmetric key never renders the action at
  all; the receipt line shows the vault id in kind shape.
- [ ] ⚙ **4.7 `saveKey({ onConflict })`** — `"refuse"` for the tile path,
  `"replace"` for `agent.save` (§34d). Today `store.put` clobbers silently,
  resetting `created`/`lastUsedAt` and downgrading protection. Accept: a
  conflicting tile save refuses and raises the overwrite banner; `agent.save`'s
  behaviour is unchanged (assert against the existing agent-ops tests);
  Replace re-wraps and the banner's stated consequences are what actually
  happen (passkey binding discarded).
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
  is the artifact's own label and needed no help.
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

## 6. Auditability — §36

- [ ] **6.1 Activity log store** — session-scoped, append-only, digests only.
  Accept: a unit test asserts no entry can carry `content`; entries clear with
  Clear session / Clear sensitive data.
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
