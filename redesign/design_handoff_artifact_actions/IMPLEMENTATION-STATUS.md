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

Not built: `ArtifactTile` as an extracted component (§33a — the anatomy is in
place inside `OutputList`, but not lifted out), the §34c `ConsequenceBanner`
and the migration of Publish onto it, §37's remaining kinds (in progress),
§38 migration, and `keyring.add`.

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
- [ ] **2.4 Catalog section `#artifactkinds`** on `/toolkit-widgets` rendering
  one tile per kind plus the fallback. Accept: section present; every kind's
  `empty` and `failed` state has a fixture (the catalog is how design fit is
  judged here, and it has caught two real defects per HANDOFF).

## 3. `ArtifactTile` and the common base — §33

- [ ] **3.1 `ArtifactTile` component** — identity line, body, action row,
  receipt line (§33a). Accept: measured on `/toolkit-widgets`, row padding
  `8px 10px`, row gap `4px`, list radius `10px`, 1px `--border` on `--surface`,
  action buttons 22px high at 10px — i.e. unchanged from the shipped tile
  (baseline measured 2026-07-31).
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
- [ ] **4.4 `GateBanner` extraction + `ConsequenceBanner`** (§34c) — one shell,
  `ApprovalBanner` re-expressed over it with no behaviour change. Accept:
  `ApprovalBanner`'s existing catalog states render identically
  (`getComputedStyle` on the `--warn` left border and the button weights, the
  same measurements §27's build used); `ConsequenceBanner` gets its own catalog
  states for publish and overwrite.
- [ ] **4.5 `key.publish`** — outward, confirmation per §34c, replaced by
  `publishedAs` + link on success (existing behaviour). Accept: declared on
  exactly one kind (asserted); the "Where" line names this site's directory and
  never an upstream host; failure renders the thrown message verbatim and leaves
  the button enabled.
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
- [ ] **5.3 `ciphertext` / `envelope` view** over `packet-map.js` /
  `packet-hex-view.js`. Accept: catalog state; the envelope tile keeps the
  engine's "required for recovery (not a share)" label.
- [ ] **5.4 `share` kind → `ShareCards`.** Accept: a split's outputs render as
  cards from the cell list, not only from `CeremonySheet`; the amber
  `share-only` tone rules are untouched (HANDOFF: "`share-only` must never
  render green").
- [ ] **5.5 `recipients`, `sshsig`, `qr`, `receipt` kinds** (§37b). Accept: one
  catalog state each; the QR tile renders via a `data:image/svg+xml;base64,`
  `<img>` and a CSP check on the live page shows no violation (add the
  report-only header check to the catalog page, which is already measured
  there).

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
