# design-sync notes — Basilisk

## Shape

Basilisk is an **application**, not a published component library:
`web/package.json` is `private: true` with no `main`/`module`/`exports`, and
`web/dist/` holds built HTML pages, not a component dist. It does now carry a
`types` entry — see "The type surface" below; that field is read by this sync
and by nothing else. So:

- `shape: "package"`, and the converter has no library entry of its own.
- `web/src/ds-entry.ts` is a **hand-authored barrel** written for this sync —
  it re-exports exactly the components that render standalone. Pass it as
  `--entry web/src/ds-entry.ts`. Without it the converter synthesizes an entry
  by scanning all of `src/`, which sweeps in the coupled toolkit widgets
  (`ToolCard` needs the op registry, `OutputList` needs artifact fixtures,
  `ToolkitShell` needs the whole notebook) — none of which render alone.
- Nothing in the app imports `ds-entry.ts`. It exists so the synced surface is
  a reviewed decision rather than a side effect of a heuristic.

## Build command

```sh
cd web && npm run build:types    # emits web/.ds-types/ — the prop contracts
cd web && npm run build          # produces dist/assets/toolkit-<hash>.css
cp web/dist/assets/toolkit-*.css web/.ds-styles.css
node .ds-sync/package-build.mjs --config .design-sync/config.json \
  --node-modules web/node_modules --entry web/src/ds-entry.ts --out ./ds-bundle
node .ds-sync/package-validate.mjs ./ds-bundle
```

`build:types` is **not** optional and **not** wired into `npm run build` — see
"The type surface" below for both halves of that sentence. Skip it on a fresh
checkout and every shipped `.d.ts` is `[key: string]: unknown` again; run it
after the sources changed and forget it, and the contracts silently describe
the previous commit. It takes about a second.

The converter must be run from the **repo root**, not from `web/` — the paths
in the command are root-relative and `cd web && node .ds-sync/…` is a
MODULE_NOT_FOUND.

Do **not** run `npm ci` reflexively — `node_modules` is already installed and
green, and a reinstall can disrupt a concurrent session working in this tree.

## The type surface

The design agent's API contract for every component comes from the package's
declared type root. Basilisk has no dist, so for the first several syncs there
was no such root and all 50 `.d.ts` files shipped `[key: string]: unknown` —
the whole contract blank, for every component, with the agent left to guess
prop names. Fixed 2026-08-14; **50 total / 0 empty** as of that build.

The mechanism is three small pieces, and the reasoning for each is the reason
not to "simplify" it later:

- **`web/tsconfig.dts.json`** — a declaration-only emit whose `files` list is
  exactly `["src/ds-entry.ts"]`. TypeScript then emits the transitive closure
  of the barrel, ~182 files. A whole-project emit is 487 files, most of them
  the test tree, and it exits 1 on a TS4058 in
  `src/test/helpers/verb-smoke.js` (openpgp's `KeyPair`). Scoping to the
  barrel means the shipped type surface is the *same* reviewed decision
  `ds-entry.ts` already is, rather than a second, wider list that can drift
  from it. `rootDir: "src"` so `.ds-types/` mirrors `src/`.
- **`"types": ".ds-types/ds-entry.d.ts"`** in `web/package.json`. This is the
  pointer that was missing; emitting without it changes nothing, because
  `findTypesRoot` (`.ds-sync/lib/dts.mjs`) reads the *declared* root. The
  field is inert for everything else: nothing imports `basilisk-portal`, the
  package is `private`, and Vite, vitest and `tsc --noEmit` never consult
  `types`. Verified — all four gates unchanged (201 files / 3827, tsc 0,
  `npm run build` ok, pytest 249). A `"//types"` comment key in the manifest
  says this in place, since JSON cannot.
- **`"build:types": "tsc -p tsconfig.dts.json"`**, deliberately *not* chained
  onto `prebuild`. The constraint on this change was that a types entry must
  not alter how the app builds; a failing emit hanging off `prebuild` would
  break `npm run build` for everyone, for a file only this sync reads. The
  cost of that choice is a staleness risk, recorded under "Re-sync risks"
  alongside the identical one for `.ds-styles.css`.

Two traps that were predicted and both landed:

- **Most components declare a local `type Props`, not an exported
  `<Name>Props`** (`ArtifactAction`, `SuggestChip`, `Glyph`, `ModeToggle`,
  `PresetMenu`, `ReadinessBar`, `SessionStrip`, `ConnectionsPanel`). No rename
  was needed and none should be done: `propsBodyFor` falls back to the
  component symbol's first call signature, and declaration emit keeps the
  local `type Props` in the file, so the parameter type resolves to the real
  thing. `cfg.dtsPropsFor` is therefore **unused** — no component needed a
  hand-written body, which is the outcome to protect. If a future component
  comes back empty, check that it is reachable from `ds-entry.ts` before
  reaching for a hand-written contract.
- **A real type root widens the component set.** `source-kit.mjs` unions
  `componentSrcMap` with every PascalCase value export the type root shows, so
  the sync jumped 50 → 75 the moment `types` resolved: the 25 compound
  subparts (`SheetContent`, `DropdownMenuItem`, `TooltipTrigger`,
  `ToggleGroupItem`, `GateFact`, …). Each would have drawn its own floor card
  for something that cannot render alone — `SheetContent` outside a `Sheet`
  has no portal. They are excluded with `null` entries in `componentSrcMap`,
  which is the sanctioned route and keeps them *importable* by previews (the
  `null` only drops them from the component list, not from `exported`). This
  is the same control point the "excluded by omission" note warns about,
  except the default flipped: with a type root, an export added to
  `ds-entry.ts` is now **included** unless someone says otherwise.

## Gotchas hit on the first sync

- `cssEntry` is **package-relative and bounded to inside the package**. A path
  like `../.design-sync/.cache/compiled.css` is silently skipped with
  `resolves outside the package`. Hence `web/.ds-styles.css` (gitignored).
- The compiled stylesheet's filename is **content-hashed**, so it cannot be
  referenced directly from config. The `cp` step above stages it at a stable
  path; re-run it after every `npm run build` or the sync ships stale CSS.
- Without `--entry`, the converter looks for `node_modules/basilisk-portal/`
  and dies with ENOENT — npm never self-installs a package into its own repo.

## Known render warns

- `[RENDER_BLANK]` on any component with **no authored preview** is the
  typographic floor card, not a failure. On the first sync that was CastDot,
  KindGlyph, ScrollArea, Separator, ToolboxDot, Badge, Glyph, Input, Textarea.
- Previews render in the **light** colour scheme (headless default) while the
  product is dark-first. Both themes are supported and light was contrast-fixed
  on 2026-07-31, so this is legitimate — but it means the cards do not show the
  dark look the app usually wears.

## Findings from the preview-authoring pass

- **Headless capture never paints a scrollbar thumb.** `ScrollArea`'s entire
  visible contribution is the `::-webkit-scrollbar` styling in `toolkit.css`,
  and no sheet can show it — the region only reads as "bounded and clipped".
  Its previews compose around that (a cut row plus a footnote, and a
  short-content cell for contrast). Do not grade it `needs-work` and go
  hunting; the thumb is unphotographable here.
- **Renders-nothing is a real design state, and needs author scaffolding.**
  `CastDot` renders nothing for toolboxes that make no self-test claim and
  when `status` is null; `KindGlyph` renders nothing for unmapped kinds. The
  house pattern established here: a dashed 12–16px slot plus a caption naming
  the reason, so absence reads as intent rather than breakage.
- **`Glyph`'s `size` prop survives only because the hard-width `.ops-glyph`
  rules in the compiled CSS are ancestor-scoped.** The unscoped rule sets only
  opacity/display/flex-shrink. If one of those width rules were ever
  unscoped, every size would render identically — a `Glyph` sheet where 16,
  18 and 22 look the same is that symptom.
- **A dead value shape exists.** `shapeForType` handles `channel`, there is a
  dedicated `[data-kind="channel"]` triangle rule, and `KIND_GLYPHS` maps it —
  but no op declares `output: "channel"`, verified by grep. Tracked separately;
  `ToolboxDot.Shapes` renders it (the component supports it) while
  `ToolboxDot.InAPipeline` uses only real registry outputs.

## Findings from the artifact-card pass

- **A card that parses its own `content` cannot be previewed with a
  placeholder.** Every card in the second batch (`KeyCard`, `SshKeyCard`,
  `PacketMapCard`, `ReceiptCard`, …) returns null or falls to its `empty` state
  for a body it cannot parse — which is the *same* floor card an unauthored
  preview draws, so the fix looks like the bug. The props have to be real
  artifacts, and they were obtained by running the real thing:
  - `basilisk run` (`web/cli/basilisk.js`) for anything headless — `genkey`,
    `gpg.genkey`, `qr`, `run.receipt`, `ssh.encode`.
  - `lib/pgp/encrypt.js` and `openpgp` directly for ciphertext and for the
    recipients list, so `encryptCapable` is *asked* of a real key rather than
    asserted (the false row is a real signing-only key).
  - The checked-in `web/src/test/fixtures/ssh/` fixtures for SSH keys and
    sshsig. `fingerprints.txt` beside them is an independent check: the
    `SHA256:` lines `SshKeyCard` renders match `ssh-keygen -lf` character for
    character, which is stronger verification than the screenshot.
- **WebRTC bodies needed a real browser, and got one.** `rtc.*` and
  `stun.check` have no headless path (`RTCPeerConnection` is browser-only, and
  the CLI refuses those toolboxes). The recipe that worked: esbuild-bundle
  `rtc-ops.js` + `quorum-ops.js` to an IIFE, serve it over `http://127.0.0.1`
  (WebCrypto needs a **secure context** — `about:blank` and `setContent` both
  fail with "The WebCrypto API is not available"), and drive it with the
  Playwright already in `.ds-sync/node_modules`. Candidate-pair and
  data-channel stats came from two `RTCPeerConnection`s wired to each other in
  the same page.
- **The reflexive address a STUN probe returns is the machine's real public
  IP.** It is redacted to 198.51.100.7 (RFC 5737) in `NetworkArtifact.tsx`, and
  the file says so. Anyone re-running that probe must redact again before
  committing — this content ships to claude.ai.
- **A `display: grid` wrapper crops truncating children.** Grid items default
  to `min-width: auto`, so a `truncate`d SSH public line inside one runs past
  the card and trips `[GRID_OVERFLOW]`. Every multi-card preview here uses
  `gridTemplateColumns: "minmax(0, 1fr)"`; that is the fix, not `cardMode`.
- **`OtpCodeCard.nowMs` is the only way to photograph a countdown**, and it
  works: one fixed artifact at three injected instants gives full / urgent /
  expired, because a TOTP step ends at an absolute `(step + 1) × period`.
- **`GateFact` is exported from `ds-entry.ts` but deliberately absent from
  `componentSrcMap`.** `GateBanner.facts` needs `<dt>`/`<dd>` pairs as *direct*
  grid children, so the banner is unusable without it — but it is a fragment
  with no standalone rendering and would only ever draw a floor card of its
  own. An export without a map entry is fine; `buttonVariants` already was one.

- **The capture harness pins the browser clock to `2024-05-15T12:00:00Z`**
  (`package-capture.mjs`), so any fixture whose validity is checked against
  "now" must be dated *behind* that. `OpenPgpKeyCard`'s armor was generated on
  the day it was authored, which is that clock's future, so the self-signature
  was not yet valid and `getPrimaryUser` rejected — leaving `uid` empty while
  the fingerprint and creation date (no date validation) and
  `getExpirationTime` (answers `Infinity` on failure) all rendered normally.
  The card read as a live bug in the component and is not one: it renders
  correctly under a real clock, verified both ways against the same bundle.
  The fixture is now dated 2023-06-01 and the preview says why. **Any
  time-validated fixture — certificates, signatures, expiring keys — inherits
  this.** A cell that renders every field except the one behind a signature
  check is this bug, not a parser bug.

## The shared-notebook widening (38 components)

- **`quorum` is not stale naming.** It survives the shared-notebook redesign as
  two live things: the authenticated transport the session sits on top of
  (`quorum.offer`/`quorum.join`/`quorum.send`/`quorum.recv` are implemented
  steps — `registry.js`, `engine.js` — and `origin: "quorum"` is a live link
  kind), and the Shamir threshold in `ShareCards`/`CeremonySheet`, where "any k
  of n" is simply what a quorum is. Do not "clean it up".
  `quorum.html` **was** a built page and is not one any more: the room moved
  into the toolkit's session sheet and `/quorum` 301s to `/toolkit`. The steps
  and the link kind are untouched by that, which is the point of this note.
- **The session/peer/share widgets are not coupled.** The exclusion rule at the
  top of `ds-entry.ts` is about `ToolCard`/`OutputList`/`ToolkitShell`, which
  need the op registry or the notebook. The twelve added here read no context
  and no store — checked, not assumed.
- **`IntegrityPanel` is in, as of the 2026-08-14 sync.** This note used to say
  it was "deliberately still out" because it reached `node:crypto` through
  `deployment-check.js` → `module-integrity.js` and the converter's esbuild
  would not tolerate the unresolved builtin. It builds and renders now, and
  arrived in that sync's `added` partition. If it ever regresses, the old
  remedy was a `lib/bundle.mjs` fork via `cfg.libOverrides` — but check first
  whether the import path still reaches a node builtin at all before assuming
  that is still the cause.
- **Portal/fixed components need `cfg.overrides.<Name> = {cardMode: "single",
  primaryStory}`** or `package-validate` raises `[GRID_OVERFLOW]` — no grid can
  present content that portals out of its cell. Applies to `Sheet`,
  `DropdownMenu`, `Tooltip`, `PresetMenu`, `CeremonySheet`.
- Radix overlays must render `open` (a closed sheet photographs as an empty
  frame) **and** suppress autofocus with `onOpenAutoFocus={(e) =>
  e.preventDefault()}`, or the first field is captured focused with its text
  selected and reads as an accident.

## Fixtures must be generated, not invented

- **BLIP39 mnemonics and VSS commitments cannot be written by hand.** A
  mnemonic is checksummed over a fixed wordlist, so plausible words render
  "Unknown SLIP-39 word", and fabricated hex is "not valid P-256 points" — a
  cell captioned as a successful check then shows a parse failure. Generate
  them with a throwaway vitest test (vitest has the Vite resolver; plain node
  cannot load `wordlist.txt`) running
  `random 32 | vss.split threshold=3 shares=5 | tee - vss.commitments | blip39`.
- **`traits.shareOf` is the share *number*, not the total** — the name reads
  like "of N" and means the opposite, and `engine.js` sets it from
  `shareIndex`. `shareIdentity` prefers it over `shareIndex`, so a fixture
  putting the total there renumbers the share.
- **`ShareCards` derives the total from how many artifacts it is given.** Pass
  the whole split or every card misstates itself; one card alone printed
  "Share 2 of 1 — any 3 of these 1 reconstruct the secret".
- **The `@` → `$` slot migration left stale spellings in the previews** —
  `out @kp`, `key=@release`, `in @secret`. These teach the design tool a recipe
  language this build no longer parses, so they were migrated. Emails and SSH
  comments (`ada@lovelace.dev`) keep their `@`. **`ReceiptCard` is left alone
  on purpose**: its fixture is a signed receipt whose `recipeDigest` is
  computed over that exact `recipeSource`, so editing the text would make the
  digest a lie. Regenerate the receipt if it ever needs updating.

## Re-sync risks

- **`web/.ds-styles.css` goes stale silently.** It is a copy, gitignored, and
  nothing rebuilds it automatically. If the toolkit's CSS changed and this file
  did not, every card renders against the old tokens with no warning.
- **A captured plan fixture goes stale when the planner gains a field, and it
  fails as a blank card.** `PlanPanel`'s preview is real `planRun` output by
  design ("a hand-written plan drifts from the shape the planner emits"), and
  that is exactly what happened: `planRun` gained a per-cell `publishes`, the
  six captured fixtures predated it, and `cell.publishes.length` threw
  `TypeError: Cannot read properties of undefined` — `[RENDER] root empty`,
  the only failure in the 2026-08-14 sync. The component was correct
  throughout. Regenerate rather than patch: the six cases are the same
  two-cell ceremony from different seats, and their inputs are recoverable
  from each fixture's own scalars (`me`, `play`, `bound`, cell peers, refusal
  reason) — reconstruct, run the real `planRun`, and check the scalars match
  before writing. `WaitingOnAPeer` is the base ceremony from okafor's seat,
  not a third cell; its `published-slot` **wait** is what identifies it.
  Any other preview holding captured planner or engine output inherits this.
- **`ds-entry.ts` drifts from the component set.** A component added to
  `componentSrcMap` but not exported from the barrel will not be in the bundle;
  the reverse ships a component nobody scoped. Keep the two in step.
- **Coupled widgets are excluded by omission, not by a rule.** Someone adding
  an export to `ds-entry.ts` silently widens the sync. That is the intended
  control point — but it is a control point, so review it. Since the type root
  landed the widening is **automatic**: `source-kit.mjs` unions the type root's
  PascalCase value exports with `componentSrcMap`, so a new barrel export
  becomes a component with a card of its own unless it gets a `null` entry.
  The 25 `null`s at the foot of `componentSrcMap` are the compound subparts
  (`SheetContent`, `DropdownMenuItem`, `TooltipTrigger`, `ToggleGroupItem`,
  `GateFact`) held out on exactly that ground — they cannot render alone.
  Deleting one of those `null`s adds a floor card, not a component.
- **`web/.ds-types/` goes stale exactly the way `.ds-styles.css` does**, and
  it is the artifact the design agent codes against. It is gitignored build
  output, `npm run build` does not regenerate it (on purpose — see "The type
  surface"), and nothing warns. Two failure shapes, neither loud:
  - *Absent* (fresh checkout, no `build:types`): `findTypesRoot` falls through
    to `web/` itself, the log reads `[DTS] parsed 1 .d.ts files`, and all 50
    contracts ship blank again. **The one-line canary is that log line** —
    a healthy build says `parsed 182` and `[DTS] 50/50 components`.
  - *Stale* (sources changed, emit not re-run): the contracts describe the
    previous commit, and every count still looks right. A prop the design
    agent is told exists and does not is worse than a blank contract, so
    `build:types` belongs at the top of the sequence, not as a repair step.
- **The `[DTS] N/50 components` line is the real check, not the file count.**
  A component reachable from `ds-entry.ts` but whose props the extractor
  cannot resolve is a silent single-component regression to
  `[key: string]: unknown`; the bundle still validates and still ships. Count
  it after every sync — `grep -c "\[key: string\]: unknown"` across
  `ds-bundle/components/*/*/*.d.ts` should be 0.

## The upload step is bigger than it looks

- **`write_files` needs an explicit `localPath` on every entry** — `{path}`
  alone is rejected (`Each file needs exactly one of "data" or "localPath"`),
  and there is no glob or manifest form. This bundle is **256 content files**,
  so the upload is ~23KB of enumerated path pairs across two ≤256-file calls,
  and that has to be budgeted for *before* starting: a partially-written
  content set is the one genuinely bad outcome, because the old
  `_ds_sync.json` keeps vouching for files that were just replaced and the
  next sync's diff will never repair them. Enumerate the list into
  `.design-sync/.cache/upload-list.json` first (never a bare `/tmp` path — on
  Windows, node's `/tmp` and Git Bash's `/tmp` are different directories), and
  do the writes in one uninterrupted stretch.
- Order is fixed: sentinel → all content → deletes → sentinel re-arm →
  `_ds_sync.json` **absolutely last**, in its own call. Writing the sentinel
  early is safe and idempotent on its own; it only asks the app to recompile
  next time the project is opened.
