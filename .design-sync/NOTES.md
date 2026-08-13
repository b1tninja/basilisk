# design-sync notes — Basilisk

## Shape

Basilisk is an **application**, not a published component library:
`web/package.json` is `private: true` with no `main`/`module`/`exports`, and
`web/dist/` holds built HTML pages, not a component dist. So:

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
cd web && npm run build          # produces dist/assets/toolkit-<hash>.css
cp web/dist/assets/toolkit-*.css web/.ds-styles.css
node .ds-sync/package-build.mjs --config .design-sync/config.json \
  --node-modules web/node_modules --entry web/src/ds-entry.ts --out ./ds-bundle
```

Do **not** run `npm ci` reflexively — `node_modules` is already installed and
green, and a reinstall can disrupt a concurrent session working in this tree.

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
- **`IntegrityPanel` is deliberately still out.** It reaches `node:crypto`
  through `deployment-check.js` → `module-integrity.js` (a vitest-only fallback
  branch). Vite tolerates the unresolved builtin; the converter's esbuild does
  not, and there is no cfg hook for externals. Re-adding it means forking
  `lib/bundle.mjs` via `cfg.libOverrides`.
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
- **`ds-entry.ts` drifts from the component set.** A component added to
  `componentSrcMap` but not exported from the barrel will not be in the bundle;
  the reverse ships a component nobody scoped. Keep the two in step.
- **Coupled widgets are excluded by omission, not by a rule.** Someone adding
  an export to `ds-entry.ts` silently widens the sync. That is the intended
  control point — but it is a control point, so review it.
- The `.d.ts` contracts come from source, not a real build, so prop types are
  weaker than a library build would give. Adding a proper library build to
  `web/` would improve them.
