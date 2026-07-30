# Prompt: iterate on Basilisk Toolkit design concepts (v3)

Copy everything below the line into a fresh agent session.

---

You are iterating on the UI design of **Basilisk's Toolkit** — a notebook-style
crypto recipe builder (React 19 + TypeScript + Tailwind v4, dark-first). Your
job is to produce the next round of design concepts and, where a concept is
approved, retrofit it into the widgets. Design exploration happens in a Claude
Design project; implementation happens in this repo.

## Source of truth

- **Design project**: https://claude.ai/design/p/73a4f81e-d784-44bb-89c5-1fe4ff8a979e
  (DesignSync MCP, `method: get_file`). Main file: `Basilisk Toolkit v2.dc.html`
  — it is a large `<x-dc>`-wrapped HTML document; JSON-parse the tool result and
  write `.content` to a scratch file so you can Read/paginate it. `support.js`
  is only the dc-runtime renderer, no design content.
- Section **18** is the assembled shell (18b), cell lifecycle (18c), tray (18d).
  Section **19** (19a–19h) breaks out each widget with real prop names.
  Section **20** (20a–20h) resolves eight open questions: kit footer bar,
  Show-all toggle, per-arrow dim reasons, TopBar, ReadinessBar copy rules,
  SuggestRail deletion, --caret/--decode/--warn tokens, OutputList.
  Section **21** (21a–21e, Publish plumbing / kit search suggestion /
  nested-caret slot filtering / suite-status consolidation) and **22** (22a–22b,
  secret params / TURN-configure diagnostic action) are all implemented.
  **18 through 22 are fully implemented and pixel/behavior-verified as of
  2026-07-29** — treat them as the current baseline, not as pending work.
  (Sanctioned deviations, all real-repo-constraint-driven: the footer kit bar
  has a fourth "Base" button because this registry's base64/base32 ops are
  kitOnly; 21b's "openpgp.export" maps to the real `role: "public-key"`
  artifact tile gpg.genkey emits, since no literal `openpgp.export` step
  exists; 21d's `nestSlots` principle applies to this registry's actual
  nestable ops — `tee`/`foreach` branches/body — not the mock's fictional
  `signAndEncrypt`; 21e's per-suite popover notes are generic
  verified/unverified/browser strings, not real version numbers, since
  `ToolkitSuiteStatus` doesn't track those; RunBar/SessionStrip still ship
  without a live two-peer mesh test — WebRTC needs two real browser sessions,
  out of reach for single-agent verification, see item 6 below.)
- **Palette**: brand `#4cde82`, surface `#0d1117`, raised `#161b22`, borders
  `#30363d`/`#21262d`, text `#e6edf3`/`#8b949e`, caret + encode blue `#58a6ff`,
  decode purple `#d2a8ff`, warn amber `#e3b341`, error `#ff7b72`. The caret is
  always blue; green is reserved for brand actions; amber for readiness.

## Where things live in the repo

- Widgets: `web/src/toolkit/widgets/` — `OpsShelf` (kit footer bar, Show-all,
  caret banner), `OpsTile` (merged encode/decode row, per-arrow `needs`),
  `SuggestChip` (`placed | selector | ghost`), `InsertGap` (`pending` → HERE
  caret, `scale: default | nested`), `RecipeChipFlow`, `ToolCard` (`compact`,
  `pinned`, `onClose`), `RunBar` (`state: idle | blocked | running |
  waiting-peer`), `TopBar` (click-to-edit rename), `ReadinessBar`,
  `OutputList` (replaces the deleted `OutputCarousel`), `SessionStrip`
  (`offering | waiting | connected | closed`), `PresetMenu`, `ParamField`,
  `ModeToggle`, `MenuPopover`, `Glyph`. Barrel: `widgets/index.ts`.
  `SuggestRail.tsx` is **deleted** — don't resurrect it.
- Shell: `web/src/toolkit/ToolkitShell.tsx`; state hook
  `web/src/toolkit/useNotebook.ts` (`runProgress`, `stopRun`, `runningCell`,
  `quorumState`, `cancelQuorum`; `pendingInsert` caret state lives in the
  shell).
- Quorum toolbox: `web/src/lib/toolkit/quorum-ops.js` (run-scoped exchange
  manager wrapping `web/src/lib/quorum/rtc.js`'s `QuorumSession`; UI coupling
  is one-way via `window` events — `basilisk:quorum-state` out,
  `basilisk:quorum-cancel` in — so this module never imports React and the
  shell never imports WebRTC). 7 steps registered in `registry.js`:
  `rtc.ice`, `stun.check`, `quorum.offer/join/send/recv/close`.
- **Evaluation surface**: `web/toolkit-widgets.html` →
  `web/src/pages/toolkit-widgets.tsx`. This catalog page renders every widget
  in its scenario states from §19–21a. **When you change a widget or propose
  a new state, add the state here first** — it is how design fit is judged
  without hand-driving the full app into each scenario.
- CSS: `web/src/css/site.css` (tokens on `:root`, legacy classes),
  `web/src/css/toolkit.css` (Tailwind `@theme` bridge + shadcn var mirror).

## Hard-won constraints (violating these has burned sessions)

1. **Never write `--x: var(--x)`** in `toolkit.css`'s mirror block — a
   self-referential custom property is a spec-level cycle that silently kills
   the variable page-wide (this once disabled `--border` everywhere).
2. Tailwind utilities sit in `@layer utilities`; site.css is **unlayered** and
   wins ties. If a Tailwind class "doesn't apply" on an element that also has a
   legacy class (`.suggest-chip`, `.tool-card`, …), add a scoped bump rule in
   `toolkit.css` (see `.suggest-chip.border-dashed`, `.tool-card[data-pinned]`).
3. Keep Tailwind class strings **literal** — no template-interpolated
   arbitrary values; the scanner can't see them.
4. The dev server's Tailwind output can go stale on long sessions — restart the
   preview (`preview_stop`/`preview_start`) before concluding a class "doesn't
   generate", and confirm against `npm run build` output in `dist/assets/*.css`.

## Verification bar (every change)

`npm run build` · `npx tsc --noEmit` (repo has pre-existing noise in
`memory-safety.js`; filter to your files) · `npm test` — exactly 3 failing
files are pre-existing baseline (`conjugate-stitch`, `toolkit-engine`,
`webauthn-mds`); zero new failures allowed. Then verify visually in the
Browser pane on `/toolkit-widgets` **using `getComputedStyle` against the
mockup's literal px/hex values** (screenshots intermittently fail to composite;
JS inspection is the reliable check). Open a fresh tab if React logs
"createRoot called twice" after repeated force-navigations.

## Open design questions

Turns 21 and 22 are fully landed (2026-07-30): 21b Publish plumbing (confirm
popover, `publishArtifact`, link-icon-copies-`directoryUrl`), 21c search→kit
suggestion, 21d nested-caret slot filtering (`nestedTipFor` — tee/foreach
branches now fit against the value flowing in, not the cell's final tip), 21e
suite-status pill+popover, 22a secret params (`ParamField` locked bind-only
UI, `recipe.js` redaction on serialize), 22b `stun.check`'s "Configure TURN"
action (jumps to `rtc.ice`'s `turn=` field, autofocused). Only the two
live-network items below are still open.

1. **Live two-peer verification**: `quorum.offer`/`join`/`send`/`recv` are
   implemented and unit/compile-tested but never mesh-tested against a real
   second peer (single-agent browser sessions can't do that). Whoever picks
   this up should open two tabs/profiles and actually run a paired
   offer/join/send/recv/close notebook end to end, then fold whatever breaks
   back into `quorum-ops.js`.
2. **SESSION region polish**: `SessionStrip` renders per-cell but its "waiting
   → connected" transition and the RunBar "waiting-peer → running" handoff
   have only been checked in isolation (catalog fixtures), not through a real
   paused run. Once #1 is possible, verify the transition is smooth (no flash
   of idle/blocked state) and that `Cancel` reliably un-pauses a stuck run.

New candidates for turn 23, surfaced while landing 21/22:

3. **Suite popover notes are generic**: 21e's popover shows "verified" /
   "unverified" / "browser" per suite, not the mock's real version strings
   ("6.1", "native") — `ToolkitSuiteStatus` has no such field. Decide whether
   it's worth threading actual library/algorithm versions through.
4. **`nestedTipFor` only covers `tee`/`foreach`**: if a future op introduces
   real fixed-slot nesting (closer to the mock's `signAndEncrypt`), the
   registry will need an actual `nestSlots` shape — `nestedTipFor`'s
   walk-to-position approach won't generalize to a slot with a *different*
   kind than "whatever flows in at that point" (e.g. a slot that only accepts
   `openpgp-key`).
5. **Publish is HKP-only**: `publishArtifact` always posts to This site's own
   `/pks/add` / `/api/v1/me/keys` — there's no path to publish to an explicit
   upstream keyserver the way `hkp.get`'s `keyserver=` param allows for reads.

Deliverables per iteration: (a) a new numbered section in the design doc
(follow the 19a-style format: mockup panel + dashed props panel naming real
repo props), (b) the catalog page updated with any new widget states, (c) the
same verification bar as above.
