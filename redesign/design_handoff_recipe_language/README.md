# Handoff: Recipe Language Corrections (tee/foreach UX, selector grammar, WebRTC audit)

## Overview
This handoff is unusual in shape: it's a **correction pass**, triggered by
finally reading `docs/RECIPE.md`'s full grammar and the real
`RecipeChipFlow.tsx` after several turns of speculating about tee/foreach/
selector UX without them. Two earlier turns (previously numbered 47-52) were
**scrapped entirely** once the real grammar surfaced facts that invalidated
their core assumptions — most importantly, that nested `tee`/`foreach` is
explicitly rejected by the parser. What replaced them (now turn 47) and the
retroactive audit of earlier WebRTC/Types work (turn 48) are both grounded
directly in `docs/RECIPE.md` quotes and the real `RecipeChipFlow.tsx` shape.

**Read this qualifier list before implementing anything below** — it's the
point of this handoff:
- Turn 46 is straightforward and unconditionally correct: a real bug,
  confirmed against the actual component.
- Turn 47 is grounded in an actual, fully-read grammar doc — high confidence.
- Turn 48's four items have three different confidence levels, stated
  explicitly per item (48a: certain bug; 48b/48c: real opportunities but not
  full retractions, flagged as open engineering questions; 48d: confirms
  something already correct, no action needed).

## About the design files
`reference.html` is a **design reference built in HTML**, not production
code. Recreate it in `b1tninja/basilisk` by extending the real files named
throughout — do not port this file's inline-style markup directly.

## Screens / views

### 1. tee/foreach insert-gap ambiguity (turn 46) — confirmed bug, fix now
Read directly off the real `RecipeChipFlow.tsx`: the gap that continues a
cell's main chain after a stem chip, and the gap inside that stem's own
nested branch/body, render the **literal same `InsertGap` component with the
same generic label** ("Insert step here" / "Insert first step"). Nothing
distinguishes their scope. Fix, three parts:
1. Branch/body gap labels become scope-specific: `` `+ step in ${branchSelector}` ``
   instead of the generic label.
2. Inserting `tee` or `foreach` auto-focuses the new branch/body's own gap
   (`activeGap` already exists as a prop — this just chooses where it points
   on insert instead of leaving it null).
3. The stem-row "continue main chain" gap is hidden until the tee/foreach's
   body has at least one step (an empty tee is invalid syntax anyway, so a
   gap implying you could continue past it yet is actively misleading).

`foreach` is worse before this fix — its body has no selector chip at all to
anchor on (unlike tee's `:public`-style branch chip), so it gets the same
three fixes plus a static `↻ each item` anchor chip in front of its body gap.

### 2. Selector grammar, corrected against `docs/RECIPE.md` (turn 47)
This section **replaces** earlier (now-deleted) speculative turns that
proposed a generic, extensible `TypeMeta.members` registry field for
"ghost" ready-made subchains. That speculation is retracted. The real
grammar is much smaller and already fully specified:

**The real selector table** (RECIPE.md's "Projectors," verbatim tip
before/after) — six selectors total, a closed set, not something to author
a registry field for:
| Selector | Tip before | Tip after |
|---|---|---|
| `:public` / `:pub` | `keypair` | `key` (which=public) |
| `:private` / `:priv` / `:secret` | `keypair` | `key` (which=private) |
| `:key` | `item` | `text/opaque` |
| `:value` | `item` | `text/mnemonic` \| `bytes/opaque` |
| `[n]` / `at n` | `shares` | one share |
| `[n:m]` / `at n:m` | `shares` | `shares` slice |

Ghost/candidate chips (using `SuggestChip`'s real `variant="candidate"` —
no new chip state needed) should read directly from this table, fit-checked
against the current tip type, exactly like any other op.

**A branch never requires a selector.** The EBNF is explicit:
`branch = [ selector , "|" ] , pipeline` — the selector is optional. The "+"
affordance set for a fresh `tee` should be: the fitting selector ghosts,
**plus `peek`** (RECIPE.md's own documented alternative to an empty tee —
"Empty tee is invalid; use peek for a side inspect"), **plus** a plain
"+ branch (no selector)" that starts an unselected branch directly on the
cloned value. Never force a selector choice.

**`foreach`'s optional selector sits before its body, not inside it.**
`foreach :items { … }` — the iteration-view modifier (`:items` / `:values`
/ `:keys`) is `foreach`'s own gap, appearing once, before the body opens.
RECIPE.md is explicit that these three are rejected as bare stem selectors
("Stem `:items`/`:keys`/`:values` are rejected — use `foreach`"), so they
must never be offered as a ghost inside the body itself. Inside the body,
a per-item selector (`:value` / `:key`, singular) is just an ordinary
optional first stage — no special mechanism, same fit-checked caret as any
other gap.

**Retracted: recursive nesting.** RECIPE.md states plainly: *"Nested `tee`
/ `foreach` inside a body is rejected in v1."* An earlier turn had proposed
generalizing `ChipPath` into a recursive trail and unifying the renderer to
support a `tee` inside a `tee`'s branch — solving a case the language
forbids. **Do not implement that.** The real `ChipBranchView.steps:
ChipStepView[]` (flat, one level, no further `hasNest`) is correct as
written. The caret/shelf/⌘K should simply not offer `tee`/`foreach` at all
while focused inside any existing branch or body — not dimmed, not shown
with an error, just absent from the list, same as any op with zero
possible fits already behaves.

**Also corrected:** any UI showing a dot-prefixed selector (`.public`) is
wrong — RECIPE.md explicitly rejects dot-members ("Dot-prefixed members
(`.public`) are rejected — use `:public`"). Every selector chip must render
with a colon.

### 3. Retroactive audit of the WebRTC/Types work (turn 48)
Four findings from re-reading earlier (turns 21-31) work against the real
grammar and the real `type-registry.js`:

**48a — real bug, fix directly.** Six WebRTC op names violate the
established naming convention (every real namespaced op is
`namespace.singlelowercaseword`: `gpg.encrypt`, `hkp.get`, `agent.unlock`,
`webauthn.prf`, `sss.split` — none camelCase). Rename:
`rtc.gatherCandidates → rtc.gather`, `rtc.checkConnectivity → rtc.check`,
`rtc.connectionState → rtc.state`, `rtc.dataChannelStats → rtc.stats`,
`rtc.createOffer/createAnswer → rtc.offer / rtc.answer`. Mechanical
find-and-replace across the earlier WEBRTC-TOOLBOX.md tables and design —
no behavior, params, or UI changes needed beyond the names.

**48b — real opportunity, not a full retraction.** `quorum.recv`'s
"multiple values over time" problem (previously solved with a bespoke
`cell.output: OutputArtifact[]` array shape + a collect/run-downstream
toggle) has a real-language precedent already: `foreach`'s tip is a
**`bundle`** of per-item tips, explicitly meant for "many values, don't pipe
the bundle itself forward, write `@slot`s in the body" — the exact same
shape `sss.split`'s shares already use. The UI insight (a live-appending
list, defaulting to inert rather than auto-fanning-out) is still correct
and needed. What should change: model `quorum.recv | foreach { - out @msg }`
using the *existing* bundle/foreach idiom instead of inventing a parallel
one — contingent on whether the engine's `foreach` execution model can
support a **live, still-growing** source rather than only a pre-computed
one. Flag this open question to whoever owns `engine.js`.

**48c — flagged, not resolved.** `quorum.mesh`'s dedicated MESH cell region
(a roster list wrapping `sss.split`'s shares into `n` parallel sessions)
might collapse into a plain `foreach` body
(`sss.split | blip39 | foreach { - quorum.offer | quorum.send }`) reusing
the SESSION region already built per-cell — **if** a body step can
legitimately pause the whole `foreach` mid-iteration waiting for a peer
(RECIPE.md never shows a body step blocking on network I/O, only
synchronous per-item transforms). This is a genuine open question for the
engine owner, not a confident correction — if `foreach` can't pause
per-iteration, the dedicated MESH region from turn 29c stands as designed.

**48d — confirmed correct, no action needed.** The network pipeline types
designed in turns 23-30 (`candidate`, `session`, `channel`, `connstate`,
`stats`, `endpoint`, `certificate`, `sdp`, `host`, `peer`) already exist
nearly one-to-one in the real `type-registry.js`'s "Network types" section
— that earlier work was well-aligned with the real registry, not
speculative. Similarly, the Types-tab Int literal widget's `0x`/`0b`/`0o`
support (turn 31) exactly matches the real `parseIntLiteral` in
`type-registry.js` — no conflict with RECIPE.md's stricter stem-literal
grammar (decimal/hex only), because the widget serializes through a `lit`
step rather than emitting a bare EBNF literal token directly.

## Interactions & behavior
- Selector ghosts (turn 47) materialize on click into a real
  `SuggestChip variant="selector"` and auto-focus that branch's own gap
  (reusing turn 46's fix) — clicking a ghost is the entire "add a branch"
  gesture, never a two-step process.
- A clicked ghost/typed branch name doesn't become real recipe text until
  its first step lands — an empty `{ - :public }` isn't valid syntax, so
  the branch is "armed" client-side state until then, same as `activeGap`
  already is.
- `tee`/`foreach` are absent (not dimmed) from any op list while the caret
  is focused inside an existing branch/body, per the "nested is rejected"
  finding.

## State management
No new global stores. `ChipPath`'s existing `{ cell, stem, branch?, body? }`
shape (one level) is sufficient and should **not** be generalized into a
trail — that generalization is explicitly retracted in this handoff.

## Design tokens
No new colors. Reuses `--caret`/`--brand`/`--warn`/`--error` exactly as
established in every prior handoff in this project.

## Assets
None.

## Files
- `reference.html` — standalone extract of turns 46-48, open directly in a
  browser.
- **Read `docs/RECIPE.md` in full before implementing any of turn 47** — the
  selector table, EBNF, and the "nested is rejected" statement are quoted
  above but the full document has more context (casts, slot args, namespace
  conventions) worth having on hand during implementation.
- Depends on every prior handoff in this project for context on what's
  being corrected — this handoff supersedes the tee/foreach/selector
  portions of `design_handoff_webrtc_toolbox/` and
  `design_handoff_inspector_tray_glyphs/` specifically; everything else in
  those packages is unaffected.

## Source
Design project: this project, turns 46-48 in `Basilisk Toolkit v2.dc.html`.
Retrofit target: `b1tninja/basilisk`, branch `feat/toolkit-redesign`,
building on commit `3bb6a54610ef`.
