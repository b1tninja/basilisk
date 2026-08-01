# Handoff: First-Class Polish, New Tools, and the Glyph System

> ## ⚠️ Correction: `glyphs-redesigned.js` is gone, and its merge instruction was wrong
>
> This document's central glyph recommendation — *"the actual task is
> finishing this merge"* of `web/src/lib/toolkit/glyphs-redesigned.js` into
> `glyphs.js` — **must not be followed**, and the file it names has been
> deleted. Nothing imported it; it was a hand-written alternative icon map
> whose own header told the reader to merge its entries into `GLYPH_PATHS`
> after generation.
>
> That hand-edit is exactly what `docs/GLYPHS.md` and
> `web/src/test/glyphs-assets.test.js` forbid. **`glyphs.js` is generated**
> by `npm run glyphs` from `web/glyphs/manifest.json` + `web/glyphs/svg/*.svg`,
> and the test asserts manifest ↔ SVG ↔ module parity — a hand-merged entry
> fails it, and is overwritten by the next generation run either way.
>
> Its house style also conflicted with the shipped set: stroke-width 1 and
> 1.75 against the set's **1.6**, and `stroke="currentColor"` hardcoded on
> every child rather than inherited.
>
> **The correct route for any design in here** is a new
> `web/glyphs/svg/<id>.svg` (20×20, `currentColor`, stroke 1.6), a
> `manifest.json` entry, then `npm run glyphs`. Commit `8d7e151` (the `otp`
> glyph) and `a0a81c1` (`key-public` / `key-secret` / `key-pair`) are worked
> examples. Note `a0a81c1` also found that `glyphIdFor` resolves
> **op → shelf → toolbox**, so a toolbox-level glyph is invisible when the ops
> declare their own.
>
> Two specifics below are now stale: the `totp` glyph it calls "genuinely
> absent" shipped as `otp` in `8d7e151`, and the sensitivity distinction the
> icon section reaches for shipped in `a0a81c1`.
>
> Everything else here — the interaction-level polish, the capability work,
> the house-style *principles* — stands.

## Overview
A cross-cutting polish pass after every feature-inventory item and checklist
row was designed (prior handoffs). Covers interaction-level craft (empty
states, command palette, undo, notifications), two new browser-native
capabilities plus one new tool (File System Access, Notification API, TOTP),
and a corrected pass over the app's icon system — including a real finding:
turn 44 initially mocked glyph "before" states that were never true. Turn 45
retracts that and grounds the work in the actual `glyphs.js`/
`glyphs-redesigned.js` files.

## About the design files
`reference.html` is a **design reference built in HTML**, not production
code. Recreate it in `b1tninja/basilisk` by extending the real files named
throughout — do not port this file's inline-style markup directly.

## Fidelity
Turns 40-44 are illustrative interaction specs (grounded in real component
shapes from prior handoffs) at normal fidelity. Turn 45 is a correction with
higher-stakes fidelity: it was written after reading the actual
`glyphs.js`/`glyphs-redesigned.js` source, and its two new glyph entries
(`totp`, `clipboard`) are meant as literal ready-to-merge strings in that
file's exact format, not illustrative mockups.

## Screens / views

### 1. Six empty tray states (turn 40a)
Each of the six tray tabs (turn 34's Keys/Slots/Connections/Outputs/Inputs/
Params) gets its own empty-state copy naming the specific action that fills
it, not a generic "nothing here": Keys — "Generate or import to get
started"; Slots — "Slots appear once a cell writes `out @x`"; Outputs —
"Run a cell to see its artifacts here"; Inputs — "Nothing pasted in yet".
Params is never empty (always shows the active profile). Each empty state
anchors on the same tab glyph from turn 35a, drawn larger (20px) at 30%
stroke opacity.

### 2. ⌘K command palette (turn 40b)
Opens the same fit-aware op list `OpsShelf` already filters — not a second
search index. Results = `ops.filter(fits tipFit).filter(matches query)`,
identical to what the shelf's own filter box runs. Inserts at whichever caret
was last focused (shown in the header, e.g. "cell [2] · after export"), or
end-of-pipeline if none. Escape returns focus without stealing it permanently.

### 3. Undo (turn 40c)
One reusable toast, not per-action confirm dialogs:
```ts
pushUndo({ label: string; undo: () => void });
```
Scope: chip remove, cell delete, key delete, input-slot delete — anything
that destroys recipe/notebook *state*. Explicitly excluded: reveal-then-hide
(has its own timeout, turn 32c) and session Close (reconnecting is a new
handshake, not a restore). Ctrl/⌘-Z also triggers the most recent undo; the
toast is a visible affordance for the shortcut, not the only way to reach it.

### 4. One toast/notification component (turn 40d)
Three severities, one component, bottom-center stack:
```ts
toast('ok' | 'warn' | 'error', text: string, action?: { label; onClick });
```
Copy currently has **no** confirmation in the real `OutputList.tsx` — this
finally gives it one ('ok', 2s auto-dismiss). A denied clipboard-read
permission (turn 32d) is 'warn' with a Retry action. Turn 40c's undo toast is
this same component in its 'ok'-plus-action shape.

### 5. First-run canvas (turn 41a)
Shown only when `cells.length === 0`. One "+ Insert first step" caret plus
three template shortcuts pulled directly from `PresetMenu`'s existing
Keys/Secrets groups (turn 37b) — not a separate onboarding flow with its own
state. Vanishes on the first real edit.

### 6. Live per-chip execution state (turn 41b)
`RunBar`'s real fixture only reports cell-granularity progress ("cell 2 of
4"). Add per-chip state:
```ts
chip.runState: 'done' | 'active' | 'pending';
```
Done chips dim to 50% rather than disappearing. The active chip's progress
underline is indeterminate for the (common) case of no duration estimate,
determinate only where an op reports real progress (a `stun.check`
round-trip, a large-buffer hash) — never fakes precision the runtime doesn't
have.

### 7. Glyph accessibility correction (turn 41c)
Turn 35 added icon-first tray tabs and `OutputList` kind-badge glyphs without
specifying what a screen reader announces. Fix, both call sites:
```html
<button role="tab" aria-label="Connections" title="Connections">
  <Cable aria-hidden />
</button>
```
Icon gets `aria-hidden="true"`; the interactive parent always carries the
real `aria-label` — critical for the tray tabs at narrow widths where the
text genuinely isn't visible at all.

### 8. Light-theme token spot-check (turn 41d)
Every mockup in this project used fixed dark hex for speed; the brief
requires light and dark both. Confirmed (not changed) that the existing
light-theme token pairs from turn 30d hold 4.5:1 contrast on white:
`--warn #e3b341→#9a6700`, `--caret #58a6ff→#0969da`, `--error #ff7b72→#cf222e`.
No new tokens — this item is a verification, flagged because nobody had
actually rendered it until now.

### 9. File System Access API (turn 42a)
`showSaveFilePicker`/`showOpenFilePicker` for notebooks-as-real-files, next
to (not replacing) turn 37b's in-browser workspace library. Same
recipe-text-only payload. Feature-detected — where unsupported (Firefox,
Safari as of this writing), the button silently falls back to the existing
download-link behavior rather than showing a dead button or support warning.
File handle permissions aren't persisted across reloads (API limitation): a
reopened session's first Save always re-prompts once.

### 10. Artifact Download (turn 42b)
`OutputList` currently only has Copy. Add Download as a fourth action
(joining turn 36a's Copy · Expand · Publish line), shown conditionally:
```ts
show Download when: sizeBytes > 2048 || kind === 'key' || netType === 'sdp';
```
Filename from the artifact's own `label`. Sensitive artifacts still require
Reveal first — same gate Copy already respects.

### 11. Notification API — scoped to one wait (turn 42c)
Only for `quorum.offer`'s "waiting for peer" (`SessionStrip`'s `waiting`
state), which can genuinely span a tab-switch. `Notification.requestPermission()`
fires only the first time a cell enters that state — never speculatively on
load. If denied, nothing degrades: the existing in-tab `SessionStrip`/
`RunBar` waiting-peer feedback is already sufficient for a focused-tab user.

### 12. New tool: TOTP (turn 43, all sub-items)
Two ops mirroring the sign/verify pair shape already in the registry:
```ts
totp.generate: bytes/base32 → text/digits   // params: period=30s, digits=6, alg=SHA-1
totp.verify: { secret, code } → bool        // window param: ±1 step (clock drift)
totp.uri: { secret, issuer, account } → text // "otpauth://totp/..." for QR provisioning
```
**The genuinely new interaction**: a TOTP code is correct for exactly 30s,
then silently wrong — the first pipeline value in the app that changes on a
local timer rather than a rerun or an external event (distinct from turn
30c's `recv`, which appends new rows on external messages; TOTP mutates one
row in place). The output row needs a countdown ring (turns `--warn` in the
last 5s) and a brief flash when the code rolls over — the one load-bearing
animation in the whole project, since missing the window is a real everyday
TOTP failure mode. `totp.uri` composes with `qr.encode` (turn 42d) with zero
special-casing — ordinary `text` in, ordinary QR out. The secret itself lives
in the Keys tray tab (turn 34b), not Inputs (turn 33b) — it's long-lived
credential material like a keypair, not a one-off runtime paste. Adds a third
Keys row kind (`'keypair' | 'openpgp' | 'totp'`), not a new tray tab.

### 13. Glyph system correction (turn 45) — read before touching icons
**Turn 44's "before" comparisons were fabricated** — written without reading
the real source first. The actual `glyphs.js` (auto-generated, ~60 entries,
`viewBox 0 0 20 20`, `1.6px` stroke) already draws `genkey` as a literal
key-and-lock, `export` as a tray with an arrow, `openpgp` as an
envelope-flap padlock. Do not "fix" these — they're fine. Retract 44b
entirely; 44a's house-style principle and 44d's legend popover idea are
still sound and now apply to real ongoing work rather than an assumed blank
slate.

**The real finding**: `glyphs-redesigned.js` already exists as an explicit,
unmerged in-progress pass (self-documented "turns 1-6") covering all 9
toolbox icons and 21 of the shelf icons, with a stated grammar: 24px grid,
1.75px stroke, round caps/joins, built only from circles/lines/simple
arcs/polygons, and color intent — green for OpenPGP (trust), gold for SSS
(sharing), gray for everything else. **The actual task is finishing this
merge**, not redesigning from scratch.

Real remaining scope (op-families in `glyphs.js` the redesign pass never
reached, diffed directly against `glyphs-redesigned.js`'s coverage):
- `gpg-*` (encrypt, sym, genkey, sign, inspect) — keep `openpgp`'s green
- `hkp-*` (get, search, cache, filter) — keep the existing radiating-dot
  "network" motif already used for the `hkp` toolbox glyph
- `wa-*` (create, get, attest, caps, prf, mds) — keep the
  fingerprint-plus-shield vocabulary the five un-redesigned entries share
- KDF/passphrase singles: `hkdf`, `pbkdf2`, `passphrase`, `recover`

Two glyphs are genuinely absent from **both** files and are drawn here to
`glyphs-redesigned.js`'s exact spec, ready to merge in directly:
```js
"totp": "<circle cx='10' cy='10.5' r='6.5'/><path d='M10 6.5v4l3 2'/><path d='M7.5 2.5h5'/>",
"clipboard": "<rect x='5' y='4.5' width='10' height='13' rx='1.3'/><rect x='7.5' y='2.5' width='5' height='3' rx='0.8'/>",
```
Both gray (neither trust nor sharing family). Note: `qr` already exists in
`glyphs.js` — turn 44c's mock of it was redundant but harmless, nothing to
change there.

## Interactions & behavior
- Undo (§3) and the toast system (§4) are the same underlying component in
  two configurations — build one, not two.
- The TOTP countdown ring and the live-chip progress underline (§6, §12)
  share the `--warn` "running low" accent — keep that consistent if either
  is touched later.
- Empty states (§1) and the first-run canvas (§5) are different scopes:
  tray-tab-level vs. whole-notebook-level. Don't collapse them into one
  component.

## State management
No new global stores. Each item is either a new field on an existing prop
shape (`chip.runState`, tray empty-state copy) or a small new local/ambient
state (undo stack, toast queue, ⌘K open/query, Notification permission
flag) — consistent with how every prior handoff in this project has scoped
additions.

## Design tokens
No new colors anywhere in this pass. Turn 41d is a verification of existing
light-theme pairs, not new tokens. Glyphs (§13) use the color intent already
established in `glyphs-redesigned.js` (green/gold/gray) — no additions there
either.

## Assets
Two new glyph path strings for `glyphs.js`/`glyphs-redesigned.js` (§13,
ready to merge as shown). No other new icon or image assets.

## Files
- `reference.html` — standalone extract of turns 40-45, open directly in a
  browser.
- Depends on every prior handoff in this project
  (`design_handoff_quorum_toolbox/`, `design_handoff_remaining/`,
  `design_handoff_webrtc_toolbox/`, `design_handoff_types_toolbox/`,
  `design_handoff_inspector_tray_glyphs/`) — this is the polish layer on top,
  not a replacement for any of them.
- Before touching icons: read the real `web/src/lib/toolkit/glyphs.js` and
  `glyphs-redesigned.js` directly. Turn 44 in the reference file is
  superseded by turn 45 — don't implement 44b.

## Source
Design project: this project, turns 40-45 in `Basilisk Toolkit v2.dc.html`.
Retrofit target: `b1tninja/basilisk`, branch `feat/toolkit-redesign`,
building on commit `3bb6a54610ef`.
