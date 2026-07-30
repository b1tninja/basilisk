# Handoff: Typed Inspector Gaps, Session Tray, Type Errors, Glyphs

## Overview
Follow-up to `PROMPT.md`'s four-problem brief, written after reading the
retrofit actually pushed to `feat/toolkit-redesign@3bb6a54610ef`. Most of that
brief's "Early" widgets — `InspectorArtifact`, `TypeCard`, `NetworkArtifact`,
`OutputList`, `SessionStrip`, `CryptoProfileControl`, `type-registry.js` — had
already landed and closely match the earlier design turns. This handoff covers
only what's genuinely still open after that reality check: the one missing
inspector body, value-display finishing touches, the clipboard feature built
from scratch, the session tray as one coherent six-tab surface, a `failed`
state `SessionStrip` doesn't have yet, type-error presentation, artifact diff,
and a glyph pass over chrome that currently relies on tiny text.

## About the design files
`reference.html` is a **design reference built in HTML**, not production
code. Recreate it in `b1tninja/basilisk` (React 19 + TypeScript + Tailwind v4,
shadcn/Radix primitives) by extending the *real* files read for this pass —
`InspectorArtifact.tsx`, `SessionStrip.tsx`, `OutputList.tsx`,
`type-registry.js` — not by porting this file's inline-style markup.

## Fidelity
Every gap below is stated against the actual current shape of its file (prop
names, type unions, existing branches), read from the repo at commit
`3bb6a54610ef`. Where a mockup shows exact TypeScript, treat it as the
intended diff to that real file.

## Screens / views

### 1. `openpgp-key` inspector body (turn 32b)
`InspectorArtifact.tsx` has bodies for `bytes`/`text`/`keypair`/`shares`/
`recipients` but no branch for `openpgp-key` — it currently falls through to
the generic "no value body" line. Add:
```ts
snapshot.openpgpKey?: {
  primary: { alg, fingerprint, usages, created, expires?, revoked? };
  userIds: { id: string; selfSigned: boolean }[];
  subkeys: { alg, fingerprint, usages, bound: boolean }[];
}
```
Render as a tree: primary key row, then user IDs and subkeys nested one level
under it (new nesting `InspectorArtifact` doesn't have yet — every existing
body is flat). Reuses the existing `Rows` grid for leaf fields. The private
scalar is never printed, matching the keypair body's `d — withheld` line.

### 2. Value display finishing touches (turn 32c)
Three items, all real gaps against `OutputList.tsx`:
- **Name the existing behavior as a decision**: `inspectSnapshot` and
  `content` are already mutually-exclusive render branches (never both shown
  on one row) — document this so it isn't "fixed" into showing both.
- **Reveal timeout**: a revealed secret has no auto-hide today. Add
  `revealTimeoutMs = 15000`, reset on interaction. No screen-share-detection
  API exists to build the brief's other ask against (the Screen Capture API
  only tells a page about *its own* capture state) — the timeout is the real,
  honest mitigation; don't fake a "screen-share detected" indicator.
- **Universal Expand**: today `Expand` only renders when
  `hasNetworkRenderer(a.netType)` is true. Extend the condition to also cover
  `a.inspectSnapshot` and long `a.content` (>512 chars), so a keypair body or
  a large hexdump can open in the same `Sheet` network artifacts already use.

### 3. Clipboard source/sink (turn 32d) — built from scratch
Confirmed absent from the registry (only `navigator.clipboard.writeText` Copy
buttons exist; no pipeline step). Two new ops:
- **`clipboard.read`** (`none → text | bytes`) — a permission-moment dialog
  every run (never remembered, since contents change silently between runs),
  then a preview of what was read before it enters the pipeline.
- **`clipboard.write`** (`any → artifact`, sink) — no permission dialog
  needed (`clipboard-write` auto-grants on a user gesture); a lightweight
  toast-style confirm only, same weight as the existing Copy button — don't
  over-dramatize it to match Read's gating.

### 4. `SessionStrip`'s missing `failed` state (turn 33a)
Real type union is `"offering" | "waiting" | "connected" | "closed"` — a
connection that drops has nowhere to render today.
```ts
type SessionStripState = "offering" | "waiting" | "connected" | "closed" | "failed";
onRestartIce?: () => void;
```
Rendered as a break in the `connected` lineage (error-red dot, not a new
unrelated tone) plus a "Restart connection" button calling
`pc.restartIce()` — distinct from turn 22b's pre-connection "Configure TURN"
(there was no session yet to restart). Only appears once `connectionState`
hits `failed` after having been `connected`, read off the same connstate data
`NetworkArtifact.tsx`'s `ConnStateStrip` already renders.

### 5. Type error presentation (turn 33c)
`SuggestChip`'s catalog fixture already ships an `error` variant with no
attached message — the brief's "most common failure, no designed
presentation" gap exactly. Add:
```ts
chip.error?: { expected: string; got: string; fixStep?: string };
```
One error banner per cell, directly under the chip row (not a tooltip — same
rule `RunBar`'s blocked state already follows): "`sss.split` expects `bytes`,
this cell gives it `text`. Insert a cast →". The "Insert a cast" link only
appears when `type-registry.js`'s producer list for the expected type
contains a real op — never a generic fix that might not resolve anything.
When `RunBar` is also blocked by this cell, its blocker text must be the same
sentence, not a second wording of the same fact.

### 6. Artifact diff (turn 33d)
Deliberately narrow scope: this run vs. the immediately previous run of the
same cell, not a history browser.
```ts
lastRun?: { sizeBytes: number; firstDiffOffset: number | null };
```
Renders as a one-line footer on the existing `OutputList` row (a fourth
footer state alongside preview/content/inspector) — "892 B → 917 B · first
differing byte at offset 40." Not a visual byte-diff viewer; for ciphertext
and signatures a byte-level diff is noise, changed/unchanged + first-offset is
the whole useful signal. Only shows when a previous run's artifact is still
in memory — nothing persists across reload (matches turn 30's storage rule).

### 7. The session tray, resolved (turn 34) — six tabs
**Decision**: Connections stays its own tab, does not fold into Outputs — its
job is live management (Close/Cancel, ongoing state, cross-notebook
visibility) versus Outputs' job (at-rest artifacts grouped by cell); merging
would force every Outputs row to carry a management action it otherwise never
needs. Server preferences (STUN/TURN defaults) do move into **Params**,
since they're a session-level default, same category as the crypto profile.

Final order: **Keys · Slots · Connections · Outputs · Inputs · Params** —
read-to-write ordering (material you hold → live activity → what a run just
made → what a run still needs → rarely-touched defaults). All six tabs stay
always-visible even when empty (e.g. no WebRTC ops in the notebook) — a tray
whose tab count changes under the user is worse than one quiet empty tab.

Three tabs drawn for the first time (referenced in turns 24/32/33, never
laid out until now):
- **Keys** — every CryptoKey/keypair/OpenPGP key, flat list, reusing
  `InspectorArtifact`'s keypair chips for the private/public-half badges.
  "+ Generate / Import" opens `TypeCard`'s own keypair origin picker (31c)
  inline — same widget, second mount point, not a second implementation.
- **Slots** — index of every `@name` in the notebook, bound or not.
  `{ slotName, home: 'keys'|'inputs'|'outputs'|null }` — this is the one tab
  that's cross-referencing, not a detail view: clicking a row jumps to that
  slot's real tab rather than opening a second view of the same data.
- **Params** — resolves an ambiguity explicitly: NOT an aggregate of every
  cell's inline `ParamField`s (those stay inline under each cell, unchanged).
  Only the small set of session-level fallbacks: the real
  `CryptoProfileControl` component (re-parented here, not redesigned) plus
  turn 24b's STUN/TURN server defaults.

### 8. Glyphs over tiny text (turn 35)
The real uniformity rule already answers where these belong:
`docs/TOOLKIT-WIDGETS.md` — "one glyph renderer [op icons only]; lucide only
for non-op chrome." Tray tabs and kind badges are chrome, not ops.
- **Tray tabs**: `KeyRound` (Keys), `LayoutGrid` (Slots), `Cable`
  (Connections), `ArrowDownToLine` (Outputs), `ArrowUpFromLine` (Inputs),
  `SlidersHorizontal` (Params). Outputs/Inputs deliberately mirror each other
  (down-into-tray vs. up-out-of-notebook). Icon + label by default (≥960px);
  icon-only is the existing <960px collapse behavior from turn 32e, not a new
  default — don't force icon-only at full width.
- **`OutputList` kind badge**: add a 12px lucide glyph in front of the
  existing 9px uppercase text on every row (`AlignLeft` for text, `KeyRound`
  for key, `Activity` for diag, `Binary` for bytes, …). Purely a rendering
  change inside the existing badge `<span>` — `a.kind` already carries the
  lookup key, no new prop on `OutputArtifact`. Same map should back
  `TypeCard`'s header badge and the Types-category shelf rows so one kind
  never shows two different glyphs across screens.
- **Explicit non-change**: the `candidate`/`session`/`channel`/`connState`
  dots (turn 25a) stay abstract CSS shapes, not pictograms. A pictogram
  implies a specific real-world reading (a plug for "session" implies
  "connected" even mid-negotiation) that the abstraction deliberately avoids.
  Rule: a value's live/handle state → abstract shape; chrome
  navigation/labels → lucide pictogram. Don't blur the two.

## Interactions & behavior
- Reveal timeout resets on any interaction with the revealed row; no other
  new interaction model beyond what's specified per-section above.
- Every tray-row click that "goes to" something reuses one gesture (jump to
  the owning cell) — now used four times (Outputs, Inputs, Connections'
  Active peers, Slots) rather than invented per tab.
- ICE restart re-negotiates in place (`restartIce()`), it does not tear down
  and re-invite — the room code and any mesh roster stay put.

## State management
No new global state patterns — every addition above is a new field on an
existing prop shape (`OutputArtifact.lastRun`, `SessionStripState` union,
`SuggestChip.error`, `InspectSnapshot.openpgpKey`) or a new registry entry
(`clipboard.read`/`clipboard.write`). The tray's tab set itself is static
(six, always rendered) rather than computed from notebook contents.

## Design tokens
No new colors. Reuses the four semantic accents established across the whole
project: `--caret #58a6ff`, `--decode #d2a8ff`, `--warn #e3b341`,
`--error #ff7b72`, plus brand green `#4cde82`. Glyphs are drawn at the same
weight/stroke as lucide's default (2px stroke, round caps) so they sit
correctly next to real lucide icons already in the app's chrome.

## Assets
No new custom icon assets — turn 35 explicitly specs real lucide component
names to import, not bespoke SVGs, per the codebase's own uniformity rule.

## Files
- `reference.html` — standalone extract of turns 32-35, open directly in a
  browser.
- Depends on the retrofit already pushed at commit `3bb6a54610ef`
  (`InspectorArtifact`, `TypeCard`, `NetworkArtifact`, `OutputList`,
  `SessionStrip`, `CryptoProfileControl`, `type-registry.js`) — this handoff
  extends those files, it does not replace them.
- Prior handoffs (`design_handoff_quorum_toolbox/`, `design_handoff_remaining/`,
  `design_handoff_webrtc_toolbox/`, `design_handoff_types_toolbox/`) cover
  everything else already retrofitted or specified.

## Source
Design project: this project, turns 32-35 in `Basilisk Toolkit v2.dc.html`.
Retrofit target: `b1tninja/basilisk`, branch `feat/toolkit-redesign`,
building on commit `3bb6a54610ef`.
