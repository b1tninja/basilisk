# Handoff: Quorum as a Toolbox (turn 21a)

## Overview
Retires the standalone Quorum page. `quorum.offer / join / send / recv / close`
become ops in the same shelf/pipeline system as every other crypto op, wrapping
the existing `web/src/lib/quorum/rtc.js` `QuorumSession` 1:1. Core idea: a
notebook run's boundary becomes the WebRTC session's boundary — running a
notebook containing `quorum.offer`/`join` pauses the run at that cell until a
peer connects, the same way a run already pauses at a blocked cell.

## About the design files
`Basilisk Toolkit v2.dc.html` (section `21a`, included in this folder as
`21a-quorum-toolbox.html` — an extracted, standalone copy of just that section)
is an HTML **design reference**, not production code. Recreate this in the
repo's real React 19 + TypeScript + Tailwind v4 stack, using its existing
widget patterns (`OpsShelf`, `RunBar`, the cell region system) — do not port
the HTML/inline-style markup directly.

## Fidelity
High-fidelity for layout, spacing, color, and copy. The exact prop shapes
below are the intended contract, not just a suggestion — match them unless a
real constraint in `rtc.js`/`QuorumSession` forces a change, in which case
update this doc's shape to match reality before implementing.

## Screens / views

### 1. Shelf — Quorum category
New category in `OpsShelf`'s tree, same visual weight as `Encoding`/`OpenPGP`/etc:
- `quorum.offer`, `quorum.join`, `quorum.send`, `quorum.recv`, `quorum.close` —
  standard op rows (6px blue dot, 11.5px mono name), no different from any
  other op row.
- `rtc.ice` — a config source op (params: STUN/TURN server list), rendered at
  75% opacity with a small "config" tag.
- `stun.check` — a one-shot diagnostic op, same dim treatment, tagged
  "diagnostic".
- Category count badge: 7.

### 2. Cell — SESSION region
A new cell region, same slot pattern as the existing HEADER/PIPELINE/PARAMS/
READINESS regions (turn 19h), inserted between PIPELINE and READINESS,
**only present on cells whose pipeline contains a `quorum.offer` or
`quorum.join` op**:
- Left rail: 16px wide, blue-tinted background (`rgba(88,166,255,.08)`),
  vertical label "SESSION" in 8.5px uppercase blue.
- Body: a rounded row (`rgba(88,166,255,.07)` bg, `rgba(88,166,255,.3)` border,
  7px radius) containing, left to right: a pulsing blue dot (7px circle +
  3px glow ring), copy "Waiting for peer to join…" (11px, `#e6edf3`), the
  invite's short fingerprint in 10px mono gray, a "Copy invite" button, a
  "Cancel" button (both `white-space:nowrap`, 22px tall).
- Once connected: row switches to "Connected to peer · 00:42" (elapsed timer),
  dot turns solid green, both buttons are replaced by a single "Close" button.

### 3. Run bar — waiting-peer state
Below the cell, `RunBar` gets a 4th state alongside `idle | blocked | running`:
- `waiting-peer`: Stop button (same red text as the running state's Stop),
  label "Paused at cell [N] — waiting for peer…" in blue mono, no progress bar
  (there's nothing to show % of).

## Interactions & behavior
- Running a notebook whose pipeline reaches a `quorum.offer`/`join` cell
  pauses the run there (RunBar → `waiting-peer`) exactly like hitting a
  blocked cell today — no new "stop and resume" mechanism, reuse whatever
  already pauses/resumes a run at a blocked cell.
- "Copy invite" copies the PGP-signed invite blob to clipboard.
- "Cancel" aborts the `QuorumSession` offer/join attempt and fails that cell
  (same visual failure state a normal op gets on error).
- On peer connect, the SESSION row and RunBar both transition automatically
  (no user action) and the run resumes into `send`/`recv`/`close`.
- `quorum.offer`'s invite blob also flows through the normal Copy/Publish
  output row (turn 20h's `OutputList`) as a second surface for sharing it —
  the SESSION strip's inline Copy is a shortcut, not the only path.

## State management
- `sessionHandle`: live object produced by `quorum.offer`/`join`, consumed by
  `send`/`recv`/`close` as their cell input — same input/output wiring every
  other op already uses, no special-cased plumbing.
- Session lifecycle state (`offering | waiting | connected | closed`) lives
  wherever per-cell run state already lives in `useNotebook.ts` (alongside
  `runProgress`/`stopRun`/`pendingInsert`) — do not introduce a second state
  store for it.
- `rtc.ice`'s server list is a normal op param, read by `offer`/`join` the
  same way any op reads an upstream config op's output.

## Design tokens
Reuses existing tokens only — no new colors:
- Session accent: `#58a6ff` (same as caret/encode blue) at `.06–.3` alpha for
  backgrounds/borders, full opacity for dot/text.
- Connected state: brand green `#4cde82`.
- Typography: 11px/11.5px system-ui for copy, `ui-monospace, Menlo, monospace`
  11.5px/10px for op names and the invite fingerprint, 8.5px uppercase system-ui
  (0.08em tracking) for the SESSION rail label — matches every other region
  label in the cell.
- Row radius 7px, buttons 5px, matching the rest of the cell chrome.

## Props (intended contracts)

```ts
// RunBar — one new state
type RunBarState = 'idle' | 'blocked' | 'running' | 'waiting-peer';
interface RunBarProps {
  // ...existing props unchanged...
  sessionInvite?: string;
  onCopyInvite?: () => void;
  onCancelSession?: () => void;
}

// New: SessionStrip (cell-level region, alongside ReadinessBar)
interface SessionStripProps {
  state: 'offering' | 'waiting' | 'connected' | 'closed';
  inviteFingerprint?: string;
  elapsedSeconds?: number;
  onCopyInvite: () => void;
  onCancel: () => void;
  onClose: () => void;
}
```

## Open items to resolve during implementation
- WebRTC is main-thread-only. Check how `agent.*` steps are flagged/handled
  for main-thread execution in the op registry and reuse that mechanism for
  `quorum.offer`/`join` rather than inventing a second one.
- Confirm whether "cancel" during `waiting` should also tear down any
  already-established ICE candidates, or if `QuorumSession` handles that
  internally.
- `stun.check`'s diagnostic output shape (reachable/unreachable, latency) is
  not yet spec'd in detail — read `rtc.js`'s current diagnostic capabilities
  before designing its exact output row.

## Files in this bundle
- `21a-quorum-toolbox.html` — standalone extracted copy of the design section
  above (open directly in a browser).

## Source of truth
Full design project (all turns, all sections): the Claude Design project this
was authored in. This handoff covers only section 21a — turns 18-21 (b–e)
cover the rest of the toolkit redesign and should be handed off separately if
needed.
