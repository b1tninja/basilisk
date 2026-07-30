# Handoff: WebRTC Toolbox (Quorum sessions, ICE/STUN, Connections tray)

## Overview
Adds a full WebRTC capability set to the Basilisk toolkit as first-class
recipe-pipeline ops, plus the ambient tray chrome (a `Connections` tab) that
supports them. Covers connectivity establishment (ICE/STUN/TURN), the
Quorum peer-session ops (`offer`/`join`/`send`/`recv`/`close`), a multi-party
mesh mode wired to the existing `sss.split`/`combine` secret sharing, session
identity (DTLS certificates), diagnostics (session log, peer detail,
bandwidth), and the storage schema all of this needs. This is the largest
single feature added to the `feat/toolkit-redesign` shell since the v2
ground-up redesign.

## About the design files
Everything in this bundle — `webrtc-toolbox-reference.html` and the turn
descriptions in this README — is a **design reference built in HTML**, not
production code. The task is to **recreate these designs in the real
`b1tninja/basilisk` codebase** (React 19 + TypeScript + Tailwind v4, per
`feat/toolkit-redesign`), reusing its existing components (`OpsShelf`,
`RunBar`, `TopBar`, `ParamField`, `OutputList`, `Popover`, the cell region
system) rather than porting the HTML/inline-style markup directly. Where a
widget below says "reuses X" or "same primitive as Y," that is a hard
requirement, not a suggestion — the whole design was built to minimize new
components; introducing parallel ad-hoc chrome during implementation would
undo that.

## Fidelity
High-fidelity for layout, spacing, color, copy, and prop shapes. Treat the
TypeScript interfaces in each section below as the intended contract. Deviate
only where a real constraint in `rtc.js`/`QuorumSession` or the browser
WebRTC APIs forces a change — and if so, update this doc to match reality
before shipping, so the next person isn't misled by a stale spec.

## Screens / views
Each corresponds to one or more turns in `webrtc-toolbox-reference.html`
(turn ids like `21a`, `23b` are anchors in that file — jump to them directly).

### 1. Quorum as a pipeline toolbox (21a)
`quorum.offer/join/send/recv/close` sit in `OpsShelf`'s category tree like
any other kit — no separate Quorum page. Cells get a new **SESSION** region
(a slotted left rail + body, same pattern as the existing HEADER/PIPELINE/
PARAMS/READINESS regions) that appears only on cells whose pipeline contains
`offer`/`join`. Shows a pulsing-dot "Waiting for peer to join…" row with
Copy-invite/Cancel, transitioning automatically to "Connected" on peer join.
`RunBar` gains a 4th state, `waiting-peer`, alongside `idle`/`blocked`/
`running` — a run pauses at a session cell exactly like it already pauses at
a blocked one, no new async/await UI model needed.

### 2. ICE/STUN/TURN as ops, not plumbing (23a-c, 26a-c)
Three ops, each a source/diagnostic op with real MDN-accurate output:
- `rtc.gatherCandidates` — lists candidates, one `OutputList` row per
  candidate, live-appending (trickle ICE keeps finding `prflx` peer-reflexive
  candidates after the initial gather). Types: `host`, `prflx`, `srflx`,
  `relay`; TCP candidates get a `tcp` protocol badge, not a separate row type.
- `rtc.checkConnectivity` — a candidate-pair matrix (local × remote), states
  `waiting`/`in-progress`/`succeeded`/`failed`, nominated pair highlighted,
  skipped pairs shown at 50% opacity (never hidden — a user debugging a slow
  connection needs the whole graph). Includes a `controlling`/`controlled`
  role badge (read from `RTCIceTransport.role`), informational only.
- `rtc.ice` — the STUN/TURN server config cell. TURN `credential` is a
  locked `secret` `ParamField` (see §7).
- ICE restart: when `iceConnectionState` hits `failed` on an already-connected
  session, the SessionStrip shows a "Restart connection" action calling
  `setConfiguration()` + `restartIce()` — distinct from `stun.check`'s
  pre-connection "Configure TURN" diagnostic action (22b).

### 3. Connections tray tab (24a-c, 27)
A 5th tray tab, after Keys/Slots/Inputs/Params (never replacing them) — the
full shell composite is in the reference file at turn 27. Three sections,
stacked vertically in the tray body:
- **Active peers** — one row per live/pending session across the whole
  notebook (not per-cell), each with a status dot, cell reference, and
  Close/Cancel; clicking jumps to that cell.
- **Server preferences** — the default STUN/TURN list any `rtc.ice` cell
  falls back to when its own list is empty; "+ Add server" opens a small
  anchored popover (reuses the existing `Popover` primitive, same chrome as
  the "More ▾" menu and Publish confirm elsewhere in the shell).
- **Session log** (collapsed by default) — see §5.

### 4. Certificate identity, reliability, mesh, bandwidth (29a-d)
- `rtc.certificate` — generates/holds the DTLS identity (`RTCCertificate`).
  Lives in the **Keys** tray tab (identity material, not connection state),
  with Pin-across-sessions / Regenerate actions. Most recipes never need
  this op explicitly — `quorum.offer` generates an ephemeral one itself.
- Data-channel reliability — `ordered`/`unordered`/time-bounded, one more
  section in `quorum.offer`'s existing inline param editor (radio + a
  conditional field, same disclosure pattern the editor already uses).
  Defaults to reliable-ordered; nothing changes for existing recipes.
- `quorum.mesh` — wraps `sss.split`'s `n` output shares into `n` parallel
  `quorum.offer` connections, one per recipient, auto-routing share `i` to
  peer `i`. New **MESH** cell region (a roster list, sibling of SESSION).
  Readiness reads "k of n connected — quorum reachable," not all-n.
- `rtc.statsReport` — live bitrate/RTT/packet-loss, folded into the peer
  detail drawer (§5) as one more section, not a separate tool.

### 5. Session log &amp; peer detail (28a, 28b, 28c)
- **Session log** — full per-peer, phase-colored event history (phases:
  `signaling`, `ice`, `dtls`, `sctp`, `channel`; distinct dot color per
  phase), replacing the flat 24c console stub. All/Errors filter tabs.
- **Peer detail drawer** — opened from any Active-peers row: nominated
  candidate-pair addresses (local/remote IP:port, protocol, role), DTLS
  transport state + remote fingerprint, SCTP transport state + max message
  size, live bandwidth stats. Every field is a real `getStats()`/transport
  property — this is a formatted read-out, not new browser-exposed data.
- **Message hexdump** — a byte-level view of one `quorum.send`/`recv`
  message's payload. **Read this carefully before implementing**: it is
  explicitly the *decrypted application-layer payload*, not a wire/packet
  capture — `RTCDataChannel` has no API that exposes raw UDP/DTLS packets to
  a web page. Label the view accordingly; do not build or describe it as a
  packet sniffer. General-purpose (any binary `OutputArtifact` can open it),
  not WebRTC-specific chrome.

### 6. quorum.recv output model (30c) — read this before implementing
The single highest-risk item in this handoff. `quorum.recv`'s data-channel
`message` event can fire an unbounded number of times over a session's life
— it is **not** a single-output op like every other op in the toolkit.
`cell.output` needs to become an array for this op (a live-appending list,
same UI shape as `rtc.gatherCandidates`'s candidate list), with a per-cell
toggle:
- **Collect only** (default) — messages append to the list; the user
  explicitly clicks "Run [N] on this →" per message to feed one downstream.
- **Run downstream** (opt-in) — automatically re-executes the downstream
  cells once per incoming message (a per-message fan-out).
Flag this to whoever owns `useNotebook.ts`'s output-shape assumptions
elsewhere in the pipeline — anything that assumes `cell.output` is a single
`OutputArtifact` needs an audit against this op specifically.

### 7. Storage schema (30a, 30b)
| Data | Store | Notes |
|---|---|---|
| Theme, last-active tray tab | `localStorage` | device preference |
| Default STUN server URLs | `localStorage` | not secret |
| TURN credential | Same secret store as key material | never plaintext localStorage — this is a hard rule, see §8 |
| `RTCCertificate` (pinned identity) | IndexedDB `certificates` store | structured-cloned; only way persistence works, since the object can't round-trip through JSON |
| Session log | IndexedDB `sessionLog` store, ring-buffered ~2000 rows per notebook | |
| Peer history | IndexedDB `peerHistory` store | not consumed by any widget yet — exists for a future "recently connected" suggestion |

One `basilisk_webrtc` IndexedDB database:
```
certificates  keyPath: id       { id, label, cert, fingerprint, algorithm, createdAt, expiresAt }
sessionLog    keyPath: id(auto) { id, notebookId, cellId, peerLabel, phase, ts, detail, level }
              indexes: [notebookId, ts], [cellId, ts]
peerHistory   keyPath: fingerprint { fingerprint, label, lastConnectedAt, notebookIds[] }
```

### 8. New pipeline kinds &amp; shelf tree (25a, 25b)
Four kinds beyond bytes/text/ciphertext/signature, each a distinct CSS shape
(not just color, to avoid confusing a live handle with a data value):
`candidate` (rotated square/diamond), `session` (square), `channel`
(triangle), `connState` (hollow ring — the one kind that's observe-only,
never bindable as a cell input). All render at the same 6-7px dot footprint
as existing kind dots, pure CSS, no icon assets. `OpsShelf`'s WebRTC category
is the first one deep enough to need a two-level tree (sub-headers: ICE/STUN,
Peer &amp; signaling, Data channel, Stats) — `category.groups` is additive,
optional structure; every other category keeps its flat `ops` array.

## Interactions &amp; behavior
- A run pauses at any `waiting-peer` cell exactly like it already pauses at a
  blocked cell — no new run-loop concept.
- ICE restart and "Configure TURN" are two different actions triggered by two
  different failure conditions (post-connection drop vs. pre-connection
  diagnostic) — don't merge them into one button.
- The Connections tray tab is always visible (not conditional on any session
  existing) — it's ambient chrome, same as Keys/Slots always being present.
- Peer detail drawer opens on click from any Active-peers row or session log
  entry; "Jump to cell" and "Full session log" are its two persistent actions.
- `quorum.mesh`'s readiness is k-of-n, not all-n — the cell can run once
  enough peers are connected to reconstruct the secret, matching `sss.split`'s
  own k-of-n semantics.
- Secret params (TURN `credential`) render locked with no free-text entry —
  only bindable to an Inputs-tray slot — and are omitted (down to a slot
  reference, never a literal) from any serialized recipe/share link.

## State management
- `sessionHandle` (live object from `quorum.offer`/`join`) is consumed by
  `send`/`recv`/`close` as ordinary cell input/output, same wiring pattern
  every other op uses — no special-cased plumbing.
- Session lifecycle state (`offering`/`waiting`/`connected`/`closed`/`failed`)
  lives in `useNotebook.ts` alongside existing per-cell run state
  (`runProgress`, `stopRun`, `pendingInsert`) — do not introduce a second
  state store.
- `rtc.ice`'s server list param falls back to the tray's `localStorage`
  default when the cell's own list is empty.
- `cell.output` for `quorum.recv` is an array (see §6) — everywhere else in
  the pipeline it remains a single `OutputArtifact`.

## Design tokens
No new color tokens beyond four semantic accents already established
elsewhere in the v2 redesign: `--caret #58a6ff`, `--decode #d2a8ff`,
`--warn #e3b341`, `--error #ff7b72` (dark theme; light-theme equivalents:
`#0969da`, `#8250df`, `#9a6700`, `#cf222e`). Session-log phase colors reuse
these plus two additions: DTLS uses `--decode` (`#d2a8ff`), SCTP reuses the
existing HKP/directory orange `#f0883e`. Typography: 11-13px system-ui for
labels/copy, `ui-monospace, Menlo, monospace` for op names, addresses, and
all technical values — unchanged from the rest of the v2 redesign. Row
radius 6-10px, matching existing cell/tray chrome.

## Assets
No new icon or image assets. All new "glyphs" (§8) are pure CSS shapes
(rotated squares, CSS border-triangles, bordered transparent circles) at the
same size as the existing kind-dot system — no SVG or icon font additions.

## Files
- `webrtc-toolbox-reference.html` — standalone extract of every turn listed
  above (21a, 22a-b, 23a-c, 24a-c, 25a-b, 26a-c, 27, 28a-c, 29a-d, 30a-d),
  open directly in a browser.
- `WEBRTC-TOOLBOX.md` — the design-side index: full op/UI/status table per
  MDN category, design principles, explicitly-not-planned items (media
  capture, DTMF, encoded transforms), and priority-ordered next design turns.
  Read this first for orientation before the README's per-screen detail.
- Prior handoffs in this project (`design_handoff_quorum_toolbox/`,
  `design_handoff_remaining/`) cover the base toolkit redesign (turns 18-21)
  this WebRTC work sits on top of — retrofit those first if they haven't
  landed yet, since SESSION region, `OutputList`, `ParamField`, and the tray
  shell are all prerequisites this handoff assumes exist.

## Source
Design project: this project, turns 21a-30 in `Basilisk Toolkit v2.dc.html`.
Retrofit target: `b1tninja/basilisk`, branch `feat/toolkit-redesign`.
