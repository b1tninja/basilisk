# WebRTC Toolbox — index &amp; handoff

Companion index to the design work in `Basilisk Toolkit v2.dc.html`, turns
21a–30. Maps the **whole** WebRTC surface as recipe-pipeline ops/UI,
organized by MDN's own reference grouping, so future turns know what's
designed, what's next, and where each piece plugs into the existing toolkit
shell (`OpsShelf` category tree, cell regions, `OutputList`, `ParamField`,
tray tabs).

Status legend: ✅ designed (has a turn) · 🚧 partially covered · ⬜ not yet
designed · ⛔ explored, not planned (no product fit).

## 1. ICE &amp; STUN/TURN foundation
Connectivity establishment — the layer everything else sits on.

| Op | Description | UI needed | Status |
|---|---|---|---|
| `rtc.ice` | STUN/TURN server config block | Config cell, `secret` credential field | ✅ 23c |
| `rtc.gatherCandidates` | Gathers candidates — `host`, `prflx` (peer reflexive, found live via trickle ICE), `srflx`, `relay`; TCP candidates (`active`/`passive`/`so`) shown as a `tcp` protocol badge, not a distinct row type | `OutputList` rows, live-appending, typed badges | ✅ 23a, corrected 26a |
| `rtc.checkConnectivity` | Tests candidate pairs, reports nominated pair + controlling/controlled role | Candidate-pair matrix + role badge | ✅ 23b, 26b |
| `stun.check` | One-shot reachability diagnostic (used inside Quorum) | Diagnostic `OutputList` row + "Configure TURN" action | ✅ 22b |
| ICE restart | Recovers a connected session after a network change | SessionStrip `failed` state + "Restart connection" action | ✅ 26c |

## 2. Peer connection &amp; signaling
`RTCPeerConnection`, offer/answer, SDP exchange, connection state.

| Op | Description | UI needed | Status |
|---|---|---|---|
| `quorum.offer` / `quorum.join` | Wraps `RTCPeerConnection` + signaling handshake | SESSION cell region, RunBar `waiting-peer` state | ✅ 21a |
| `rtc.createOffer` / `rtc.createAnswer` | Raw SDP offer/answer (escape hatch below `quorum.*`) | Read-only SDP blob, `OutputList` binary-artifact pattern | ✅ 30d |
| `rtc.connectionState` | Exposes `connectionState`/`iceConnectionState`/`signalingState` live | State-machine strip (26a's type-row shape) | ✅ 30d |
| `quorum.close` | Tears down the session | Reuses SESSION region's Close button | ✅ 21a |
| `rtc.certificate` | DTLS identity (`RTCCertificate`) — the fingerprint 28b displays | Keys-tray subsection, pin/regenerate | ✅ 29a |

## 3. Data channel
`RTCDataChannel` — arbitrary data exchange once connected.

| Op | Description | UI needed | Status |
|---|---|---|---|
| `quorum.send` | Pipes a cell's bytes over the data channel | Standard pipeline chip | ✅ 21a |
| `quorum.recv` | **Not single-output** — fires repeatedly; live-appending list, "run downstream vs. collect" per message | New shape: `cell.output` array; 30c | ✅ 30c |
| Reliability config | `ordered`/`maxRetransmits`/`maxPacketLifeTime`, fixed at channel open | Radio + conditional field in `quorum.offer`'s param editor | ✅ 29b |
| `rtc.dataChannelStats` / back-pressure | Buffered amount; throttles `send()` past the high-water mark | Progress bar (20b's primitive) | ✅ 30d |

## 4. Media capture &amp; streams
`getUserMedia`, `MediaStream`/`MediaStreamTrack`. ⛔ Not planned — Basilisk
is a text/crypto notebook, not a calling app; revisit only if that changes.

## 5. Telephony (DTMF)
`RTCDTMFSender`. ⛔ Not planned — no PSTN/telephony use case.

## 6. Stats &amp; diagnostics
`RTCStatsReport`, `getStats()`.

| Op | Description | UI needed | Status |
|---|---|---|---|
| `rtc.statsReport` | Live bitrate/RTT/packet-loss | Sparkline + numbers in the peer detail drawer | ✅ 29d |

## 7. Encoded transforms
`RTCRtpScriptTransform`, worker-based frame processing. ⛔ Not planned — no
media pipeline exists for it to transform.

## 8. Multi-party (not an MDN section — a Basilisk-specific fit)
WebRTC itself is strictly peer-to-peer; "multi-party" here means composing
`n` independent sessions with a toolkit primitive that already exists.

| Op | Description | UI needed | Status |
|---|---|---|---|
| `quorum.mesh` | Wraps `sss.split`'s `n` shares into `n` parallel `quorum.offer` connections, one per recipient, auto-routed share→peer | New MESH cell region (roster list), each row surfaces in the tray's Active peers same as any session | ✅ 29c |

This is the strongest new idea from the "what else fits" pass — it isn't a
port of another MDN interface, it's the toolkit's own k-of-n secret sharing
made literal as k-of-n peer connections. Readiness reads "quorum reachable"
(k connected) rather than requiring all n.

## The full handshake, phase by phase
Two phases had no design owner through turn 26 despite sitting between "ICE
connected" and "data channel open": **DTLS** (secures the nominated pair via
handshake) and **SCTP** (negotiates the data-channel transport on top of
DTLS). Both were implicit inside `QuorumSession` with zero UI surface.

| Phase | What happens | Design |
|---|---|---|
| Signaling | Offer/answer traded via the PGP-signed invite blob | 21a |
| ICE | Gather, check, nominate, restart on failure | 23a-c, 26a, 26b, 26c |
| DTLS | Handshake secures the nominated candidate pair | 28a (log), 28b (peer detail), 29a (identity op) |
| SCTP | Negotiates the data-channel transport over DTLS | 28a (log), 28b (peer detail) |
| Channel | `quorum.send`/`recv` flow; reliability config; back-pressure | 21a, 29b, 30c, 30d |
| Recovery | ICE restart when a connected session drops | 26c |

New chrome from this pass: a phase-colored per-peer **session log** (28a,
supersedes 24c's flat console), a **peer detail drawer** (28b — real
`getStats()`/transport fields: candidate-pair addresses, DTLS fingerprint,
SCTP state, now also bandwidth from 29d), and a **message hexdump** (28c) —
explicitly scoped as the decrypted `RTCDataChannel` payload, since no browser
API exposes raw wire packets to a page; never design this as a packet sniffer.

## Storage — what belongs where (turn 30)
Three scopes, three stores, deliberately not mixed:

| Data | Store | Why |
|---|---|---|
| Theme, last-active tray tab | `localStorage` | Device UI preference |
| Default STUN server URLs (24b) | `localStorage` | Not secret |
| TURN credential (22a/24b) | App's existing secret store (same as keys) | Follows 22a's rule — never a plaintext side channel |
| `RTCCertificate` (29a "pin across sessions") | IndexedDB, `certificates` store | The object itself is structured-clonable — the *only* way pinning can work; a fingerprint string alone can't reconstruct the identity |
| Session log (28a) | IndexedDB, `sessionLog` store, ring-buffered per notebook (~2000 rows) | Survives reload; unbounded growth would not |
| Peer history | IndexedDB, `peerHistory` store | Powers a future "recently connected" suggestion in Active peers; not its own widget yet |

One `basilisk_webrtc` IndexedDB database (`certificates`, `sessionLog`,
`peerHistory` stores), versioned separately from the notebook-document
store. Full schema: turn 30b.

## quorum.recv is not a single-output op
The one real risk found in this whole pass: turn 21a modeled `recv` like any
other op with one output slot. A data channel's `message` event can fire any
number of times over a session, so `recv`'s output is a live-appending list
(same shape as 23a's candidate list), and each row is a real pipeline value —
not just a diagnostic — that downstream cells may or may not want to consume
automatically. Default behavior is **collect only**: incoming messages append
to the list, and the user explicitly triggers "Run [N] on this" per message.
An opt-in "Run downstream" mode re-executes automatically per message. This
is a `cell.output: OutputArtifact → OutputArtifact[]` shape change — flag it
to whoever retrofits 21a specifically, since it's the one place existing
single-output assumptions elsewhere in the pipeline could break silently.
Full detail: turn 30c.

## New kinds &amp; shelf tree
Four pipeline kinds beyond bytes/text/ciphertext/signature: `candidate`
(diamond glyph), `session` (square glyph), `channel` (triangle glyph),
`connState` (hollow ring — observe-only, never bindable as an input). All
render at the same 6-7px dot size via pure CSS shapes, no icon assets. The
`OpsShelf` WebRTC category groups into ICE/STUN, Peer &amp; signaling, Data
channel, Stats sub-headers — the one category deep enough to need that
second tree level. Two tool dialogs (Add server, peer detail) reuse the
existing `Popover` primitive; no new dialog system. Full detail: turn 25.

## Tray chrome vs. pipeline ops
Not every WebRTC capability should be a recipe op. A `Connections` tray tab
(turn 24) — the shell's fifth tray tab, after Keys/Slots/Inputs/Params, per
turn 27's full composite — holds built-in, always-there session/connection
management, the same split the tray already makes for secrets (`Inputs`):

| Tray section | Holds | Status |
|---|---|---|
| Active peers | Every live/pending session across all cells (mesh rosters included), jump-to-cell, Close/Cancel | ✅ 24a, 27 |
| Server preferences | Default STUN/TURN list any `rtc.ice` cell falls back to; TURN credential is the tray-bound `secret` field | ✅ 24b |
| Session log | Full phase-colored per-peer event history | ✅ 28a |
| Peer detail | IP/port/candidate-pair/DTLS/SCTP/bandwidth drawer | ✅ 28b |

Ops (sections 1-3, 8) stay the explicit, recipe-authored path for composing
or overriding connectivity behavior; the tray is the ambient, always-on path
for everyday visibility and defaults. Neither replaces the other — `rtc.ice`'s
own params fall back to the tray default when left empty.

## Design principles carried through every item above
- Every WebRTC capability becomes a **pipeline op**, not a separate page —
  same `OpsShelf` category tree, same cell/chip/caret vocabulary as crypto
  ops (21a's core decision).
- **Secret params never become literal text or serialize into a share link**
  — `rtc.ice`'s TURN `credential` is the reference case (22a).
- **Diagnostics show the whole graph, not a verdict** — 23a/26a's per-type
  candidate list, 23b/26b's per-pair matrix, 28a's phase-colored log all
  reject a single pass/fail rollup.
- A run **pauses at a cell** rather than needing a separate async/await UI
  model — `waiting-peer` (21a) is the pattern any long-running op reuses.
- **State the platform's real limits plainly** — 28c's hexdump is the
  decrypted message payload, not a packet capture, because that's genuinely
  all `RTCDataChannel` can expose; design honesty over implying a capability
  that doesn't exist. The same rule now applies to the *transport*: `rtc.offer`
  and `rtc.answer` close their own `RTCPeerConnection` before returning, so the
  raw-SDP escape hatch in §2 hands back a blob whose connection is already
  gone, and the hand-carried exchange two shipped templates describe cannot
  complete. The `sdp` panel says so above the blob. See deviation 5 in
  `IMPLEMENTATION-STATUS.md` — that is the one place in this bundle where a
  designed capability turned out not to exist, and it needs a new op
  (`rtc.accept`) plus a live-offer registry, not a UI change.
- **Reuse the toolkit's own primitives before inventing new ones** — 29a
  mirrors `genkey`'s shape, 29c wraps `sss.split` instead of building a new
  group-session concept from scratch.
- **Not every value is single-shot** — 30c's correction to `quorum.recv`
  generalizes: any op wrapping a repeating browser event (not just WebRTC)
  should default to a live-appending output list, not a one-shot slot.

## Explored, not planned
Media capture (§4), DTMF telephony (§5), and encoded transforms (§7) were
checked against Basilisk's actual use case (text/crypto notebook) and don't
fit — no product need for camera/mic capture, no PSTN interop, no media
pipeline for frame transforms to act on. Revisit only if a future product
decision adds audio/video or telephony to Basilisk's scope.

## Next design turns, in priority order
1. `quorum.mesh`'s roster UI at scale (n=5+) — turn 29c mocked n=3; worth a
   pass on how the tray's Active peers list reads once several mesh sessions
   run concurrently.
2. Peer history suggestions in Active peers, now that `peerHistory` (30b)
   exists as a store with nothing reading it yet.

## Source
Design project: this project (turns 21a–30 in `Basilisk Toolkit v2.dc.html`).
Retrofit target: `b1tninja/basilisk`, branch `feat/toolkit-redesign`, same
file locations noted in the Quorum and 21b–22b handoff packages
(`design_handoff_quorum_toolbox/`, `design_handoff_remaining/`).
