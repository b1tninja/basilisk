# WebRTC toolbox — implementation status

Records what actually landed in `b1tninja/basilisk` (`feat/toolkit-redesign`)
against this handoff, plus the deviations the README asks be written back so
the next person isn't misled by a stale spec. **Last updated 2026-08-01.**

Every state below was checked against the code on the day it was written. The
previous revision of this file was two days old and wrong in four places — it
listed op names that had been renamed, filed a shipped Connections tray and a
shipped ICE restart under "not implemented", and reported a test count from a
run with three failing files. A blanket find-replace in a sibling status doc
once ticked three unbuilt items and had to be walked back, so each line here
was verified individually rather than swept.

## Landed — the ops layer

All 16 WebRTC ops are registered, dispatched, and verified against real browser
WebRTC APIs. `lib/toolkit/rtc-ops.js` is the module; `quorum-ops.js` has a
`getLiveSession()` accessor so the diagnostic ops can read live transports
without importing the mesh.

**The `quorum` toolbox is back, and this doc's own §8 is why.** For several
turns the count above read 22, because an earlier pass renamed the `quorum`
toolbox to `webrtc` "so all the ops live in one category" — a spec-named drawer
absorbing a Basilisk-specific one. That put `quorum.offer`, `quorum.join`,
`quorum.close`, `quorum.send`, `quorum.recv` and `dkg.run` under a header
claiming they were WebRTC. `WEBRTC-TOOLBOX.md` §8 had already ruled on this
before the code was written — it is titled *"not an MDN section — a
Basilisk-specific fit"* — and the registry simply had not followed. The test is
now whether an op is a WebRTC built-in:

| Op | Now in | Because |
|---|---|---|
| `quorum.offer` / `quorum.join` / `quorum.close` | `quorum` toolbox, **Exchange** shelf | A room derived from an OpenPGP audience and a signed invite posted through a relay is not in any WebRTC specification |
| `quorum.send` / `quorum.recv` | `quorum` toolbox, **Data channel** shelf | Encrypted under the pairwise session key; the shelf is deliberately the same one `peer.send`/`peer.recv` are on, so the two send verbs keep one header and one mark |
| `dkg.run` | `sss` toolbox, **Split** shelf | Feldman VSS over P-256 — the same scheme and curve as the four `vss.*` ops it now sits with. A live exchange is its *transport*, and transport is not a filing rule: `rtc.check`/`state`/`stats`/`quality`/`restart` all need one and are WebRTC regardless |

**No op was renamed.** `rtc.*` is the specification's own prefix
(`RTCPeerConnection`, `RTCCertificate`, `RTCDataChannel`), `peer.*` names that
central object, and `stun.check` is a gather against a STUN server; there is no
`webrtc.*` namespace and `step-names.js` was not touched. Namespace and toolbox
are separate questions — see the note below, and `HANDOFF.md`.

**`lib/webrtc/` now exists, and quorum consumes it.** Four things that are plain
WebRTC were inside the session layer, which had `lib/toolkit/rtc-ops.js` and
`peer-ops.js` — the modules implementing the *spec* ops — importing from the
layer that is supposed to sit on top of them:

| Moved | From | Why it is not quorum's |
|---|---|---|
| `link-registry.js` | `lib/quorum/` | An inventory of `RTCPeerConnection`s. Holds no fingerprint, derives no key, drives no negotiation |
| `DEFAULT_ICE_SERVERS` → `webrtc/ice.js` | `lib/quorum/rtc.js` | An `RTCIceServer[]` |
| `offerCollisionAction` → `webrtc/negotiation.js` | `lib/quorum/rtc.js` | The MDN perfect-negotiation glare rule, already pure |
| `selectedCandidateType` → `webrtc/candidates.js` | `lib/quorum/roster.js` | A `getStats()` read that knows which engines omit the `transport` stat |

Delete `lib/quorum/` and `peer.*`/`rtc.*` still stand, which is the test.

**What was deliberately not extracted.** The driver — `RTCPeerConnection`
construction, `onnegotiationneeded`, `ondatachannel` and everything downstream
— stays inside `QuorumSession`. Not effort: `derivePairwiseSessionKey` binds
**both DTLS fingerprints** into the transcript and `peer.localDtls` is assigned
from the local description *inside* the negotiation handler, so moving
negotiation moves the instant that fingerprint becomes known. The failure mode
of getting it subtly wrong is key confirmation **succeeding anyway** over a
transcript no longer bound to the transport — green tests, broken binding. That
extraction needs its own pass with the binding as the thing demonstrated (§59b).

**The op names in the design turns are not the shipped names.** The camelCase
originals were shortened during implementation; a reader following the design
doc will not find them in the registry:

| Turn's name | Shipped name |
|---|---|
| `rtc.gatherCandidates` | `rtc.gather` |
| `rtc.checkConnectivity` | `rtc.check` |
| `rtc.createOffer` / `rtc.createAnswer` | `peer.offer` / `peer.answer` (via `rtc.offer`/`rtc.answer`, both since retired) |
| `rtc.connectionState` | `rtc.state` |
| `rtc.dataChannelStats` | `rtc.stats` |
| `rtc.statsReport` | `rtc.quality` |
| `quorum.send` / `quorum.recv` | `quorum.send` / `quorum.recv` — shipped as `rtc.send`/`rtc.recv` for several turns, then moved back; see the note below |
| — (not in the design) | `rtc.restart`, `dkg.run` |

**The one row that went out and came back.** `quorum.send`/`quorum.recv` were
renamed to `rtc.send`/`rtc.recv` on the argument that channel traffic is a
transport primitive and `quorum.*` should cover only the exchange — room,
roster, lifecycle. The claimed payoff was that the ops would then work on any
data channel. They never could: both dispatch to
`execQuorumSend`/`execQuorumRecv`, which require a live exchange, address peers
by PGP fingerprint, and encrypt under the pairwise session key derived in
`lib/quorum/crypto.js`; `rtc.send`'s doc string said *key-confirmed channels
only* throughout. §55c confirmed it from the other side by declining to widen
them to `peer.*` links for exactly that reason. The design turn's name was the
right one and has been restored; `peer.send`/`peer.recv` (§55) are what actually
deliver "works on any data channel".

That story is about the **name**, and it is settled: `quorum.send` is not
becoming `rtc.send` a third time. The toolbox move above is a different axis —
`quorum.send` keeps its name *and* its "Data channel" shelf, and only the
category header above it changed. Anyone reading the two together should not
conclude the channel ops are drifting back out of `quorum.*`; they are not.

| Op | Turn | Verified |
|---|---|---|
| `rtc.ice` | 23c | ✅ live — STUN and TURN server lists, credential bound to a slot |
| `stun.check` | 22b | ✅ live — reflexive address in 127ms, plus the candidate mix |
| `rtc.gather` | 23a, 26a | ✅ live — real `host` + `srflx`; `relay` proven 2026-08-01 against a coturn |
| `rtc.check` | 23b, 26b | ✅ against a real connected pair (`succeeded`/`nominated`, rtt, bytes) |
| `rtc.certificate` | 29a | ✅ live — ECDSA P-256 and RSA 2048, real SHA-256 fingerprints |
| ~~`rtc.offer`~~ | 30d | retired → `peer.offer` (deviation 5) |
| ~~`rtc.answer`~~ | 30d | retired → `peer.answer` (deviation 5) |
| `rtc.state` | 30d | ✅ shape verified; clean error with no live exchange |
| `rtc.stats` | 30d | ✅ `data-channel` stats + back-pressure fields confirmed real |
| `rtc.quality` | 29d | ✅ candidate-pair rtt/bytes real. **Loss is not reported at all — deviation 6.** |
| `rtc.restart` | 26c | ✅ op exists; `restartLiveIce` was a no-op until 2026-08-01 |
| `quorum.offer/join/send/recv/close` | 21a | ✅ live between two browser contexts |
| `dkg.run` | — | ✅ multi-party, but see "mesh" below |

Also landed: **25a** as a real type system (deviation 1) and **25b** the
four-group WebRTC shelf tree (ICE / STUN · Peer & signaling · Data channel ·
Stats). Values carry *structured* data end to
end (the `recipients` precedent) — the engine renders them as JSON only at
`out`, so downstream ops read fields instead of re-parsing strings.

## Manager widgets — typed artifacts render as UI, not JSON

`toolkit/widgets/NetworkArtifact.tsx` renders a network artifact as a real
widget, dispatching on the pipeline **type**. Nine renderers, each a read-out of
data the op already produces — none invent browser capabilities.

The organising question for all nine is that **these are the screens a user
lands on when a connection fails**, so each is judged by whether it answers
*why did this not connect, and what do I do next*. Three of them did not, and
were rebuilt on 2026-08-01; the derivations behind them live in
`lib/toolkit/artifact-readouts.js` (`connStateReadout`, `stunReachability`,
`sdpReadout`) rather than inside the component, because a verdict written in a
widget is a verdict with no test.

| Type | Renderer | Turn |
|---|---|---|
| `candidate` | Typed ICE rows; all four MDN types listed, absent ones explained | 23a, 26a |
| `stats/candidate-pairs` | Pair matrix; nominated tinted, role badge, all-failed → "Configure TURN" | 23b, 26b |
| `connstate` | Verdict + three-stage track + terminal outcome, per peer | 30d |
| `stats/data-channel` | Back-pressure bar against the low-water mark + counters | 30d |
| `stats/quality` | RTT / throughput; loss stated as unmeasurable | 29d |
| `endpoint` | ICE server list, or `stun.check`'s verdict and candidate mix | 23c, 22b |
| `certificate` | DTLS algorithm + fingerprints + expiry verdict | 29a |
| `session` | Room, role, connected count, audience | 21a |
| `sdp` | Fingerprint / candidates / transport, then the closed-transport note | 30d |

Each artifact row also gains an **Expand** action opening the same widget in its
own window (the shell's existing `Sheet`) with a "Copy raw" escape hatch. All
nine have catalog fixtures under `#networkartifact`, **including the failure
states** — `connstate` failed/disconnected/closed, `connstate` connected with a
channel that will not open, and `endpoint` blocked. Those were added the day the
`failed` bug below was found, because a catalog that shows the happy path by
accident shows nothing on purpose.

Deliberately *not* built: automatic polling to keep a live artifact refreshing.
Re-running an op is the cell's own Run button.

## Deviations from the spec — read these

1. **~~`valueKind` is UI-only~~ — RESOLVED, the types are real.** The `IoType`
   union carries the full network vocabulary — `host`, `endpoint`, `candidate`,
   `sdp`, `certificate`, `session`, `channel`, `peer`, `connstate`, `stats` —
   split three ways in `types.js`: **DATA** (inert, serializable), **HANDLE**
   (`session`/`channel`, a live browser object), **OBSERVE**
   (`connstate`/`stats`, a diagnostic). `isObserveOnlyType` enforces that HANDLE
   and OBSERVE values display but never *feed* a computing op. Dot shapes derive
   from the declared `output` type via `shapeForType()`. `valueKind` is gone.

2. **`RTCIceTransport.role` is `null` in Chromium** even on a fully connected
   transport. 26b's controlling/controlled badge is therefore blank in practice;
   the op reports `""` rather than guessing and the panel says "role not
   reported by this browser".

3. **Local candidate `address`/`ip` are empty strings** in Chrome's
   `local-candidate` stats (mDNS redaction). The pair matrix labels pairs
   `type:port` (`srflx:60122`), which is what 23b's mock shows anyway.

4. **Registry lookup was case-broken; fixed.** `getStep`/`canonicalName`
   lower-case their query but `BY_NAME` stored authored casing, so any
   mixed-case op name was silently unresolvable. Registration now lower-cases
   its keys while `step.name` keeps authored casing.

5. **~~`rtc.offer` and `rtc.answer` close their own `RTCPeerConnection`~~ —
   RESOLVED 2026-08-02, and the ops are gone.** They closed their connection in
   a `finally` before returning, so the ICE ufrag/pwd and DTLS fingerprint in
   the blob named an object that had been torn down, and `sdp-hand-carried` /
   `sdp-to-clipboard` described a flow that could not complete.

   The predicted fix — "a live-offer registry and an `rtc.accept` op" — is what
   landed, at a layer rather than as two ops: `redesign/design_handoff_peer_connections/`.
   `rtc.offer`/`rtc.answer` are retired and migrated to **`peer.offer`** /
   **`peer.answer`**, which keep the connection under a name in
   `lib/quorum/link-registry.js`; **`peer.accept`** applies the remote answer
   and **`peer.wait`** blocks until ICE completes. Both template blurbs are
   corrected, and `sdp-hand-carried` now really connects. The `sdp` panel's note
   (`SDP_CARRY_NOTE`, formerly `SDP_TRANSPORT_CLOSED`) says what to do with the
   blob instead of why it cannot work. Measured between two real browsers in
   `src/test/e2e/peer-manager.e2e.js`.

6. **`rtc.quality` does not report packet loss, and cannot.** It used to print
   `0% loss`; the figure was RTP losses divided by ICE-path packet counts, two
   different populations, and `remote-inbound-rtp` does not exist on a
   data-channel-only connection. There is no RTP on an SCTP transport to lose
   packets from. The panel says "loss not measured" in words rather than a dash,
   because a dash beside a real RTT reads as a number that has not arrived yet.

7. **`stun.check` can never obtain a relay candidate.** It refuses any `server=`
   that is not `stun:`/`stuns:` and builds its connection with no username and
   no credential, so it never attempts an allocation. Its relay count is a
   constant, measured as zero against a live coturn that was relaying for two
   peers at the time. The panel drew it as `RELAY ×0` beside two real counts,
   reading as "TURN was checked and is missing"; the row now says it was not
   probed and names `rtc.gather`, which is the op that can be given credentials.
   `stunReachability` says nothing about relay for the same reason.

8. **A wrong TURN password and a dead TURN server are indistinguishable** in
   every surface. Both produce an empty candidate list; only
   `icecandidateerror` code 401 tells them apart and nothing in the app reads
   it. The candidate panel's relay row no longer claims "no TURN configured" —
   it names all three possibilities and says they arrive identically.

9. **`connectionState: "failed"` rendered as a blank strip.** The `connstate`
   track was `new → connecting → connected → disconnected → closed`;
   `"failed"` is a real `RTCPeerConnection.connectionState` and was on none of
   it, so `indexOf` returned `-1`, no segment lit and no label bolded — a failed
   connection drew pixel-identical to one that had never started, on the panel
   that exists for that state. The track is now the three stages that really are
   a sequence, with outcomes (`disconnected`/`failed`/`closed`) as a terminal
   verdict beside it rather than milestones in line after `connected`.

10. **ICE is not governed by CSP.** Verified and pinned: zero
    `securitypolicyviolation` events with STUN reaching a third party, and none
    under TURN either, under `connect-src 'self'` plus two keyservers.

11. **`iceTransportPolicy` is never set** — always the default `"all"`. The
    relay path is proven to *work* (forced with `"relay"` in the e2e harness);
    it is not proven to be *chosen* under real symmetric NAT, because no NAT is
    simulated.

## Landed since the previous revision of this file

These were filed under "not implemented" on 2026-07-30 and are wrong there.

- **24a Connections tray tab** — shipped, third of the tray's seven tabs, in
  read-to-write order: what you hold → what is live → what a run made. It holds
  **Active peers only**: the live session's phase, room, role, mesh-health line,
  per-peer roster with connectivity *and* authentication reported separately,
  and Copy invite / Restart connection / Close session.
- **26c ICE restart** — shipped. `SessionStrip` has a `failed` state and an
  `onRestartIce`, `ConnectionsPanel` has the same button, and `rtc.restart` is a
  registered op. `restartLiveIce` was a **no-op until 2026-08-01** and the
  button has still never been exercised by a real user.
- **30c `quorum.recv` array output** — resolved, but **not the way the handoff
  specified**. `cell.output` did not become an array; `cellOutputs` was already
  `ArtifactTile[][]` per cell. Instead `quorum.recv` takes `count=` — `1` (default)
  emits one message as text, `3`/`all` collects several and emits a `bundle` for
  `foreach`. The repetition became a parameter of the op rather than a shape
  change to the notebook, which is why the audit of `useNotebook.ts` the handoff
  called for was never needed. The handoff's own "highest-risk item" framing no
  longer applies and should not be re-raised.

## Not implemented — remaining scope

- **24b Server preferences** — no default STUN/TURN list in `localStorage`, no
  "+ Add server" popover. `rtc.ice` has built-in defaults and no tray fallback.
- **28a/28b/28c** — no session log, no peer detail drawer, no message hexdump.
  The Connections tab shows what is live, not what happened.
- **29b channel reliability** — no `ordered`/`maxRetransmits`/
  `maxPacketLifeTime` block on `quorum.offer`; the channel is always
  reliable-ordered.
- **29c `quorum.mesh`** — no op, no MESH cell region, no `sss.split` → n-peer
  auto-routing. Multi-party landed instead as `dkg.run`, whose roster the
  Connections tab renders and whose mesh degree it states (`meshHealth`,
  honest past ~8 participants). The k-of-n readiness idea is unbuilt.
- **30a/30b storage** — no `basilisk_webrtc` IndexedDB database. Certificates
  are ephemeral (no pinning), no session log or peer-history persistence.
- ~~**`rtc.accept`**~~ — built, as `peer.accept`. See deviation 5.
- **A 401 signal** — nothing reads `icecandidateerror` (deviation 8).

## Glyphs

`TOOLBOX_META.webrtc`, `SHELF_META.peer` and `SHELF_META.channel` all pointed at
the `agent` glyph — a vault key standing for a peer connection. Enumerating all
118 registered steps showed `agent` resolving for exactly seven ops, every one
of them WebRTC, and for no `agent.*` op at all: the mark belonged to the toolbox
that had never been drawn, not to the one it was named after.

Three marks were authored (`web/glyphs/svg/`, 20×20, `currentColor`, stroke
1.6), judged rasterised at their shipping sizes — 12px for kind badges, 16px for
the ops drawer — and magnified nearest-neighbour rather than viewed as vectors:

| id | Metaphor | Ink coverage @12px | vs. the `agent` it replaces |
|---|---|---|---|
| `webrtc` | A span on two solid footings — ICE *builds* the route | 18.5% | 1.31× |
| `peer` | Offer and answer as two wedges facing across a gap | 24.4% | 1.73× |
| `channel` | Two arrows, opposite directions, vertical | 23.4% | 1.66× |

All three sit inside the shipped band (`flow` 12.5% … `io` 26.4%) and above
`agent`'s 14.1%. Solid pixels at 12px is the sharper figure: `peer` has 34 where
`agent` has 6, which is why a mark that was legible at 20px was a smudge on a
badge. Two rejected candidates are the argument for rasterising: a diagonal
dumbbell for `webrtc` collapsed into `key-pair`'s silhouette, and a
dots-and-arcs lens collapsed into `ports`'. The seven ops' redundant explicit
`glyph: "agent"` declarations were deleted rather than retargeted, so the shelf
is now the single source of its ops' marks.

`ice` and `rtcstats` still borrow I/O's `ports`. Left as-is: two sockets and a
bridge is a fair reading of a candidate pair, and it rhymes with `webrtc`'s
span. Worth revisiting only if the collision with the I/O shelf bites.

## Contrast

Measured on the catalog in both themes with a probe that composites every
ancestor background and every ancestor opacity, sanity-checked against
black-on-white = 21.00 before any figure was believed. (An earlier probe read
`color(srgb …)` channels as 0-255 and reported a false failure; another
composited its layers in the wrong direction and reported 1.00 for everything.)

Before: 40 nodes below 4.5:1 in light, 12 in dark. After: **none in either**,
across 208 measured nodes. The four causes were all one mistake in four places
— a hand-written alpha where `--tile-tint` exists, and `--tile-tint` is 6% in
light and 12% in dark precisely because the light accents are chosen to clear
4.5:1 on the plain surface:

- `.net-badge` hard-coded 12%; twenty badges sat at 3.96–4.20 in light while the
  identically-hued `.artifact-badge` passed.
- `SessionStrip` and `ConnectionsPanel` each wrote their own 14%/16% verdict
  chip (3.59–4.42). One `.peer-verdict` rule now serves both.
- The absent-candidate rows and non-nominated pair rows carried `opacity-45` /
  `opacity-50`, which took their *explanations* down with the badge: "none
  gathered — no TURN configured" measured 2.16:1. The badge fades; the sentence
  does not. The nominated pair is marked *up* with a tint instead of every other
  pair being marked down — same hierarchy, legible either way.
- The panel's own `--surface-raised` wash was 55%; in dark, the raised surface
  is lighter than the page, so every wash of it spends contrast on the muted
  text inside. 30% recovers it and the border still carries the grouping.

## Verification bar used

`npm run build` · `npx tsc --noEmit` (clean but for the pre-existing
`src/lib/memory-safety.js`) · `npx vitest run` — **140 files / 2484 tests, all
passing**, no known failures. `npm run test:e2e` — 3 files / 57 tests, real
Chromium contexts against the built app under the shipped CSP, including a real
coturn for the relay path.

The bug worth remembering from live verification: `rtc.gather` originally
awaited its gather promise *before* `setLocalDescription`, so it returned zero
candidates — gathering does not start until the local description is set.
`rtc.offer`/`rtc.answer` similarly emitted SDP before gathering finished. Both
now wait correctly. Green gates are not proof: every one of deviations 5, 6, 7,
8 and 9 passed `tsc` and the full suite while wrong in the page.
