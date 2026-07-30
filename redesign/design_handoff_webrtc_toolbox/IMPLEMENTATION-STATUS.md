# WebRTC toolbox — implementation status

Records what actually landed in `b1tninja/basilisk` (`feat/toolkit-redesign`)
against this handoff, plus the deviations the README asks be written back so
the next person isn't misled by a stale spec. Last updated 2026-07-30.

## Landed — the ops layer

All 8 new ops are registered, dispatched, and verified against real browser
WebRTC APIs. `lib/toolkit/rtc-ops.js` is the new module; `quorum-ops.js` gained
a `getLiveSession()` accessor so the diagnostic ops can read live transports
without importing the mesh.

| Op | Turn | Verified |
|---|---|---|
| `rtc.gatherCandidates` | 23a, 26a | ✅ live — real `host` + `srflx` in 127ms against Cloudflare STUN |
| `rtc.checkConnectivity` | 23b, 26b | ✅ against a real connected pair (`succeeded`/`nominated`, rtt, bytes) |
| `rtc.certificate` | 29a | ✅ live — ECDSA P-256 and RSA 2048, real SHA-256 fingerprints |
| `rtc.createOffer` | 30d | ✅ live — SDP with 2 candidates + DTLS fingerprint |
| `rtc.createAnswer` | 30d | ✅ live — consumes an offer, emits `setup:active` answer |
| `rtc.connectionState` | 30d | ✅ shape verified; clean error with no live exchange |
| `rtc.dataChannelStats` | 30d | ✅ `data-channel` stats + back-pressure fields confirmed real |
| `rtc.statsReport` | 29d | ✅ candidate-pair rtt/bytes confirmed real |

Also landed: **25a** as a real type system (see deviation 1), **25b** the
four-group WebRTC shelf tree (ICE / STUN · Peer & signaling · Data channel ·
Stats), and the `quorum` toolbox renamed to `webrtc` so all 15 ops live in one
category. Values carry *structured* data end to end (the `recipients`
precedent) — the engine renders them as JSON only at `out`, so downstream ops
read fields instead of re-parsing strings.

## Manager widgets — typed artifacts render as UI, not JSON

`toolkit/widgets/NetworkArtifact.tsx` renders a network artifact as a real
widget, dispatching on the pipeline **type** — which is the concrete payoff of
deviation 1 being resolved. Ten renderers, each a read-out of data the op
already produces (none invent browser capabilities):

| Type | Renderer | Turn |
|---|---|---|
| `candidate` | Typed ICE rows; all four MDN types listed, absent ones dim + explained | 23a, 26a |
| `stats/candidate-pairs` | Pair matrix; nominated highlighted, skipped at 50%, role badge, all-failed → "Configure TURN" CTA | 23b, 26b |
| `connstate` | new→connecting→connected→disconnected→closed strip per peer | 30d |
| `stats/data-channel` | Back-pressure bar against the low-water mark + counters | 30d |
| `stats/quality` | RTT / loss / throughput | 29d |
| `endpoint` | ICE server list, or stun.check's discovered address | 23c, 22b |
| `certificate` | DTLS algorithm + fingerprints | 29a |
| `session` | Room, role, connected count, audience | 21a |
| `sdp` | Raw SDP block | 30d |

Each artifact row also gains an **Expand** action opening the same widget in
its own window (the shell's existing `Sheet`, per the handoff's "reuse
existing primitives" requirement) with a "Copy raw" escape hatch. All ten have
catalog fixtures under `#networkartifact`.

Deliberately *not* built: automatic polling to keep a live artifact refreshing.
Re-running an op is the cell's own Run button; adding a second execution path
from the artifact would duplicate the run loop. A true always-live manager is
the Connections tray tab (24a-c), still unbuilt — see below.

## Deviations from the spec — read these

1. **~~`valueKind` is UI-only~~ — RESOLVED, the types are real.** An earlier
   pass shipped these as `text` plus a presentational `valueKind` badge; that
   has been replaced with genuine pipeline types. The `IoType` union now
   carries the full network vocabulary — `host`, `endpoint`, `candidate`,
   `sdp`, `certificate`, `session`, `channel`, `peer`, `connstate`, `stats` —
   split three ways in `types.js`:
   - **DATA** (`host`/`endpoint`/`candidate`/`sdp`/`certificate`/`peer`) —
     inert, serializable, safe to pipe onward.
   - **HANDLE** (`session`/`channel`) — a live browser object, meaningful only
     inside the run that created it.
   - **OBSERVE** (`connstate`/`stats`) — a diagnostic read-out.

   `isObserveOnlyType` enforces that HANDLE and OBSERVE values can be
   displayed (`out`/`inspect`/`text`) but never *consumed* by a computing op,
   with an error that says why. Real consequences, all regression-tested in
   `toolkit-types.test.js`:
   - `rtc.createOffer | rtc.createAnswer` type-checks; `rtc.gatherCandidates |
     rtc.createAnswer` fails with "expects sdp, got candidate".
   - `quorum.offer | digest` fails: "a live handle is only valid inside the run
     that opened it".
   - `rtc.connectionState | base64` fails: "this is an observe-only diagnostic".
   - `ice=@slot` type-checks against `rtc.ice`'s `endpoint` output and rejects
     e.g. a keypair slot with "not an ICE config — use rtc.ice".

   Dot shapes now derive from the op's declared `output` type via
   `shapeForType()`, so the visual can't drift from what the type system
   actually enforces. `valueKind` is gone.

2. **`RTCIceTransport.role` is `null` in Chromium** even on a fully connected
   transport (verified directly: property exists, `typeof "object"`, value
   `null`). 26b's controlling/controlled badge will therefore be blank in
   practice on Chrome. The op reports `""` rather than guessing, which matches
   26b's own rule ("shows nothing rather than guessing") — but the mock's
   populated badge is not achievable on Chromium today.

3. **Local candidate `address`/`ip` are empty strings** in Chrome's
   `local-candidate` stats (mDNS privacy redaction) even while connected. The
   candidate-pair matrix therefore labels pairs `type:port` (e.g. `srflx:60122`),
   which is exactly the format 23b's mock shows and is always populated. The
   `address` field is still emitted, just blank — don't render it as the
   primary label.

4. **Registry lookup was case-broken; fixed.** `getStep`/`canonicalName`
   lower-case their query but `BY_NAME` stored authored casing, so *any*
   mixed-case op name (`rtc.gatherCandidates`) was silently unresolvable —
   the parser reported "Unknown step". Registration now lower-cases its keys
   while `step.name` keeps authored casing for display/serialization. This was
   a latent bug, not specific to WebRTC; it just had no camelCase op to expose
   it until now.

## Not implemented — remaining scope

None of the larger UI surfaces in this handoff landed. In rough dependency
order:

- **30c `quorum.recv` array output** — the handoff's own flagged
  highest-risk item. `cell.output` is still a single `OutputArtifact`
  everywhere; `quorum.recv` still models one message per run. Nothing in
  `useNotebook.ts` was audited for the array shape yet.
- **24a-c + 27 Connections tray tab** — Active peers, Server preferences,
  Session log. The tray still has its four tabs (Keys/Slots/Inputs/Params).
- **28a/28b/28c** session log, peer detail drawer, message hexdump.
- **26c ICE restart** — `SessionStrip` has no `failed` state or
  `onRestartIce`; only 22b's pre-connection "Configure TURN" exists.
- **29b channel reliability** param block on `quorum.offer`.
- **29c `quorum.mesh`** and the MESH cell region.
- **30a/30b storage** — no `basilisk_webrtc` IndexedDB database; certificates
  are ephemeral (no pinning), no session log or peer history persistence.

## Verification bar used

`npm run build` · `npx tsc --noEmit` · `npm test` — 782 passing, with exactly
the 3 pre-existing failing files (`conjugate-stitch`, `toolkit-engine`,
`webauthn-mds`) unchanged from before this work, plus 6 new type-rule
regression tests in `toolkit-types.test.js`. 8 new verb-smoke cases (all
`compile` mode — every one of these ops needs a real `RTCPeerConnection`, and
several a live exchange, so none can run headless). Live browser verification
was done by driving the ops directly against a genuinely connected
`RTCPeerConnection` pair with an open data channel.

One bug was caught only by live verification and is worth remembering:
`rtc.gatherCandidates` originally awaited its gather promise *before*
`setLocalDescription`, so it returned **zero** candidates (gathering doesn't
start until the local description is set). `rtc.createOffer`/`createAnswer`
similarly emitted SDP before gathering finished, producing blobs with no
candidates — both now wait correctly.
