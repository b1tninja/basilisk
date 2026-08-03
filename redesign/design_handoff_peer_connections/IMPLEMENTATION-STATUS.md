# Peer connection manager — implementation status

What landed against this handoff, what was measured, and the deviations, so the
next person is not misled by a spec that has moved. **Last updated 2026-08-02.**

Every state below was checked against the code or against a running browser on
the day it was written. A sibling status doc once had three unbuilt items ticked
by a blanket find-replace and had to be walked back, so each line here was
verified individually.

---

## Landed — unit 1, complete

### The registry

`web/src/lib/quorum/link-registry.js`. One module-level map of **links**, each
one managed `RTCPeerConnection` plus who made it, held under a name a recipe
can use.

The record stores a **holder** and reads `pc` / `channel` *through* it rather
than copying them at registration. That is load-bearing rather than stylistic: a
quorum peer's channel does not exist when its `RTCPeerConnection` is created —
`_wireChannel` assigns it later and `ondatachannel` may replace it — so a copied
field would be stale from the first renegotiation onward, in the exact direction
that reads as "connected, no channel". Pinned in `peer-links.test.js`.

### The seven ops

`web/src/lib/toolkit/peer-ops.js`, toolbox `webrtc`, shelves `peer` / `channel`.

| Op | in → out | Verified |
|---|---|---|
| `peer.offer` | none → `sdp` | ✅ live — offer with 2 host candidates, real ufrag and DTLS fingerprint |
| `peer.answer` | `sdp` → `sdp` | ✅ live — answers an offer made in a *different browser*, `a=setup:active` |
| `peer.accept` | `sdp` → `connstate` | ✅ live — completes the exchange; refuses an offer, and a link not in `have-local-offer` |
| `peer.wait` | none → `channel` | ✅ live — both ends reached `connected` with the channel open |
| `peer.send` | `text` → `text` | ✅ live — 11 bytes each way, counted by `rtc.stats` |
| `peer.recv` | none → `text`\|`bundle` | ✅ live — A heard `pong-from-B`, B heard `ping-from-A` |
| `peer.close` | none → `connstate` | ✅ live — closes only `peer`-origin links, forgets them |

### Retired and migrated

`rtc.offer` → `peer.offer`, `rtc.answer` → `peer.answer`. **Removed, not
aliased**: both fail live parse with a sentence naming the replacement, and
`migrateRecipe` rewrites them. The two camelCase entries retarget past the names
they used to migrate to (`rtc.createoffer → peer.offer`), because the table is
single-pass and would otherwise migrate one dead name to another. Pinned in
`rtc-channel-ops.test.js`.

### Quorum stopped owning the inventory (§57a)

`rtc.state`, `rtc.check`, `rtc.stats`, `rtc.quality` and `rtc.restart` used to
open with `requireSession()` and walk `session.peers`, so the **mesh was the
definition of "what is connected"** and every one of them refused outright for a
connection made any other way. They enumerate the registry now;
`QuorumSession` registers its peer connections into it (`origin: "quorum"`,
fingerprint as id, `kcVerified` as the authentication fact) and deregisters in
`stop()`.

Nothing about negotiation, key derivation, key confirmation or relay moved. The
mesh keeps every behaviour its e2e suite proved.

### The UI

`ConnectionsPanel` gained a **Direct connections** section; the empty state moved
behind *both* the session and the links being absent, and now names `peer.offer`
first. `NetworkArtifact` gained a `channel` renderer. `linkOriginNote` in
`artifact-readouts.js` is the one wording of the authentication difference, read
by both. Catalog fixtures under `#connections` and `#networkartifact`, including
the failure states and both origins side by side.

### The two template blurbs

`sdp-hand-carried` and `sdp-to-clipboard` in `recipe.js` promised a flow that
could not complete. `sdp-hand-carried` is now a six-cell template that really
connects — both ends in one notebook, so it connects to itself and the whole
handshake is watchable — and says in its blurb that a real exchange runs the
middle cell in the other browser. `peer-live-channel` was written as a third
template and then **folded into it**, because the WebRTC preset group has a
hard cap of 8 and merging made one complete story instead of two partial ones.

---

## Measured, in a real browser

Two isolated Chromium contexts, the built `dist/` over `http://127.0.0.1`, the
shipped production CSP. `src/test/e2e/peer-manager.e2e.js`.

```
offer candidates : 2 | ufrag JX+6
offer dtls fpr   : 86:D3:EB:CE:77:8B:DF:7B:AC:B6:A3:83:05:00:A2:FD:…
answer setup     : active
rtc.state        : connectionState=connected iceConnectionState=connected
                   channelState=open origin=peer authenticated=false via=host
nominated pair   : host:57791 (192.168.1.70) ↔ host:55266, udp,
                   state=succeeded nominated=true
                   bytesSent=2238 bytesReceived=2401
rtc.stats        : readyState=open messagesSent=1 messagesReceived=1
                   bytesSent=11 bytesReceived=11
rtc.quality      : packetsSent=10 packetsReceived=10 packetLossPct=null
A heard / B heard: ["pong-from-B","ping-from-A"]
peer.wait        : {link:"a",origin:"peer",state:"open",via:"host"}
                   {link:"b",origin:"peer",state:"open",via:"host"}
CSP violations   : none, either peer
```

`bytesSent=11` is `"ping-from-A".length`, which is the check that the channel
carried the payload rather than only DTLS/SCTP setup.

**Contrast**, on the catalog in both themes, with a probe that composites every
ancestor background and every ancestor opacity, sanity-checked at
black-on-white = **21.00** before any figure was believed:

| Theme | Nodes | Minimum | Below 4.5:1 |
|---|---|---|---|
| light | 42 | **5.24** (`channel` verdict chip) | 0 |
| dark | 42 | **5.74** (`channel` note rows) | 0 |

Every colour is an existing measured rule — `.peer-dot`, `.peer-verdict`,
`--muted-foreground` — so this is a confirmation that the new nodes inherited
them correctly, not a new palette.

**Target size**: all seven per-link controls measure **24 × 56–64 px** against
2.5.8's 24×24 floor, and each carries an `aria-label` naming its link (`Close
connection alice-laptop`). **Inline style attributes inside these widgets: 0**,
measured live.

---

## Deviations — read these

1. **`peer.wait` emits the `channel` handle, and that gave `channel` its first
   producer.** Three things had to move in one commit and are easy to separate
   by accident: the producer, the `netvalue` role (`NETWORK_BASES` in
   `types.js`), and a renderer (`hasNetworkRenderer` + a `ChannelPanel`). A
   producer without the role stamps `text` on a live channel; a role without a
   renderer resolves to `network-value` and then draws nothing, which is the
   shape of the defect that once left `hasNetworkRenderer` undefined and the
   widgets catalog blank. `network-tip.test.js` now gates all three together.

   Consequence: **`channel` is no longer a "reserved" type.**
   `type-card-reserved.test.js`'s unmakeable list is `["host", "item", "none",
   "peer"]`, down from five. Being a HANDLE still means nothing may *consume*
   it — `isObserveOnlyType` is unchanged — and that is a different question from
   whether it may be drawn. `session` is the precedent: also a handle, drawn as
   a `netvalue` since §21a.

2. **A connection name is not a slot, and `peer.offer @a` is refused.** Every
   other cross-cell reference in this language is `@slot`, so the habit is
   strong and the first draft of this very design used `@a` throughout — caught
   by a test, not by review. The refusal names the fix specifically
   (`write it without the @`) rather than emitting a bare charset complaint,
   which would read as "your name has a typo" and send a reader hunting for one.

3. **`peer.recv` refuses a quorum link by name.** Only a link this module opened
   has an inbox — `wireChannel` installs the listener that fills one — and a
   mesh link's traffic is decrypted under the pairwise session key and delivered
   through the session's own `onChat`. Found by the node test, which crashed on
   `undefined.length`; it now says so and names `quorum.recv`.

4. **The channel ops were deliberately *not* widened** to reach managed links.
   They encrypt under the exchange's pairwise session key, which a direct link
   does not have. Reusing the names would either throw somewhere confusing or —
   if anyone "fixed" the throw — put plaintext on an unauthenticated channel
   under ops whose entire history is encrypted traffic.

   They were `rtc.send`/`rtc.recv` at the time, and this finding is what
   retired that name afterwards: an op that must not be used at the transport
   layer should not be named for it. They are `quorum.send`/`quorum.recv`
   again, and `peer.send`/`peer.recv` — added in this same unit — are the verbs
   that genuinely do work on any managed channel.

5. **Chromium marks a candidate pair `nominated` while it is still
   `in-progress`.** Measured here: this e2e passed on its first run and failed on
   its second for exactly that reason. The suite now polls until the nominated
   pair reaches `succeeded`. That is a *sampling* fix, not a tolerance — the
   assertion is unchanged.

6. **The refusal wording of five diagnostics changed**, and the old one is now
   wrong rather than merely terse. "no live exchange — run quorum.offer or
   quorum.join first" was accurate while the mesh was the only connectable
   thing; it became a false instruction the moment `peer.offer` could produce a
   connection those ops can read. They say "no live connection — open one with
   peer.offer / peer.answer, or a mesh with quorum.offer / quorum.join".

7. **`SDP_TRANSPORT_CLOSED` is gone, replaced by `SDP_CARRY_NOTE`.** The old
   constant said the connection an SDP describes is already closed and that
   carrying it cannot complete a handshake. That was true and is now false. The
   test that asserted it has been inverted rather than deleted, so the claim is
   still pinned in one direction or the other.

8. **The pre-existing session-level buttons are still under the 24px target
   floor** (`px-2 py-1 text-[10px]`, ~22px). Recorded rather than swept into
   this change: they belong to a widget this work was not asked to touch, and a
   blanket restyle is how a status doc ends up claiming more than was verified.
   The *new* controls carry the floor in `.link-action`.

9. **`peer.*` has no trickle ICE and no glare handling, deliberately.**
   `peer.offer` waits for gathering and ships a complete offer because a human
   carries it; trickle needs a signalling channel, and if you have one you want
   `quorum.*`. Perfect negotiation resolves *simultaneous* offers on a
   persistent channel, and hand-carrying is turn-taking by construction — the
   polite/impolite rule stays in `QuorumSession`, where it is exercised.

10. **One unexplained e2e failure was observed once and did not reproduce.** A
    single run reported `1 failed | 43 passed` without the failing test being
    captured; ten subsequent runs (six plain, four verbose) were clean. The most
    likely cause is that run racing a `dist/` rebuild from the command before
    it, since the harness resolves content-hashed chunk names at page load. Not
    proven, and recorded rather than dismissed.

---

## Not implemented — remaining scope

- ~~**Unit 2: `QuorumSession` drives the manager.**~~ **Built.** The sequencing
  this entry prescribed is what happened: the registry landed first, held the
  mesh's links, and negotiation was lifted afterwards with the transcript
  binding as the explicit acceptance criterion. The driver is
  `src/lib/webrtc/peer-link.js`; `lib/quorum/` drives no WebRTC built-in and
  `src/test/quorum-layering.test.js` holds that.

  The acceptance criterion needed two halves rather than one, which is the part
  worth carrying forward. `src/test/quorum-dtls-binding.test.js` meshes two real
  sessions over a fake transport and (a) a mailbox that rewrites one peer's
  fingerprint and re-seals it under that peer's *own* key must leave both ends
  unconfirmed, and (b) each peer's `localDtls` must equal the fingerprint its
  own connection minted. (a) alone is not enough: a driver that reports a
  constant fingerprint to both peers leaves them agreeing, so confirmation
  succeeds and every tamper assertion still passes. That mutation was run; only
  (b) caught it. The test was watched failing-when-tampered against the
  untouched code **before** the move, which is the whole reason the move was
  defensible.
- **A cell-level strip for `peer.wait`.** A cell paused inside `peer.wait` has
  no `SessionStrip` — that widget is wired to the quorum exchange only. The
  Connections tab answers "what is live"; nothing answers "what is *this cell*
  waiting on". Raised by the design critique (C6) and deferred: it needs a
  second state channel through `useNotebook`.
- **Link persistence across runs.** A link is a HANDLE. `basilisk_webrtc`
  IndexedDB (§30a/30b) remains unbuilt and this does not need it.
- **`peer.*` in the CLI.** `RTCPeerConnection` does not exist in Node.
- **`via` for quorum rows in the panel** still arrives through `quorum-ops`'
  own async enrichment rather than the registry. Both call
  `selectedCandidateType`, so the vocabulary agrees; consolidating the two
  call sites is tidy-up, not a fix.

---

## Verification bar used

`npx tsc --noEmit` — clean but for the pre-existing `src/lib/memory-safety.js`.
`npm run build` — clean. `npx vitest run` — **141 files / 2519 tests**, all
passing (was 140 / 2484). `npm run test:e2e` — **4 files, 44 passed / 18
skipped**; the 18 are `turn-relay.e2e.js`, which needs a Docker coturn and skips
cleanly without one, exactly as designed.

Green gates are not proof, and this work is the reason to keep saying so: the
op it replaces passed `tsc`, the full suite, and a test file named after it,
for its entire shipped life, while producing an offer that could not connect.
