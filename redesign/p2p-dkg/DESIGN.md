# Generic P2P mesh: authenticated multi-party sessions and distributed key generation

Research + design pass. Grounded in the specs and prior art linked at the
bottom, not from memory. Nothing here is implemented yet.

## The claim being tested

> Could Basilisk's WebRTC tooling be generic enough to serve as a rudimentary
> direct peer-to-peer distributed key generator, authenticated when
> participants use a published public key?

Short answer: **yes, and the shape of the problem fits unusually well** — but
one specific attack (RFC 8844 UKS) has to be designed against from the start,
not bolted on.

## 1. Why mesh is right here, when it usually isn't

The standard advice is that full mesh collapses past ~4–6 participants: each
peer sends and receives N−1 streams, so bandwidth and CPU scale linearly per
node and quadratically across the session.

**That limit is about media.** It is a bandwidth argument about continuous
audio/video streams. A DKG round trip is a few hundred bytes of commitments
and shares, exchanged a handful of times. The quadratic term is on message
*count*, not bandwidth, and N(N−1)/2 data channels at N=7 is 21 channels
carrying kilobytes total.

So the topology everyone avoids for video is the correct one here, because it
is also the only topology with **no server that sees the traffic** — which is
the entire point of running a DKG peer-to-peer. Realistic threshold
configurations (3-of-5, 5-of-7) sit comfortably inside mesh's practical range.

This should be stated in the UI: the Connections tab should show the mesh
degree and stop pretending arbitrary N is fine. A soft cap around 8 with an
honest explanation beats silent degradation.

## 2. Perfect negotiation is mandatory, not optional

With one peer connection, glare (both sides offering at once) is an edge case.
In a mesh where every peer connects to every other peer as members join in
arbitrary order, **glare is the normal case**.

The standard answer is the perfect-negotiation pattern: each side is either
*polite* or *impolite*. On collision the impolite peer ignores the incoming
offer; the polite peer rolls back its own (`setLocalDescription({type:
'rollback'})`) and accepts. Modern `setLocalDescription()` with no arguments
picks offer-or-answer from `signalingState` automatically.

**The mesh-specific part**: politeness must be assigned without coordination,
because there is no server to assign it. Compare the two peers' stable
identifiers and let the lexicographically lower one be polite. Every pair
agrees on the roles independently, with zero negotiation about who negotiates.

This belongs in the ops layer (`quorum-ops.js`), not per-op.

## 3. Authentication: signing the fingerprint, and the attack that breaks it

WebRTC already binds the DTLS handshake to signaling: the SDP carries
`a=fingerprint:sha-256 …`, the certificate presented in the handshake must
match it. Basilisk already surfaces exactly this via `rtc.certificate`.

So the authentication story writes itself from parts that already exist:

```
rtc.certificate | rtc.offer | gpg.sign | out @invite      # publish
in @invite | gpg.verify | quorum.join                           # verify, then connect
```

Sign the offer with your long-lived OpenPGP key. The peer fetches your public
key (`hkp.get`), verifies the signature, and now knows the `a=fingerprint` line
came from you. The DTLS channel then provably terminates at whoever holds that
certificate. No server is trusted at any point.

**The catch — RFC 8844.** This binding is *not* integrity-protected against
unknown key-share attacks. An attacker who can relay signaling can take your
signed offer and present it in a session you did not intend, so a victim
believes they are talking to you while actually talking to the attacker on a
different connection. The mitigation is that the identity assertion must be
bound to **every** fingerprint in the session description, not merely present
alongside one.

Concretely, for this design: **sign a transcript, not a fingerprint.** The
signed payload must cover the room identifier, the signer's identity, the full
set of fingerprints in that offer, and a nonce — so a signature lifted into
another session fails verification. Signing the bare SDP is the intuitive
implementation and it is the vulnerable one.

This is the single most important finding in this document.

## 4. The bootstrap problem is honest and unavoidable

WebRTC cannot connect two peers without some prior channel to exchange the
first offer/answer. There is no serverless escape from this; "serverless
WebRTC" always means "the signaling happened somewhere else".

Basilisk's existing answer is already the right one — a signed invite blob the
user moves out of band. What is missing is making the channel a first-class
choice rather than an implicit copy-paste: clipboard (op designed, unbuilt),
QR (`qr` exists) for phone-to-laptop, and a pasted blob for chat. STUN is still
needed for NAT traversal even with manual signaling; TURN only when both peers
are behind symmetric NAT, and the existing `stun.check` diagnostic already
tells you which case you are in.

Once one pair is connected, **the mesh can bootstrap itself**: existing members
relay introductions for newcomers over already-authenticated data channels, so
only the first join needs out-of-band signaling. That is the difference between
a demo and a usable tool, and it is a modest amount of work on top of what
exists.

## 5. DKG on top

The transport above is generic — it is an authenticated N-party message bus.
DKG is then one protocol running on it, and the toolkit shape already suits it:

- Each participant generates a secret and commitments locally (`genkey`,
  `random`, the existing SSS ops).
- Commitments are broadcast to all peers (`quorum.send`).
- Shares are delivered pairwise (per-peer channels — the mesh gives this for
  free, whereas an SFU would not).
- Each participant verifies received shares against commitments before
  accepting, then combines.

The important property: **no participant and no server ever holds the composed
private key.** That is precisely what Basilisk's SSS toolbox already models
locally; the mesh makes it multi-party.

Feldman VSS over the existing curve is the natural first target — verifiable,
well understood, and it reuses the commitment/verify shape already present.
Worth stating plainly in the UI that a rudimentary DKG is *not* a substitute
for an audited threshold-signature implementation.

## 6. How it fits the widgets that exist

| Piece | Exists | Change needed |
|---|---|---|
| `NetworkArtifact` candidate/pair/stats renderers | yes | none |
| `SessionStrip` incl. `failed` + ICE restart | yes | per-peer, not per-session |
| `rtc.certificate` | yes | feed the signed transcript, not raw SDP |
| `stun.check` reachability triage | yes | none |
| `quorum.offer` / `join` / `send` / `recv` | yes (2-party) | N-party; `recv` array output |
| Connections tray tab | **no** | the mesh manager — this is the centrepiece |
| Perfect negotiation | **no** | ops layer, politeness by identifier compare |
| Mesh self-bootstrap (relayed introductions) | **no** | new |
| Signed-transcript auth (RFC 8844-safe) | **no** | new, security-critical |
| DKG rounds | **no** | new protocol layer |
| `clipboard` / QR as signaling channels | partial | `qr` exists, clipboard designed only |

The Connections tab stops being a nice-to-have here. In a mesh it is the only
place that can answer "who is actually in this room, which links are up, and
which of them are authenticated" — three different questions the current
per-cell `SessionStrip` cannot express, because it assumes one session with one
peer.

## 7. Suggested order

1. **Connections tray tab** — per-peer rows, link state, auth state. Nothing
   below is debuggable without it.
2. **Perfect negotiation** in the ops layer. Unblocks N>2 entirely.
3. **N-party `quorum.*`** including `recv`'s array output (already the flagged
   highest-risk item in the WebRTC handoff).
4. **Signed-transcript authentication.** Do this before mesh bootstrap, since
   relayed introductions must ride on already-authenticated links.
5. **Mesh self-bootstrap.**
6. **DKG rounds** as an ordinary protocol on the finished bus.

Steps 1–3 are a working unauthenticated mesh. Step 4 makes it trustworthy.
Steps 5–6 are what make it pleasant and what make it a DKG.

## Sources

- [Perfect Negotiation — MDN](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Perfect_negotiation)
- [Perfect negotiation in WebRTC — Mozilla Advancing WebRTC](https://blog.mozilla.org/webrtc/perfect-negotiation-in-webrtc/)
- [RFC 8844 — Unknown Key-Share Attacks on Uses of TLS with SDP](https://www.rfc-editor.org/rfc/rfc8844.html)
- [RFC 5763 — Framework for establishing a SRTP Security Context with DTLS](https://github.com/leaysgur/webrtc-rfcs/blob/master/markdown/rfc5763.md)
- [WebRTC Security Architecture (RTCWEB WG)](https://rtcweb-wg.github.io/security-arch/)
- [Multi-Party WebRTC Option 1: Mesh — WebRTC.ventures](https://webrtc.ventures/2018/06/multi-party-webrtc-option-1-mesh/)
- [WebRTC Mesh Architecture — WebRTC.ventures](https://webrtc.ventures/2021/06/webrtc-mesh-architecture/)
- [SnoW: Serverless n-Party calls over WebRTC (arXiv)](https://arxiv.org/pdf/2206.12762)
- [WebRTC Security: DTLS, SRTP, Fingerprints, Identity — Fora Soft](https://www.forasoft.com/learn/video-streaming/articles-streaming/webrtc-security-dtls-srtp)
