# Brief: peer connections as a first-class managed thing

The capability request, as given:

> Focus on the p2p tools / connection management features and designs … we need
> RTCPeerConnection management features. Quorum should be able to communicate
> with connected peers, but not have to worry about how that is done. Just
> provide a way for users to manage peers. We should still offer the underlying
> raw capabilities / expose WebRTC functionality, but users shouldn't be forced
> to use that to setup a connection. Quorum can then reuse whatever session
> management capabilities.

## What the brief is right about

- **A connection manager layer is the missing piece.** There are two layers
  today (`rtc.*` raw, `quorum.*` mesh) and no middle. The middle is where
  "connect me to that browser" lives.
- **The raw layer must survive.** `rtc.gather`, `rtc.certificate`, `rtc.check`,
  `rtc.state`, `rtc.stats`, `rtc.quality` are how a failure gets explained, and
  nothing here touches them except to widen what they can see.
- **Perfect negotiation is the canonical pattern**, and MDN's payoff sentence —
  "the same code is used for both the caller and the callee" — is exactly the
  "quorum shouldn't have to worry about how" the brief asks for.

## Where the brief is corrected

**"Lift the machinery out of `quorum/rtc.js`" is the right instinct and the
wrong first move.** The perfect-negotiation wiring there is real and proven, but
it is entangled with `derivePairwiseSessionKey`'s transcript binding, which
includes both DTLS fingerprints. Lifting negotiation means moving the moment the
local fingerprint becomes known, and getting that subtly wrong produces a key
confirmation that succeeds on a transcript no longer bound to the transport —
with every existing test still green. Argued in §59b; the registry is the seam
that lift would be built on, and it is what unit 1 lands.

**Perfect negotiation is also not what the hand-carried flow needs.** Glare is
simultaneous offers on a persistent signalling channel. Carrying a blob between
two browsers by hand is turn-taking by construction. The polite/impolite rule
stays in `QuorumSession`, where it is used; `peer.*` does not get a copy it
would never exercise (§59c).

## The defect this generalises

`execCreateOffer` closes its own `RTCPeerConnection` before returning, so
`sdp-hand-carried` and `sdp-to-clipboard` describe a flow that cannot complete.
The identified fix — "a live-offer registry plus an `rtc.accept` op" — was
deferred as an op-surface design decision. It is the same decision as the
connection manager, and §54b argues that the narrow version of it is not
implementable on its own: the moment a connection outlives the op that made it,
something has to hold it.
