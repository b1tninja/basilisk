/**
 * Perfect negotiation — the glare rule, and nothing else.
 *
 * This is the MDN pattern, not a Basilisk invention, which is why it lives in
 * `lib/webrtc/` and is imported by the session layer rather than the other way
 * round. `QuorumSession` still calls it from inside its own
 * `onnegotiationneeded`/`ondescription` handlers; moving a pure function does
 * not move *when* those handlers run, which is the property §59b insists on
 * (see the note in `lib/quorum/session.js`).
 *
 * @module lib/webrtc/negotiation
 */

/**
 * Perfect-negotiation collision rule (MDN pattern), pure so it is testable
 * without an RTCPeerConnection. A collision is an incoming offer while we are
 * mid-offer ourselves or otherwise not stable; the impolite peer ignores it,
 * the polite peer accepts (its own offer rolls back implicitly inside
 * `setRemoteDescription`).
 *
 * Politeness is assigned without coordination — each pair compares stable
 * identifiers and the lexicographically lower fingerprint is polite. Both
 * sides compute the same answer independently, which is the property that
 * makes this work with no negotiation about who negotiates.
 *
 * @param {{ polite: boolean, makingOffer: boolean, signalingState: string }} x
 * @returns {"accept"|"ignore"}
 */
export function offerCollisionAction({ polite, makingOffer, signalingState }) {
  const collision = makingOffer || signalingState !== "stable";
  if (!collision) return "accept";
  return polite ? "accept" : "ignore";
}
