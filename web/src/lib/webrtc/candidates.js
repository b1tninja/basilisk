/**
 * Reading candidate facts back off a live `RTCPeerConnection`.
 *
 * `getStats()` is a WebRTC interface and the shapes it returns differ per
 * engine; knowing that Firefox omits the `transport` stat that links the
 * selected pair is a fact about browsers, not about a quorum roster. It lived
 * in `lib/quorum/roster.js` because the roster was its first caller — then
 * `peer.*` became its second, which left the peer-connection manager importing
 * the mesh's projection module to answer a question about ICE.
 *
 * @module lib/webrtc/candidates
 */

/**
 * Read which ICE candidate type a live connection actually selected.
 *
 * Best-effort by design: stats shapes differ per engine, and a peer that
 * cannot answer just stays without a `via` badge. Reported as the local
 * candidate's type (`host`/`srflx`/`prflx`/`relay`) — the vocabulary the rest
 * of the toolkit (stun.check, NetworkArtifact) already uses.
 *
 * @param {RTCPeerConnection | null | undefined} pc
 * @returns {Promise<string>} candidate type, or "" when undeterminable
 */
export async function selectedCandidateType(pc) {
  if (!pc || typeof pc.getStats !== "function") return "";
  let report;
  try {
    report = await pc.getStats();
  } catch {
    return "";
  }
  /** @type {Map<string, any>} */
  const byId = new Map();
  report.forEach((s) => byId.set(s.id, s));
  let pair = null;
  for (const s of byId.values()) {
    if (s.type === "transport" && s.selectedCandidatePairId) {
      pair = byId.get(s.selectedCandidatePairId);
      break;
    }
  }
  if (!pair) {
    // Firefox has no `transport` stat linking the pair; fall back to the
    // `selected`/`nominated` flags on the pairs themselves.
    for (const s of byId.values()) {
      if (s.type !== "candidate-pair") continue;
      if (s.selected || (s.nominated && s.state === "succeeded")) {
        pair = s;
        break;
      }
    }
  }
  const local = pair ? byId.get(pair.localCandidateId) : null;
  return String(local?.candidateType || "");
}
