/**
 * Roster projection — QuorumSession peer state → the UI's ConnectionPeer rows.
 *
 * Pure on purpose: quorum-ops feeds it live `QuorumPeerState`s, tests feed it
 * literals, and neither side drags in WebRTC or OpenPGP to do so. This is the
 * single place the transport's vocabulary ("unknown", kcVerified, …) is
 * translated into the panel's ("new", authenticated, …); if the two drift,
 * fix it here rather than teaching a widget transport terms.
 * @module lib/quorum/roster
 */

/**
 * @typedef {object} ConnectionPeerRow
 * @property {string} id            short label for the row
 * @property {string} fingerprint   full fingerprint, for tooltips/addressing
 * @property {"new"|"connecting"|"connected"|"disconnected"|"failed"|"closed"} state
 * @property {boolean} authenticated
 * @property {string} [via]         ICE candidate type actually selected
 */

/** Transport peer status → panel row state. */
const STATE_BY_STATUS = {
  unknown: "new",
  verified: "new", // signalling seen, no transport yet — still "new" to the mesh
  connecting: "connecting",
  connected: "connected",
  failed: "failed",
};

/**
 * @param {string} fpr
 * @returns {string} `AABBCCDD…EEFF` — matches how fingerprints are shortened
 *   elsewhere (rtc.js error messages, SessionStrip).
 */
export function shortFpr(fpr) {
  const f = String(fpr || "").toUpperCase();
  return f.length > 12 ? `${f.slice(0, 8)}…${f.slice(-4)}` : f;
}

/**
 * Project the session's peer map into panel rows.
 *
 * Connectivity and authentication are carried separately on purpose — a peer
 * can be fully connected and completely unverified. `authenticated` demands
 * both proofs: the PGP-signed signalling envelope (who they claim to be) and
 * the transcript-bound key confirmation (that this channel is theirs).
 *
 * @param {Iterable<[string, {
 *   status: string,
 *   pgpVerified: boolean,
 *   kcVerified: boolean,
 * }]>} peersByFpr
 * @param {Map<string, string>} [viaByFpr] cached ICE candidate types, filled
 *   asynchronously as stats resolve — absent entries simply omit `via`
 * @returns {ConnectionPeerRow[]}
 */
export function projectRosterPeers(peersByFpr, viaByFpr) {
  const rows = [];
  for (const [fpr, peer] of peersByFpr) {
    const via = viaByFpr?.get(fpr);
    rows.push({
      id: shortFpr(fpr),
      fingerprint: fpr,
      state: STATE_BY_STATUS[peer?.status] || "new",
      authenticated: !!(peer?.pgpVerified && peer?.kcVerified),
      ...(via ? { via } : {}),
    });
  }
  return rows;
}

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
