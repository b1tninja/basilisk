/**
 * Roster projection — NotebookSession peer state → the UI's ConnectionPeer rows.
 *
 * Pure on purpose: quorum-ops feeds it live `NotebookPeerState`s, tests feed it
 * literals, and neither side drags in WebRTC or OpenPGP to do so. This is the
 * single place the transport's vocabulary ("unknown", kcVerified, …) is
 * translated into the panel's ("new", authenticated, …); if the two drift,
 * fix it here rather than teaching a widget transport terms.
 *
 * `selectedCandidateType` used to live here because the roster was its first
 * caller. It reads `RTCPeerConnection.getStats()` and knows which engines omit
 * the `transport` stat, which is a fact about browsers rather than about a
 * notebook roster — and its second caller was `peer.*`, so answering an ICE
 * question meant importing the mesh's projection module. It is
 * `lib/webrtc/candidates.js` now.
 *
 * @module lib/notebook/roster
 */

import { canonicalAudience } from "./room.js";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";

/**
 * @typedef {object} ConnectionPeerRow
 * @property {string} id            the peer as a cell header addresses it — the
 *   whole fingerprint, upper case. Identical to `fingerprint`, and both are
 *   carried because they are two different questions that used to have two
 *   different answers: `id` is what the notebook says and `fingerprint` is what
 *   the key is. They agree by construction now, and a row is still free to have
 *   a key with no place in any notebook.
 * @property {string} fingerprint   the whole fingerprint
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
 * Every member of a room, present or not, in one canonical order.
 *
 * **This is what is left of `peerLabels`, and the difference is the whole
 * point.** It used to hand each member a *position* — `peer1`, `peer2`,
 * numbered over `canonicalAudience` — and that positional label was the root of
 * a class of defect this repo patched twice (`96dde48`, `4b3305d`) rather than
 * removed: adding or removing anybody renumbered everyone who sorted below
 * them, so a cell reading `@peer2` came to mean a different person with nothing
 * on screen moving. It also told a reader nothing. `@peer1` is not a name.
 *
 * A peer is now the key itself, so there is no numbering to drift and nothing
 * to hand out; what is left is the order, which several callers still want —
 * the panel rows, and anything that has to walk the room deterministically.
 *
 * A fingerprint outside the audience is not a room member, so it cannot be
 * ordered by the audience; those are appended in their own sorted order, which
 * keeps the whole list deterministic for a given set.
 *
 * @param {string[]} [audienceFprs]  every member, present or not
 * @param {Iterable<string>} [presentFprs]
 * @returns {string[]} upper-case fingerprints, audience first
 */
export function roomMembers(audienceFprs, presentFprs = []) {
  const order = canonicalAudience(audienceFprs || []);
  const seen = new Set(order);
  const extra = [...presentFprs].map((f) => String(f || "").toUpperCase()).sort();
  for (const fpr of extra) {
    if (fpr && !seen.has(fpr)) {
      seen.add(fpr);
      order.push(fpr);
    }
  }
  return order;
}

/**
 * The room's roster — every member bound to the name a cell header uses for
 * them — and which of those this browser is.
 *
 * **The roster is identity-mapped, and that is the change.** A peer *is* a
 * fingerprint, so `{ peer: fingerprint }` has the fingerprint on both sides.
 * That looks like a redundant object and is worth keeping as one, because it is
 * the shape `peersDigest` hashes into `peersSha` and the shape `planRun` binds
 * against — one object for "the thing planned against" and "the thing committed
 * to", which is the property `plan.js` argues for and which survives the
 * mapping becoming trivial.
 *
 * **The important consequence: `peersSha` now agrees by construction.** Two
 * browsers holding the same audience derive the same roster with nothing
 * carried between them, because there is no invented layer left to disagree
 * about. Every defect in this area — a draft numbered one way and a room
 * another, a rotation applied here and not there — was a disagreement about an
 * invention. There is nothing to invent.
 *
 * **Why this is here and not in the shell.** The shell used to answer "which
 * peer am I" by searching the peer rows for its own fingerprint, and
 * `session.peers` is the audience *minus* self — deliberately, `NotebookSession`
 * refuses to be its own peer — so the search could not succeed and `me` was
 * always `""`. Every cell then planned as somebody else's, `planRun` refused
 * this browser's own peer as one "no one in this room answers to", and the
 * placed-run gate was never built at all. Self is still not a peer anywhere:
 * this adds nothing to `session.peers` and projects no row for it.
 *
 * **The roster is the audience, not who has arrived.** Both ends must reach the
 * same binding, and the audience is fixed for the session and identical
 * everywhere (the room id is a digest of it); who has meshed so far is neither.
 *
 * A `selfFpr` outside the audience returns `""` — the honest answer, and the
 * one that leaves `planRun`'s `who-am-i` question standing rather than claiming
 * a place in a room that does not contain this browser.
 *
 * @param {string[]} [audienceFprs]  every member, present or not
 * @param {Iterable<string>} [presentFprs]  who has arrived
 * @param {string} [selfFpr]  this browser's own fingerprint
 * @returns {{ roster: Record<string, string>, me: string }}
 */
export function roomRoster(audienceFprs, presentFprs = [], selfFpr = "") {
  const members = roomMembers(audienceFprs, presentFprs);
  /** @type {Record<string, string>} */
  const roster = {};
  for (const fpr of members) roster[fpr] = fpr;
  const self = normalizeFingerprintInput(selfFpr);
  return { roster, me: self && roster[self] ? self : "" };
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
    const hex = String(fpr || "").toUpperCase();
    rows.push({
      id: hex,
      fingerprint: fpr,
      state: STATE_BY_STATUS[peer?.status] || "new",
      authenticated: !!(peer?.pgpVerified && peer?.kcVerified),
      ...(via ? { via } : {}),
    });
  }
  return rows;
}

