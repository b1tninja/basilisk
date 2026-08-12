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

/**
 * @typedef {object} ConnectionPeerRow
 * @property {string} id            the peer's label — a legal `@peer` name,
 *   stable across machines, and what a cell header addresses. Not a shortened
 *   fingerprint: see `peerLabels`.
 * @property {string} display       `AABBCCDD…EEFF` — which key the label is
 *   attached to, for a reader. Never an identity: nothing addresses by it.
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

/** What a positional peer label is called before its number. */
const PEER_LABEL_PREFIX = "peer";

/**
 * Peer label for every member of a room, by fingerprint.
 *
 * **Why a label is not an abbreviated fingerprint.** A row's `id` is written
 * into notebook source as `@<id>` and is the key of `planRun`'s roster, so it
 * has to satisfy the peer-label grammar — a letter followed by letters,
 * digits, `_` or `-`. `shortFpr`'s output satisfies none of it: the ellipsis
 * is not an identifier character. Removing the ellipsis would not rescue it
 * either, because `peerLooksLikeFingerprint` refuses hex-only labels on
 * purpose — a fingerprint in shared recipe text hands over the audience, and
 * `room.js` derives the room from a digest of exactly that audience.
 *
 * **Why the audience orders them.** The label has to mean the same person in
 * every browser, because the notebook it is written into round-trips through
 * text and is digested into manifests. Arrival order cannot do that — it
 * differs per machine and shifts as people join. The audience can: the room is
 * a one-way digest of it, so it is fixed for the session and identical
 * everywhere, and `canonicalAudience` sorts it. Position in that list is
 * therefore stable, agreed, and reveals only how many were invited — which the
 * invite already says.
 *
 * A fingerprint outside the audience is not a room member and cannot be
 * ordered by it; those are appended in their own sorted order so the label is
 * still legal and still deterministic for a given set.
 *
 * @param {string[]} [audienceFprs]  every member, present or not
 * @param {Iterable<string>} [presentFprs]
 * @returns {Map<string, string>} fingerprint → label
 */
export function peerLabels(audienceFprs, presentFprs = []) {
  const order = canonicalAudience(audienceFprs || []);
  const seen = new Set(order);
  const extra = [...presentFprs].map((f) => String(f || "").toUpperCase()).sort();
  for (const fpr of extra) {
    if (fpr && !seen.has(fpr)) {
      seen.add(fpr);
      order.push(fpr);
    }
  }
  const labels = new Map();
  order.forEach((fpr, i) => labels.set(fpr, `${PEER_LABEL_PREFIX}${i + 1}`));
  return labels;
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
 * @param {string[]} [audienceFprs] every member the room was derived from,
 *   present or not. What orders the labels — see `peerLabels`.
 * @returns {ConnectionPeerRow[]}
 */
export function projectRosterPeers(peersByFpr, viaByFpr, audienceFprs) {
  const rows = [];
  const labels = peerLabels(audienceFprs, [...peersByFpr].map(([fpr]) => fpr));
  for (const [fpr, peer] of peersByFpr) {
    const via = viaByFpr?.get(fpr);
    rows.push({
      id: labels.get(String(fpr || "").toUpperCase()) || "",
      display: shortFpr(fpr),
      fingerprint: fpr,
      state: STATE_BY_STATUS[peer?.status] || "new",
      authenticated: !!(peer?.pgpVerified && peer?.kcVerified),
      ...(via ? { via } : {}),
    });
  }
  return rows;
}

