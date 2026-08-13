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
 * @property {string} id            the peer's label — a legal `@peer` name,
 *   stable across machines, and what a cell header addresses. Not a shortened
 *   fingerprint: see `peerLabels`.
 * @property {string} fingerprint   the whole fingerprint, for addressing and
 *   for the `<Fingerprint>` the panels render beside the label
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

/** What a positional peer label is called before its number. */
const PEER_LABEL_PREFIX = "peer";

/**
 * Peer label for every member of a room, by fingerprint.
 *
 * **Why a label is not an abbreviated fingerprint.** A row's `id` is written
 * into notebook source as `@<id>` and is the key of `planRun`'s roster, so it
 * has to satisfy the peer-label grammar — a letter followed by letters,
 * digits, `_` or `-`. The `AABBCCDD…EEFF` this module used to produce satisfies
 * none of it: the ellipsis is not an identifier character. Removing the
 * ellipsis would not rescue it either, because `peerLooksLikeFingerprint`
 * refuses hex-only labels on purpose — a fingerprint in shared recipe text
 * hands over the audience, and `room.js` derives the room from a digest of
 * exactly that audience.
 *
 * The label is now the *only* thing a dense roster row prints. The elided form
 * that used to sit beside it is gone from the product entirely (see
 * `components/ui/fingerprint.tsx`), and this label is what `variant="compact"`
 * shows in its place — a name the row already had, carrying no bits of the key.
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
 * The room's roster — every member bound to their label — and which of those
 * labels this browser occupies.
 *
 * **Why this is here and not in the shell.** A label means a position in the
 * audience and nothing else, so the only thing that can say which label is
 * *yours* is the function that hands the labels out. The shell used to answer
 * it by searching the peer rows for its own fingerprint, and `session.peers`
 * is the audience *minus* self — deliberately, `NotebookSession` refuses to be
 * its own peer — so the search could not succeed and `me` was always `""`.
 * Every cell then planned as somebody else's, `planRun` refused this browser's
 * own label as a peer "no one in this room answers to", and the placed-run gate
 * was never built at all.
 *
 * Answering it from `peerLabels` instead means the two cannot disagree: the map
 * that names peer1 and peer2 is the map that says which one you are, so there
 * is no second derivation to drift. Self is still not a peer anywhere — this
 * adds nothing to `session.peers` and projects no row for it.
 *
 * **The roster is the audience, not who has arrived.** Both ends must reach the
 * same `{label: fingerprint}` binding: `buildRunManifest` digests it into
 * `peersSha`, and two peers committing to different bindings is an offer the
 * other side cannot accept. The audience is fixed for the session and identical
 * everywhere (the room id is a digest of it); who has meshed so far is neither.
 *
 * A fingerprint outside the audience cannot be positioned by it, so a `selfFpr`
 * that is not a member returns `""` — the honest answer, and the one that
 * leaves `planRun`'s `who-am-i` question standing rather than inventing a
 * position for a browser the room does not contain.
 *
 * @param {string[]} [audienceFprs]  every member, present or not
 * @param {Iterable<string>} [presentFprs]  who has arrived — passed on to
 *   `peerLabels` so this roster and the panel rows are labelled from one call
 *   with one set of inputs
 * @param {string} [selfFpr]  this browser's own fingerprint
 * @returns {{ roster: Record<string, string>, me: string }}
 */
export function roomRoster(audienceFprs, presentFprs = [], selfFpr = "") {
  const labels = peerLabels(audienceFprs, presentFprs);
  /** @type {Record<string, string>} */
  const roster = {};
  for (const [fpr, label] of labels) roster[label] = fpr;
  return { roster, me: labels.get(normalizeFingerprintInput(selfFpr)) || "" };
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
      fingerprint: fpr,
      state: STATE_BY_STATUS[peer?.status] || "new",
      authenticated: !!(peer?.pgpVerified && peer?.kcVerified),
      ...(via ? { via } : {}),
    });
  }
  return rows;
}

