/**
 * The peer-connection driver — constructing an `RTCPeerConnection`, running
 * negotiation on it, and taking it down again.
 *
 * Everything here is the browser's API and nothing here is Basilisk's:
 * `new RTCPeerConnection`, `onnegotiationneeded`, `setLocalDescription`,
 * `setRemoteDescription`, `addIceCandidate`, `createDataChannel`,
 * `ondatachannel`. It lived inside `QuorumSession` until the mesh was made a
 * layer *on top of* WebRTC rather than a shelf containing it; `lib/quorum/` now
 * holds identity, the signed invite, the relay, the room, the roster, key
 * derivation, key confirmation and the DKG session — the protocol — and calls
 * this for the transport.
 *
 * ## The fingerprint contract, which is the whole reason this was hard
 *
 * A quorum session key is derived over a transcript that includes **both** DTLS
 * certificate fingerprints. The local one does not exist until a local
 * description does, so it is minted here, inside negotiation — which is exactly
 * what made moving negotiation risky: get the timing wrong and key confirmation
 * *succeeds* over a transcript that no longer commits to the transport, with
 * every test still green.
 *
 * So the contract is explicit rather than incidental. Every function that
 * produces a local description returns `{ sdp, dtlsFingerprint }` **together**,
 * read from that same description in the same expression, and hands both to the
 * caller before the caller can send anything. A caller cannot signal an SDP
 * without the fingerprint that belongs to it, and cannot obtain the fingerprint
 * out of order, because there is no other way to get either.
 *
 * `src/test/quorum-dtls-binding.test.js` is the guard: two real sessions mesh
 * over a fake transport, the transcript is asserted against the fingerprints
 * the two transports actually minted, and a signalling relay that rewrites one
 * fingerprint — re-sealing under the original signer's own key, so the PGP
 * layer sees nothing wrong — must leave both ends unconfirmed. Removing the
 * binding turns that test green; that is what it is for.
 *
 * @module lib/webrtc/peer-link
 */

import { offerCollisionAction } from "./negotiation.js";
import { extractDtlsFingerprint } from "./sdp.js";

/**
 * A local description and the certificate fingerprint it committed to.
 * @typedef {object} LocalDescriptionFacts
 * @property {string} sdp
 * @property {string} dtlsFingerprint
 */

/**
 * @typedef {object} PeerLinkHandlers
 * @property {RTCIceServer[]} iceServers
 * @property {(candidate: RTCIceCandidateInit) => void} onIceCandidate
 *   One gathered candidate. End-of-gathering (`null`) is swallowed here.
 * @property {(local: LocalDescriptionFacts) => Promise<void>|void} onLocalOffer
 *   A fresh local offer, with its fingerprint. Awaited inside the negotiation
 *   handler, so `onMakingOffer(false)` does not run until it resolves — the
 *   glare window stays open for exactly as long as the offer is in flight.
 * @property {(making: boolean) => void} onMakingOffer
 * @property {(state: string) => void} onConnectionState
 * @property {(channel: RTCDataChannel) => void} onDataChannel
 *   Both directions: the channel this end creates and the one the far end does.
 * @property {(err: Error) => void} onError
 */

/**
 * @typedef {object} PeerLink
 * @property {RTCPeerConnection} pc
 * @property {(label?: string) => RTCDataChannel} openDataChannel
 */

/**
 * Construct a peer connection with negotiation wired up.
 *
 * Nothing fires before this returns — every handler here runs off a task or a
 * remote description — so a caller can safely register the connection wherever
 * it keeps its inventory before opening a channel on it.
 *
 * @param {PeerLinkHandlers} handlers
 * @returns {PeerLink}
 */
export function openPeerLink({
  iceServers,
  onIceCandidate,
  onLocalOffer,
  onMakingOffer,
  onConnectionState,
  onDataChannel,
  onError,
}) {
  const pc = new RTCPeerConnection({ iceServers });

  pc.onicecandidate = (ev) => {
    if (!ev.candidate) return;
    onIceCandidate(ev.candidate.toJSON());
  };

  // One offer path for both the first negotiation and every renegotiation:
  // creating a data channel trips this, and so does restartIce() (which
  // previously went nowhere — no handler meant no new offer, so "Restart
  // connection" only ever cleared flags). No-arg setLocalDescription picks
  // offer-or-answer from signalingState itself.
  pc.onnegotiationneeded = async () => {
    try {
      onMakingOffer(true);
      await pc.setLocalDescription();
      const sdp = pc.localDescription?.sdp || "";
      await onLocalOffer({ sdp, dtlsFingerprint: extractDtlsFingerprint(sdp) });
    } catch (err) {
      onError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      onMakingOffer(false);
    }
  };

  pc.onconnectionstatechange = () => onConnectionState(pc.connectionState);
  pc.ondatachannel = (ev) => onDataChannel(ev.channel);

  return {
    pc,
    openDataChannel(label = "data") {
      // The offer itself rides onnegotiationneeded, which this trips.
      const channel = pc.createDataChannel(label, { ordered: true });
      onDataChannel(channel);
      return channel;
    },
  };
}

/**
 * Apply a remote offer and produce the answer, unless the glare rule says to
 * drop it.
 *
 * Returns `null` when the offer is ignored — the impolite peer's own offer is
 * in flight and will win. Otherwise the answer SDP and the fingerprint the
 * local description just committed to, read together.
 *
 * @param {RTCPeerConnection} pc
 * @param {{ sdp: string, polite: boolean, makingOffer: boolean }} incoming
 * @returns {Promise<LocalDescriptionFacts|null>}
 */
export async function answerRemoteOffer(pc, { sdp, polite, makingOffer }) {
  // Perfect negotiation: on glare the impolite peer drops the incoming offer
  // (its own is in flight and will win); the polite peer accepts —
  // setRemoteDescription rolls its pending local offer back implicitly.
  const action = offerCollisionAction({
    polite,
    makingOffer,
    signalingState: pc.signalingState,
  });
  if (action === "ignore") return null;
  await pc.setRemoteDescription({ type: "offer", sdp });
  await pc.setLocalDescription();
  const local = pc.localDescription?.sdp || "";
  return { sdp: local, dtlsFingerprint: extractDtlsFingerprint(local) };
}

/**
 * Apply a remote answer.
 *
 * @param {RTCPeerConnection} pc
 * @param {string} sdp
 * @returns {Promise<boolean>} false when the answer is stale by construction —
 *   it answers an offer we rolled back, and arrives in a state that cannot take
 *   it, so it is dropped rather than surfaced as an error.
 */
export async function applyRemoteAnswer(pc, sdp) {
  if (pc.signalingState !== "have-local-offer") return false;
  await pc.setRemoteDescription({ type: "answer", sdp });
  return true;
}

/**
 * @param {RTCPeerConnection} pc
 * @param {RTCIceCandidateInit} candidate
 * @returns {Promise<void>}
 */
export async function addRemoteCandidate(pc, candidate) {
  await pc.addIceCandidate(candidate);
}

/**
 * Whether a connection is carrying traffic right now.
 *
 * A data channel still reads `open` while its connection is failing, which is
 * why liveness is asked of the connection rather than the channel.
 *
 * @param {RTCPeerConnection|null|undefined} pc
 * @returns {boolean}
 */
export function isPeerLinkLive(pc) {
  return pc?.connectionState === "connected";
}

/**
 * Close a connection, tolerating one that is already gone.
 * @param {RTCPeerConnection|null|undefined} pc
 */
export function closePeerLink(pc) {
  try {
    pc?.close();
  } catch (_) {
    /* already closed, or never opened */
  }
}
