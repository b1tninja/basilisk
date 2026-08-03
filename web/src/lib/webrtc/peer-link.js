/**
 * The peer-connection driver — constructing an `RTCPeerConnection`, running
 * negotiation on it, and taking it down again — behind a **link**: a handle
 * whose owner never sees the connection inside it.
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
 * ## Why a handle and not a connection
 *
 * The first extraction moved the driver out and then handed the connection
 * straight back: `openPeerLink` returned a link and the session immediately
 * unwrapped it to keep `pc`. Nine `.pc` reads later the session was still
 * calling `signalingState`, `restartIce` and `close` on a built-in — the
 * transport with two helpers factored out, not a layer above it.
 *
 * So a `PeerLink` is the whole vocabulary its owner gets: answer an offer,
 * apply an answer, add a candidate, open a channel, ask whether traffic is
 * flowing, restart, close. `pc` and `channel` remain public *fields* because
 * the link is itself what `link-registry.js` registers as a holder, and the
 * diagnostics in `lib/toolkit/` read raw `getStats()` off the inventory — but
 * nothing in `lib/quorum/` may touch them, and `src/test/quorum-layering.test.js`
 * fails the build if it does.
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

import { selectedCandidateType } from "./candidates.js";
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
 * One managed peer connection, and the only vocabulary its owner has for it.
 *
 * Also a `LinkHolder` (see `link-registry.js`): `pc` and `channel` are fields
 * rather than accessors so the inventory can read the current pair through the
 * link and null them out when it closes one.
 */
export class PeerLink {
  /**
   * Nothing fires before the constructor returns — every handler runs off a
   * task or a remote description — so an owner can safely register the link
   * wherever it keeps its inventory before opening a channel on it.
   *
   * @param {PeerLinkHandlers} handlers
   */
  constructor({
    iceServers,
    onIceCandidate,
    onLocalOffer,
    onMakingOffer,
    onConnectionState,
    onDataChannel,
    onError,
  }) {
    /**
     * The transport. Read by `link-registry.js` (which holds this object) and
     * by the diagnostics that call `getStats()`; never by `lib/quorum/`.
     * @type {RTCPeerConnection|null}
     */
    this.pc = new RTCPeerConnection({ iceServers });
    /**
     * The channel currently carrying traffic — whichever end made it. Assigned
     * here rather than by the owner so the inventory sees it the moment it
     * exists, including the one `ondatachannel` brings in on a renegotiation.
     * @type {RTCDataChannel|null}
     */
    this.channel = null;
    /** @type {(channel: RTCDataChannel) => void} */
    this._announceChannel = onDataChannel;

    const pc = this.pc;

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
    pc.ondatachannel = (ev) => this._adopt(ev.channel);
  }

  /**
   * @param {RTCDataChannel} channel
   * @returns {RTCDataChannel}
   */
  _adopt(channel) {
    this.channel = channel;
    this._announceChannel(channel);
    return channel;
  }

  /**
   * Create the channel this end offers. Creating it is what starts negotiation.
   * @param {string} [label]
   * @returns {RTCDataChannel}
   */
  openDataChannel(label = "data") {
    const pc = this._live("openDataChannel");
    // The offer itself rides onnegotiationneeded, which this trips.
    return this._adopt(pc.createDataChannel(label, { ordered: true }));
  }

  /**
   * Apply a remote offer and produce the answer, unless the glare rule says to
   * drop it.
   *
   * Returns `null` when the offer is ignored — the impolite peer's own offer is
   * in flight and will win. Otherwise the answer SDP and the fingerprint the
   * local description just committed to, read together in one expression.
   *
   * @param {{ sdp: string, polite: boolean, makingOffer: boolean }} incoming
   * @returns {Promise<LocalDescriptionFacts|null>}
   */
  async answerRemoteOffer({ sdp, polite, makingOffer }) {
    const pc = this._live("answerRemoteOffer");
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
   * @param {string} sdp
   * @returns {Promise<boolean>} false when the answer is stale by construction —
   *   it answers an offer we rolled back, and arrives in a state that cannot
   *   take it, so it is dropped rather than surfaced as an error. Also false on
   *   a link that has been torn down.
   */
  async applyRemoteAnswer(sdp) {
    const pc = this.pc;
    if (!pc || pc.signalingState !== "have-local-offer") return false;
    await pc.setRemoteDescription({ type: "answer", sdp });
    return true;
  }

  /**
   * @param {RTCIceCandidateInit} candidate
   * @returns {Promise<boolean>} false when there is no transport to add it to.
   */
  async addRemoteCandidate(candidate) {
    const pc = this.pc;
    if (!pc) return false;
    await pc.addIceCandidate(candidate);
    return true;
  }

  /**
   * Whether this link is carrying traffic right now.
   *
   * A data channel still reads `open` while its connection is failing, which is
   * why liveness is asked of the link rather than the channel.
   *
   * @returns {boolean}
   */
  isLive() {
    return this.pc?.connectionState === "connected";
  }

  /**
   * Whether the transport is gone — closed here, or closed out from under this
   * link by the inventory (`closeLink` nulls its holder's fields). The owner
   * asks so it knows whether the peer is re-connectable; it is the question
   * `peer.pc === null` used to answer by reaching in.
   *
   * @returns {boolean}
   */
  isTornDown() {
    return !this.pc;
  }

  /**
   * Re-run ICE in place — the connection keeps its identity and its channel.
   * @returns {boolean} whether a restart was issued (false on an engine without
   *   `restartIce`, or a link already torn down).
   */
  restartIce() {
    const pc = this.pc;
    if (typeof pc?.restartIce !== "function") return false;
    pc.restartIce();
    return true;
  }

  /**
   * Which ICE candidate type this link actually selected, best-effort.
   * @returns {Promise<string>} "host"/"srflx"/"prflx"/"relay", or "".
   */
  async selectedCandidateType() {
    return selectedCandidateType(this.pc);
  }

  /** Close the channel and the connection, tolerating one already gone. */
  close() {
    try {
      this.channel?.close();
    } catch (_) {
      /* already closed */
    }
    try {
      this.pc?.close();
    } catch (_) {
      /* already closed, or never opened */
    }
    this.channel = null;
    this.pc = null;
  }

  /**
   * @param {string} op
   * @returns {RTCPeerConnection}
   */
  _live(op) {
    const pc = this.pc;
    if (!pc) throw new Error(`peer link: ${op} on a connection that is gone`);
    return pc;
  }
}

/**
 * Construct a peer connection with negotiation wired up.
 *
 * @param {PeerLinkHandlers} handlers
 * @returns {PeerLink}
 */
export function openPeerLink(handlers) {
  return new PeerLink(handlers);
}
