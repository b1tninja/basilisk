/**
 * Quorum full-mesh WebRTC data-channel session.
 *
 * Creators post a PGP-signed invite proving key possession; joiners mesh only
 * after verifying that invite. Pairwise session keys use per-peer ephemeral
 * ECDH with transcript-bound HKDF and key confirmation (data-channel PFS).
 * @module lib/quorum/rtc
 */

import {
  assertInvite,
  buildInvitePayload,
  combineDtlsFingerprints,
  derivePairwiseSessionKey,
  decryptSessionPayload,
  encryptSessionPayload,
  exportEcdhPublicJwk,
  extractDtlsFingerprint,
  fetchAudienceKeys,
  generateEcdhKeyPair,
  importEcdhPublicJwk,
  openSignalingEnvelope,
  randomNonceHex,
  requireSelfInAudience,
  sealSignalingEnvelope,
} from "./crypto.js";
import { canonicalAudience, isValidRoomId } from "./room.js";
import { deregisterLink, patchLink, registerLink } from "./link-registry.js";
import { classifyChannelFrame, createSeenSet, shouldRelay } from "./relay.js";
import { postSignaling, startSignalingPoll } from "./signaling.js";
import { zeroKeyMaterial } from "../pgp/memory.js";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";

export const DEFAULT_ICE_SERVERS = [
  { urls: "stun:stun.cloudflare.com:3478" },
  { urls: "stun:stun.l.google.com:19302" },
];

/**
 * @typedef {object} QuorumPeerState
 * @property {string} fingerprint
 * @property {"unknown"|"verified"|"connecting"|"connected"|"failed"} status
 * @property {boolean} pgpVerified
 * @property {boolean} kcVerified
 * @property {boolean} isInitiator
 * @property {RTCPeerConnection|null} pc
 * @property {RTCDataChannel|null} channel
 * @property {CryptoKey|null} sessionKey
 * @property {string|null} transcriptHash
 * @property {JsonWebKey|null} ecdhPublicJwk
 * @property {string|null} helloNonce
 * @property {string} localDtls
 * @property {string} remoteDtls
 * @property {CryptoKeyPair|null} localEcdh
 * @property {JsonWebKey|null} localEcdhJwk
 * @property {string|null} localHelloNonce
 * @property {boolean} kcSent
 * @property {boolean} polite      perfect negotiation: lower fingerprint yields on glare
 * @property {boolean} makingOffer
 * @property {boolean} ignoreOffer
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
  return !polite && collision ? "ignore" : "accept";
}

/**
 * @typedef {object} QuorumSessionOpts
 * @property {string} roomId
 * @property {string[]} audienceFprs
 * @property {import("openpgp").PrivateKey} privateKey
 * @property {string} myFingerprint
 * @property {"creator"|"joiner"} [role]
 * @property {RTCIceServer[]} [iceServers]
 * @property {(peers: Map<string, QuorumPeerState>) => void} [onRoster]
 * @property {(msg: { from: string, text: string, ts: number }) => void} [onChat]
 * @property {(status: string) => void} [onStatus]
 * @property {(err: Error) => void} [onError]
 */

export class QuorumSession {
  /** @param {QuorumSessionOpts} opts */
  constructor(opts) {
    this.roomId = String(opts.roomId || "")
      .trim()
      .toUpperCase();
    if (!isValidRoomId(this.roomId)) throw new Error("Invalid room id");
    this.myFpr = normalizeFingerprintInput(opts.myFingerprint);
    this.audienceFprs = requireSelfInAudience(this.myFpr, opts.audienceFprs);
    this.privateKey = opts.privateKey;
    this.role = opts.role === "joiner" ? "joiner" : "creator";
    this.iceServers = opts.iceServers?.length
      ? opts.iceServers
      : DEFAULT_ICE_SERVERS;
    this.onRoster = opts.onRoster;
    this.onChat = opts.onChat;
    this.onStatus = opts.onStatus;
    this.onError = opts.onError;

    /** @type {Map<string, QuorumPeerState>} */
    this.peers = new Map();
    /** @type {Map<string, import("openpgp").Key>} */
    this.audienceKeys = new Map();
    /** Invite-level ECDH (proof material in invite; not used for session KDF). */
    /** @type {CryptoKeyPair|null} */
    this._inviteEcdh = null;
    this.inviteNonce = "";
    this.initiatorFpr = this.role === "creator" ? this.myFpr : "";
    this.inviteVerified = this.role === "creator";
    this._meshing = this.role === "creator";
    this._since = 0;
    this._poll = null;
    this._seenSeqs = new Set();
    /** Relayed-envelope dedupe — one armored blob is handled once, ever. */
    this._envSeen = createSeenSet();
  }

  async start() {
    if (!this.audienceFprs.includes(this.myFpr)) {
      throw new Error("Local key must be in the room audience");
    }
    this.onStatus?.("Loading audience keys…");
    this.audienceKeys = await fetchAudienceKeys(this.audienceFprs);
    const missing = this.audienceFprs.filter((f) => !this.audienceKeys.has(f));
    if (missing.length) {
      throw new Error(
        `Missing public keys for: ${missing.map((f) => f.slice(0, 8)).join(", ")}`
      );
    }

    for (const fpr of this.audienceFprs) {
      if (fpr === this.myFpr) continue;
      this.peers.set(fpr, this._newPeer(fpr));
    }
    this._emitRoster();

    this._poll = startSignalingPoll({
      roomId: this.roomId,
      getSince: () => this._since,
      setSince: (s) => {
        this._since = s;
      },
      onMessage: (m) => this._onMailbox(m),
      onError: (err) => this.onError?.(err),
    });

    if (this.role === "creator") {
      this.onStatus?.("Publishing signed invite…");
      this._inviteEcdh = await generateEcdhKeyPair();
      const inviteJwk = await exportEcdhPublicJwk(this._inviteEcdh.publicKey);
      this.inviteNonce = randomNonceHex(32);
      const invite = buildInvitePayload({
        roomId: this.roomId,
        audience: this.audienceFprs,
        initiator: this.myFpr,
        ecdhPublicJwk: inviteJwk,
        nonce: this.inviteNonce,
      });
      await this._broadcast(invite);
      await this._beginMeshing();
    } else {
      this.onStatus?.("Waiting for signed invite…");
    }
  }

  stop() {
    this._poll?.stop();
    this._poll = null;
    this._inviteEcdh = null;
    this.inviteNonce = "";
    for (const fpr of this.peers.keys()) {
      // Out of the shared inventory before the transports go: the session owns
      // these connections and is tearing them down itself, so `deregisterLink`
      // (forget) rather than `closeLink` (close *and* forget) — closing twice is
      // harmless, but routing a mesh teardown through the registry would put the
      // registry in charge of a lifecycle it does not manage.
      deregisterLink(fpr);
    }
    for (const peer of this.peers.values()) {
      try {
        peer.channel?.close();
      } catch (_) {
        /* ignore */
      }
      try {
        peer.pc?.close();
      } catch (_) {
        /* ignore */
      }
      peer.channel = null;
      peer.pc = null;
      peer.sessionKey = null;
      peer.transcriptHash = null;
      peer.localEcdh = null;
      peer.localEcdhJwk = null;
      peer.ecdhPublicJwk = null;
      peer.kcVerified = false;
      peer.status = "failed";
    }
    // Wipe OpenPGP privateParams while the object is still reachable.
    try {
      zeroKeyMaterial(this.privateKey);
    } catch (_) {
      /* ignore */
    }
    this.privateKey = /** @type {any} */ (null);
    this._emitRoster();
    this.onStatus?.("Disconnected");
  }

  /**
   * @param {string} text
   */
  async sendChat(text) {
    return this._sendChatFiltered(text, "");
  }

  /**
   * Chat to a single verified peer, by fingerprint prefix.
   *
   * Distinct from `_sendTo`, which goes over the signalling relay for
   * handshake traffic — this is the encrypted data channel. Each peer already
   * gets its own `sessionKey` in the broadcast loop, so addressing one is a
   * filter rather than a different code path.
   *
   * @param {string} toFpr  fingerprint or unambiguous prefix
   * @param {string} text
   * @returns {Promise<number>} peers written to (never 0 — throws instead)
   */
  async sendChatTo(toFpr, text) {
    const n = await this._sendChatFiltered(text, toFpr);
    if (!n) {
      // Silence here would be dangerous: the author asked to tell one peer and
      // would have no signal that nobody heard it.
      throw new Error(
        `quorum.send to=${toFpr}: no verified peer with that fingerprint is connected`
      );
    }
    return n;
  }

  /**
   * @param {string} text
   * @param {string} toFpr  empty = every verified peer
   * @returns {Promise<number>} peers written to
   */
  async _sendChatFiltered(text, toFpr) {
    const body = JSON.stringify({
      kind: "chat",
      text: String(text || ""),
      ts: Date.now(),
      from: this.myFpr,
    });
    const want = String(toFpr || "").replace(/\s+/g, "").toUpperCase();
    let sent = 0;
    // The map is keyed by fingerprint; the peer record itself carries no copy
    // of it, so the key is the only place to match on.
    for (const [fpr, peer] of this.peers) {
      if (
        !peer.channel ||
        peer.channel.readyState !== "open" ||
        !peer.sessionKey ||
        !peer.kcVerified
      ) {
        continue;
      }
      if (want && !String(fpr || "").toUpperCase().startsWith(want)) continue;
      const blob = await encryptSessionPayload(peer.sessionKey, body);
      peer.channel.send(JSON.stringify({ v: 1, blob }));
      sent += 1;
    }
    return sent;
  }

  /** @param {{ seq: number, payload: string }} msg */
  async _onMailbox(msg) {
    if (this._seenSeqs.has(msg.seq)) return;
    this._seenSeqs.add(msg.seq);
    let opened;
    try {
      opened = await openSignalingEnvelope({
        armored: msg.payload,
        decryptionKey: this.privateKey,
        audienceKeyByFpr: this.audienceKeys,
        audienceFprs: this.audienceFprs,
        expectedRoomId: this.roomId,
      });
    } catch (err) {
      this.onError?.(
        err instanceof Error ? err : new Error(String(err))
      );
      return;
    }
    const { payload, signerFpr } = opened;
    if (signerFpr === this.myFpr) return;
    // Everyone polls the mailbox themselves — a message for someone else is
    // simply not ours; relaying is a channel-path concern.
    if (payload.to && payload.to !== this.myFpr) return;
    await this._handleSignal(payload, signerFpr);
  }

  /**
   * A sealed envelope arriving over a data channel instead of the mailbox —
   * either addressed to us (channel-first signaling, mesh introductions) or
   * to be forwarded (we are the relaying member). Verification is identical
   * to the mailbox path: same sealed envelope, same checks, only the wire
   * differs.
   * @param {string} fromFpr peer whose channel delivered the frame
   * @param {{ env: string, hops: number }} frame
   */
  async _onChannelEnvelope(fromFpr, frame) {
    if (this._envSeen.seen(frame.env)) return;
    let opened;
    try {
      opened = await openSignalingEnvelope({
        armored: frame.env,
        decryptionKey: this.privateKey,
        audienceKeyByFpr: this.audienceKeys,
        audienceFprs: this.audienceFprs,
        expectedRoomId: this.roomId,
      });
    } catch (err) {
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    const { payload, signerFpr } = opened;
    if (signerFpr === this.myFpr) return;
    if (payload.to && payload.to !== this.myFpr) {
      // Not ours: pass it one link onward. Introductions ride only
      // authenticated links, directly to the target when we hold that link,
      // otherwise on to every other verified member (bounded by the hop cap
      // and the per-node dedupe — a small room drowns no one).
      if (!shouldRelay({ to: payload.to, myFpr: this.myFpr, hops: frame.hops })) {
        return;
      }
      const out = JSON.stringify({ v: 1, env: frame.env, hops: frame.hops + 1 });
      const target = this.peers.get(payload.to);
      if (target?.channel?.readyState === "open" && target.kcVerified) {
        target.channel.send(out);
        return;
      }
      for (const [fpr, p] of this.peers) {
        if (fpr === fromFpr) continue;
        if (p.channel?.readyState === "open" && p.kcVerified) {
          p.channel.send(out);
        }
      }
      return;
    }
    await this._handleSignal(payload, signerFpr);
  }

  /**
   * Verified signaling payload → session/peer state. Shared by the mailbox
   * and channel paths.
   * @param {import("./crypto.js").QuorumEnvelopePayload} payload
   * @param {string} signerFpr
   */
  async _handleSignal(payload, signerFpr) {
    if (payload.type === "invite") {
      await this._handleInvite(payload, signerFpr);
      return;
    }

    if (!this._meshing) return;

    const peer = this.peers.get(signerFpr);
    if (!peer) return;
    peer.pgpVerified = true;
    if (signerFpr === this.initiatorFpr) peer.isInitiator = true;

    if (payload.helloNonce) peer.helloNonce = String(payload.helloNonce);
    if (payload.dtlsFingerprint) {
      peer.remoteDtls = String(payload.dtlsFingerprint);
    }
    if (payload.ecdhPublicJwk) {
      peer.ecdhPublicJwk = payload.ecdhPublicJwk;
      await this._maybeDeriveSession(signerFpr);
    }

    if (payload.type === "hello") {
      peer.status = peer.status === "connected" ? "connected" : "connecting";
      this._emitRoster();
      if (this.myFpr < signerFpr) {
        await this._ensurePeerConnection(signerFpr, true);
      }
      return;
    }

    if (payload.type === "offer" && payload.sdp) {
      await this._ensurePeerConnection(signerFpr, false);
      const p = this.peers.get(signerFpr);
      const pc = p?.pc;
      if (!pc || !p) return;
      // Perfect negotiation: on glare the impolite peer drops the incoming
      // offer (its own is in flight and will win); the polite peer accepts —
      // setRemoteDescription rolls its pending local offer back implicitly.
      p.ignoreOffer =
        offerCollisionAction({
          polite: p.polite,
          makingOffer: p.makingOffer,
          signalingState: pc.signalingState,
        }) === "ignore";
      if (p.ignoreOffer) return;
      try {
        await pc.setRemoteDescription({ type: "offer", sdp: payload.sdp });
        await pc.setLocalDescription();
      } catch (err) {
        this.onError?.(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      p.localDtls = extractDtlsFingerprint(pc.localDescription?.sdp || "");
      const local = await this._ensureLocalEcdh(signerFpr);
      await this._sendTo(signerFpr, {
        type: "answer",
        sdp: pc.localDescription?.sdp || "",
        dtlsFingerprint: p.localDtls,
        ecdhPublicJwk: local.jwk,
        helloNonce: local.helloNonce,
      });
      await this._maybeDeriveSession(signerFpr);
      peer.status = "connecting";
      this._emitRoster();
      return;
    }

    if (payload.type === "answer" && payload.sdp) {
      const p = this.peers.get(signerFpr);
      const pc = p?.pc;
      if (!pc || !p) return;
      // An answer to an offer we rolled back arrives in a state that cannot
      // take it — stale by construction, dropped rather than surfaced.
      if (pc.signalingState !== "have-local-offer") return;
      try {
        await pc.setRemoteDescription({ type: "answer", sdp: payload.sdp });
      } catch (err) {
        this.onError?.(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      await this._maybeDeriveSession(signerFpr);
      peer.status = "connecting";
      this._emitRoster();
      return;
    }

    if (payload.type === "ice" && payload.candidate) {
      const p = this.peers.get(signerFpr);
      const pc = p?.pc;
      if (!pc) return;
      try {
        await pc.addIceCandidate(payload.candidate);
      } catch (err) {
        // Candidates for an offer we deliberately ignored fail by design.
        if (p?.ignoreOffer) return;
        this.onError?.(
          err instanceof Error ? err : new Error(String(err))
        );
      }
    }
  }

  /**
   * @param {import("./crypto.js").QuorumEnvelopePayload} payload
   * @param {string} signerFpr
   */
  async _handleInvite(payload, signerFpr) {
    try {
      const { inviteNonce, initiator } = await assertInvite(payload, {
        signerFpr,
        expectedRoomId: this.roomId,
        expectedAudience: this.audienceFprs,
      });
      if (this.inviteVerified && this.inviteNonce && this.inviteNonce !== inviteNonce) {
        // Already locked to first valid invite
        return;
      }
      this.inviteNonce = inviteNonce;
      this.initiatorFpr = initiator;
      this.inviteVerified = true;
      const initiatorPeer = this.peers.get(initiator);
      if (initiatorPeer) {
        initiatorPeer.isInitiator = true;
        initiatorPeer.pgpVerified = true;
      }
      this._emitRoster();
      if (!this._meshing) {
        await this._beginMeshing();
      }
    } catch (err) {
      this.onError?.(
        err instanceof Error ? err : new Error(String(err))
      );
    }
  }

  async _beginMeshing() {
    this._meshing = true;
    this.onStatus?.("Announcing presence…");
    for (const fpr of this.peers.keys()) {
      const local = await this._ensureLocalEcdh(fpr);
      await this._sendTo(fpr, {
        type: "hello",
        ecdhPublicJwk: local.jwk,
        helloNonce: local.helloNonce,
      });
    }
    for (const fpr of this.peers.keys()) {
      if (this.myFpr < fpr) {
        await this._ensurePeerConnection(fpr, true);
      }
    }
    this.onStatus?.(
      this.role === "creator"
        ? "Invite published — waiting for peers…"
        : "Invite verified — waiting for peers…"
    );
  }

  /**
   * @param {string} fpr
   * @returns {QuorumPeerState}
   */
  _newPeer(fpr) {
    return {
      fingerprint: fpr,
      status: "unknown",
      pgpVerified: false,
      kcVerified: false,
      isInitiator: fpr === this.initiatorFpr,
      pc: null,
      channel: null,
      sessionKey: null,
      transcriptHash: null,
      ecdhPublicJwk: null,
      helloNonce: null,
      localDtls: "",
      remoteDtls: "",
      localEcdh: null,
      localEcdhJwk: null,
      localHelloNonce: null,
      kcSent: false,
      polite: this.myFpr < fpr,
      makingOffer: false,
      ignoreOffer: false,
    };
  }

  /**
   * @param {string} peerFpr
   * @returns {Promise<{ jwk: JsonWebKey, helloNonce: string, pair: CryptoKeyPair }>}
   */
  async _ensureLocalEcdh(peerFpr) {
    const peer = this.peers.get(peerFpr);
    if (!peer) throw new Error("Unknown peer");
    if (!peer.localEcdh || !peer.localEcdhJwk || !peer.localHelloNonce) {
      peer.localEcdh = await generateEcdhKeyPair();
      peer.localEcdhJwk = await exportEcdhPublicJwk(peer.localEcdh.publicKey);
      peer.localHelloNonce = randomNonceHex(16);
    }
    return {
      jwk: peer.localEcdhJwk,
      helloNonce: peer.localHelloNonce,
      pair: peer.localEcdh,
    };
  }

  /**
   * @param {string} peerFpr
   * @param {boolean} asOfferer
   */
  async _ensurePeerConnection(peerFpr, asOfferer) {
    let peer = this.peers.get(peerFpr);
    if (!peer) return;
    if (peer.pc) return;
    const local = await this._ensureLocalEcdh(peerFpr);
    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    peer.pc = pc;
    peer.status = "connecting";
    // Into the shared inventory (§57a). The registry reads `pc`/`channel`
    // *through* this peer record rather than copying them, which is why
    // registering here — before the channel exists — is correct: `_wireChannel`
    // assigns it later and `ondatachannel` may replace it, and a copied field
    // would go stale in the direction that reads as "connected, no channel".
    //
    // Nothing about negotiation, key derivation or key confirmation moves. What
    // the mesh gives up is being the sole answer to "what is connected", which
    // it was never the right owner of: the five `rtc.*` diagnostics used to
    // refuse outright for any connection made another way.
    registerLink({
      id: peerFpr,
      origin: "quorum",
      role: asOfferer ? "offerer" : "answerer",
      holder: peer,
      label: "quorum",
      authenticated: !!peer.kcVerified,
    });
    this._emitRoster();

    pc.onicecandidate = (ev) => {
      if (!ev.candidate) return;
      void this._sendTo(peerFpr, {
        type: "ice",
        candidate: ev.candidate.toJSON(),
        ecdhPublicJwk: local.jwk,
        helloNonce: local.helloNonce,
      });
    };
    // One offer path for both the first negotiation and every renegotiation:
    // creating the data channel below trips this, and so does restartIce()
    // (which previously went nowhere — no handler meant no new offer, so
    // "Restart connection" only ever cleared flags). No-arg
    // setLocalDescription picks offer-or-answer from signalingState itself.
    pc.onnegotiationneeded = async () => {
      try {
        peer.makingOffer = true;
        await pc.setLocalDescription();
        peer.localDtls = extractDtlsFingerprint(pc.localDescription?.sdp || "");
        await this._sendTo(peerFpr, {
          type: "offer",
          sdp: pc.localDescription?.sdp || "",
          dtlsFingerprint: peer.localDtls,
          ecdhPublicJwk: local.jwk,
          helloNonce: local.helloNonce,
        });
      } catch (err) {
        this.onError?.(err instanceof Error ? err : new Error(String(err)));
      } finally {
        peer.makingOffer = false;
      }
    };
    pc.onconnectionstatechange = () => {
      const st = pc.connectionState;
      if (st === "connected") {
        if (!peer.kcVerified) peer.status = "connecting";
        else peer.status = "connected";
      } else if (st === "failed" || st === "closed" || st === "disconnected") {
        peer.status = st === "failed" ? "failed" : peer.status;
      }
      this._emitRoster();
    };
    pc.ondatachannel = (ev) => {
      this._wireChannel(peerFpr, ev.channel);
    };

    if (asOfferer) {
      // The offer itself rides onnegotiationneeded, which this trips.
      const channel = pc.createDataChannel("quorum", { ordered: true });
      this._wireChannel(peerFpr, channel);
    }
  }

  /**
   * @param {string} peerFpr
   * @param {RTCDataChannel} channel
   */
  _wireChannel(peerFpr, channel) {
    const peer = this.peers.get(peerFpr);
    if (!peer) return;
    peer.channel = channel;
    channel.onopen = () => {
      void this._maybeSendKeyConfirm(peerFpr);
      this._emitRoster();
    };
    channel.onclose = () => {
      if (peer.status === "connected") peer.status = "failed";
      peer.kcVerified = false;
      patchLink(peerFpr, { authenticated: false });
      this._emitRoster();
    };
    channel.onmessage = (ev) => {
      void this._onChannelMessage(peerFpr, String(ev.data || ""));
    };
  }

  /**
   * @param {string} peerFpr
   * @param {string} raw
   */
  async _onChannelMessage(peerFpr, raw) {
    const frame = classifyChannelFrame(raw);
    if (frame?.kind === "envelope") {
      await this._onChannelEnvelope(peerFpr, frame);
      return;
    }
    if (frame?.kind !== "session") return;
    const peer = this.peers.get(peerFpr);
    if (!peer?.sessionKey) return;
    try {
      const pt = await decryptSessionPayload(peer.sessionKey, frame.blob);
      const msg = JSON.parse(pt);
      if (msg.kind === "kc") {
        const th = String(msg.transcriptHash || "");
        const from = normalizeFingerprintInput(msg.fpr || "") || peerFpr;
        if (
          from === peerFpr &&
          String(msg.roomId || "") === this.roomId &&
          th &&
          th === peer.transcriptHash
        ) {
          peer.kcVerified = true;
          peer.status = "connected";
          peer.pgpVerified = true;
          // The inventory's `authenticated` is the mesh's own key-confirmation
          // fact, not a second opinion about it — the panel and the `connstate`
          // tile both read it from there.
          patchLink(peerFpr, { authenticated: true });
          this._emitRoster();
          this.onStatus?.("Peer verified — secure channel ready");
          await this._maybeSendKeyConfirm(peerFpr);
        } else {
          peer.status = "failed";
          this.onError?.(new Error("Key confirmation failed"));
          this._emitRoster();
        }
        return;
      }
      if (msg.kind === "chat") {
        if (!peer.kcVerified) return;
        this.onChat?.({
          from: normalizeFingerprintInput(msg.from) || peerFpr,
          text: String(msg.text || ""),
          ts: Number(msg.ts) || Date.now(),
        });
      }
    } catch (err) {
      this.onError?.(
        err instanceof Error ? err : new Error(String(err))
      );
    }
  }

  /** @param {string} peerFpr */
  async _maybeDeriveSession(peerFpr) {
    const peer = this.peers.get(peerFpr);
    if (
      !peer?.ecdhPublicJwk ||
      !peer.localEcdh ||
      !peer.localEcdhJwk ||
      !peer.localHelloNonce ||
      !peer.helloNonce ||
      !this.inviteNonce ||
      !peer.localDtls ||
      !peer.remoteDtls ||
      peer.sessionKey
    ) {
      return;
    }
    const peerPub = await importEcdhPublicJwk(peer.ecdhPublicJwk);
    const dtls = combineDtlsFingerprints(peer.localDtls, peer.remoteDtls);
    const { aesKey, transcriptHash } = await derivePairwiseSessionKey({
      privateKey: peer.localEcdh.privateKey,
      peerPublicKey: peerPub,
      roomId: this.roomId,
      myFpr: this.myFpr,
      peerFpr,
      audienceFprs: this.audienceFprs,
      myEcdhJwk: peer.localEcdhJwk,
      peerEcdhJwk: peer.ecdhPublicJwk,
      inviteNonce: this.inviteNonce,
      myHelloNonce: peer.localHelloNonce,
      peerHelloNonce: peer.helloNonce,
      dtlsFingerprint: dtls,
    });
    peer.sessionKey = aesKey;
    peer.transcriptHash = transcriptHash;
    await this._maybeSendKeyConfirm(peerFpr);
  }

  /** @param {string} peerFpr */
  async _maybeSendKeyConfirm(peerFpr) {
    const peer = this.peers.get(peerFpr);
    if (
      !peer?.sessionKey ||
      !peer.transcriptHash ||
      !peer.channel ||
      peer.channel.readyState !== "open" ||
      peer.kcSent
    ) {
      return;
    }
    peer.kcSent = true;
    const body = JSON.stringify({
      kind: "kc",
      fpr: this.myFpr,
      roomId: this.roomId,
      transcriptHash: peer.transcriptHash,
      ts: Date.now(),
    });
    const blob = await encryptSessionPayload(peer.sessionKey, body);
    peer.channel.send(JSON.stringify({ v: 1, blob }));
  }

  /**
   * @param {Partial<import("./crypto.js").QuorumEnvelopePayload>} fields
   */
  async _broadcast(fields) {
    const audienceKeys = [...this.audienceKeys.values()];
    const payload = {
      v: 1,
      from: this.myFpr,
      to: null,
      roomId: this.roomId,
      ts: Date.now(),
      ...fields,
    };
    const armored = await sealSignalingEnvelope({
      payload: /** @type {import("./crypto.js").QuorumEnvelopePayload} */ (
        payload
      ),
      signingKey: this.privateKey,
      audienceKeys,
    });
    await postSignaling(this.roomId, armored);
  }

  /**
   * @param {string} toFpr
   * @param {Partial<import("./crypto.js").QuorumEnvelopePayload>} fields
   */
  async _sendTo(toFpr, fields) {
    const audienceKeys = [...this.audienceKeys.values()];
    const payload = {
      v: 1,
      from: this.myFpr,
      to: toFpr,
      roomId: this.roomId,
      ts: Date.now(),
      ...fields,
    };
    const armored = await sealSignalingEnvelope({
      payload: /** @type {import("./crypto.js").QuorumEnvelopePayload} */ (
        payload
      ),
      signingKey: this.privateKey,
      audienceKeys,
    });
    // Channel-first: once links exist, signaling rides them and the mailbox
    // becomes the bootstrap-only path — a renegotiation survives the mailbox
    // dying, and a newcomer's introduction reaches peers it cannot signal
    // directly. The envelope is sealed end to end either way; the wire
    // carries nothing a relay can read or alter.
    if (this._sendEnvelopeViaChannel(toFpr, armored)) return;
    await postSignaling(this.roomId, armored);
  }

  /**
   * @param {string} toFpr
   * @param {string} armored
   * @returns {boolean} whether any channel accepted it
   */
  _sendEnvelopeViaChannel(toFpr, armored) {
    // Never re-handle our own frame if a copy gossips back.
    this._envSeen.seen(armored);
    const frame = JSON.stringify({ v: 1, env: armored, hops: 0 });
    const direct = this.peers.get(toFpr);
    // Direct link: any open channel on a *live* connection will do —
    // pre-verification traffic is exactly what signaling is, and the envelope
    // carries its own proof. The connectionState check matters during ICE
    // failure: a dying channel still reads "open" and would swallow the very
    // restart offer meant to revive it — that case must reach the mailbox.
    if (
      direct?.channel?.readyState === "open" &&
      direct.pc?.connectionState === "connected"
    ) {
      try {
        direct.channel.send(frame);
        return true;
      } catch (_) {
        /* fall through to relay / mailbox */
      }
    }
    // Relay: only over authenticated links (relayed introductions must ride
    // links whose far end is proven, DESIGN §7 step 4).
    let sent = false;
    for (const [fpr, p] of this.peers) {
      if (fpr === toFpr) continue;
      if (
        p.channel?.readyState === "open" &&
        p.kcVerified &&
        p.pc?.connectionState === "connected"
      ) {
        try {
          p.channel.send(frame);
          sent = true;
        } catch (_) {
          /* this member just dropped — try the next */
        }
      }
    }
    return sent;
  }

  _emitRoster() {
    this.onRoster?.(this.peers);
  }
}

export { requireSelfInAudience, canonicalAudience };
