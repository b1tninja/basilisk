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
 */

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
    this._makingOffer = new Set();
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
    const body = JSON.stringify({
      kind: "chat",
      text: String(text || ""),
      ts: Date.now(),
      from: this.myFpr,
    });
    for (const peer of this.peers.values()) {
      if (
        !peer.channel ||
        peer.channel.readyState !== "open" ||
        !peer.sessionKey ||
        !peer.kcVerified
      ) {
        continue;
      }
      const blob = await encryptSessionPayload(peer.sessionKey, body);
      peer.channel.send(JSON.stringify({ v: 1, blob }));
    }
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
    if (payload.to && payload.to !== this.myFpr) return;

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
      await pc.setRemoteDescription({ type: "offer", sdp: payload.sdp });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      p.localDtls = extractDtlsFingerprint(answer.sdp || "");
      const local = await this._ensureLocalEcdh(signerFpr);
      await this._sendTo(signerFpr, {
        type: "answer",
        sdp: answer.sdp || "",
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
      await pc.setRemoteDescription({ type: "answer", sdp: payload.sdp });
      await this._maybeDeriveSession(signerFpr);
      peer.status = "connecting";
      this._emitRoster();
      return;
    }

    if (payload.type === "ice" && payload.candidate) {
      const pc = this.peers.get(signerFpr)?.pc;
      if (!pc) return;
      try {
        await pc.addIceCandidate(payload.candidate);
      } catch (err) {
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
      if (this._makingOffer.has(peerFpr)) return;
      this._makingOffer.add(peerFpr);
      const channel = pc.createDataChannel("quorum", { ordered: true });
      this._wireChannel(peerFpr, channel);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      peer.localDtls = extractDtlsFingerprint(offer.sdp || "");
      await this._sendTo(peerFpr, {
        type: "offer",
        sdp: offer.sdp || "",
        dtlsFingerprint: peer.localDtls,
        ecdhPublicJwk: local.jwk,
        helloNonce: local.helloNonce,
      });
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
    const peer = this.peers.get(peerFpr);
    if (!peer?.sessionKey) return;
    try {
      const wrapper = JSON.parse(raw);
      const pt = await decryptSessionPayload(peer.sessionKey, wrapper.blob);
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
    await postSignaling(this.roomId, armored);
  }

  _emitRoster() {
    this.onRoster?.(this.peers);
  }
}

export { requireSelfInAudience, canonicalAudience };
