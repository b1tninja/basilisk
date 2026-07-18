/**
 * Quorum full-mesh WebRTC data-channel session.
 * @module lib/quorum/rtc
 */

import {
  derivePairwiseSessionKey,
  decryptSessionPayload,
  encryptSessionPayload,
  exportEcdhPublicJwk,
  extractDtlsFingerprint,
  fetchAudienceKeys,
  generateEcdhKeyPair,
  importEcdhPublicJwk,
  openSignalingEnvelope,
  sealSignalingEnvelope,
} from "./crypto.js";
import { canonicalAudience, isValidRoomId } from "./room.js";
import { postSignaling, startSignalingPoll } from "./signaling.js";
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
 * @property {RTCPeerConnection|null} pc
 * @property {RTCDataChannel|null} channel
 * @property {CryptoKey|null} sessionKey
 * @property {JsonWebKey|null} ecdhPublicJwk
 */

/**
 * @typedef {object} QuorumSessionOpts
 * @property {string} roomId
 * @property {string[]} audienceFprs
 * @property {import("openpgp").PrivateKey} privateKey
 * @property {string} myFingerprint
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
    this.audienceFprs = canonicalAudience(opts.audienceFprs);
    this.privateKey = opts.privateKey;
    this.myFpr = normalizeFingerprintInput(opts.myFingerprint);
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
    /** @type {CryptoKeyPair|null} */
    this.ecdh = null;
    /** @type {JsonWebKey|null} */
    this.myEcdhJwk = null;
    this._since = 0;
    this._poll = null;
    this._seenSeqs = new Set();
    this._makingOffer = new Set();
  }

  async start() {
    this.onStatus?.("Loading audience keys…");
    this.audienceKeys = await fetchAudienceKeys(this.audienceFprs);
    if (!this.audienceKeys.has(this.myFpr)) {
      // Allow local key even if fetch used a different casing — ensure we have encrypt keys for others
      const missing = this.audienceFprs.filter((f) => !this.audienceKeys.has(f));
      if (missing.length) {
        throw new Error(
          `Missing public keys for: ${missing.map((f) => f.slice(0, 8)).join(", ")}`
        );
      }
    }
    this.ecdh = await generateEcdhKeyPair();
    this.myEcdhJwk = await exportEcdhPublicJwk(this.ecdh.publicKey);

    for (const fpr of this.audienceFprs) {
      if (fpr === this.myFpr) continue;
      this.peers.set(fpr, {
        fingerprint: fpr,
        status: "unknown",
        pgpVerified: false,
        pc: null,
        channel: null,
        sessionKey: null,
        ecdhPublicJwk: null,
      });
    }
    this._emitRoster();

    this.onStatus?.("Announcing presence…");
    await this._broadcast({
      type: "hello",
      ecdhPublicJwk: this.myEcdhJwk,
    });

    this._poll = startSignalingPoll({
      roomId: this.roomId,
      getSince: () => this._since,
      setSince: (s) => {
        this._since = s;
      },
      onMessage: (m) => this._onMailbox(m),
      onError: (err) => this.onError?.(err),
    });

    // Perfect negotiation: offer to peers with lexicographically greater fpr
    for (const fpr of this.peers.keys()) {
      if (this.myFpr < fpr) {
        await this._ensurePeerConnection(fpr, true);
      }
    }
    this.onStatus?.("Waiting for peers…");
  }

  stop() {
    this._poll?.stop();
    this._poll = null;
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
      peer.status = "failed";
    }
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
      if (!peer.channel || peer.channel.readyState !== "open" || !peer.sessionKey) {
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

    const peer = this.peers.get(signerFpr);
    if (!peer) return;
    peer.pgpVerified = true;

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
      const pc = this.peers.get(signerFpr)?.pc;
      if (!pc) return;
      await pc.setRemoteDescription({ type: "offer", sdp: payload.sdp });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await this._sendTo(signerFpr, {
        type: "answer",
        sdp: answer.sdp || "",
        dtlsFingerprint: extractDtlsFingerprint(answer.sdp || ""),
        ecdhPublicJwk: this.myEcdhJwk || undefined,
      });
      peer.status = "connecting";
      this._emitRoster();
      return;
    }

    if (payload.type === "answer" && payload.sdp) {
      const pc = this.peers.get(signerFpr)?.pc;
      if (!pc) return;
      await pc.setRemoteDescription({ type: "answer", sdp: payload.sdp });
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
   * @param {string} peerFpr
   * @param {boolean} asOfferer
   */
  async _ensurePeerConnection(peerFpr, asOfferer) {
    let peer = this.peers.get(peerFpr);
    if (!peer) return;
    if (peer.pc) return;
    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    peer.pc = pc;
    peer.status = "connecting";
    this._emitRoster();

    pc.onicecandidate = (ev) => {
      if (!ev.candidate) return;
      void this._sendTo(peerFpr, {
        type: "ice",
        candidate: ev.candidate.toJSON(),
        ecdhPublicJwk: this.myEcdhJwk || undefined,
      });
    };
    pc.onconnectionstatechange = () => {
      const st = pc.connectionState;
      if (st === "connected") peer.status = "connected";
      else if (st === "failed" || st === "closed" || st === "disconnected") {
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
      await this._sendTo(peerFpr, {
        type: "offer",
        sdp: offer.sdp || "",
        dtlsFingerprint: extractDtlsFingerprint(offer.sdp || ""),
        ecdhPublicJwk: this.myEcdhJwk || undefined,
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
      peer.status = "connected";
      this._emitRoster();
      this.onStatus?.("Mesh connected");
    };
    channel.onclose = () => {
      if (peer.status === "connected") peer.status = "failed";
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
      if (msg.kind === "chat") {
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
    if (!peer?.ecdhPublicJwk || !this.ecdh || peer.sessionKey) return;
    const peerPub = await importEcdhPublicJwk(peer.ecdhPublicJwk);
    peer.sessionKey = await derivePairwiseSessionKey(
      this.ecdh.privateKey,
      peerPub,
      this.roomId,
      this.myFpr,
      peerFpr
    );
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
