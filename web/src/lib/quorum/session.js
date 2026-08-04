/**
 * Quorum full-mesh WebRTC data-channel session.
 *
 * Creators post a PGP-signed invite proving key possession; joiners mesh only
 * after verifying that invite. Pairwise session keys use per-peer ephemeral
 * ECDH with transcript-bound HKDF and key confirmation (data-channel PFS).
 *
 * **This module is a consumer of `lib/webrtc/`, not a peer of it.** No WebRTC
 * built-in is constructed, driven, or *held* here. A peer's transport is a
 * `PeerLink` — an opaque handle from `webrtc/peer-link.js` — and everything
 * this layer does to it is a method on that handle. The connection inside it
 * is never unwrapped: there is no `pc` on a peer record, and
 * `src/test/quorum-layering.test.js` fails if one comes back.
 *
 * That is the difference between this and the first extraction, which moved the
 * driver out and then took the connection straight back off the link it
 * returned — nine `.pc` reads, `signalingState` and `close` among them, which is
 * the transport with two helpers factored out rather than a layer above it.
 *
 * SDP parsing lives in `webrtc/sdp.js`; the link inventory, the default ICE
 * server list, the glare rule and the selected-candidate stats in
 * `webrtc/link-registry.js`, `ice.js`, `negotiation.js` and `candidates.js`.
 * Deleting `lib/quorum/` leaves `peer.*` and `rtc.*` standing.
 *
 * What stays is the protocol: the PGP audience, the signed invite, the relay,
 * the room, the roster, key derivation, key confirmation, and the mesh policy
 * that decides *which* links exist and who offers. The one piece of transport
 * this layer still touches directly is a live data channel's `send` and
 * `readyState` — because the frames on it are quorum's own, sealed under a key
 * this layer holds and the transport cannot read.
 *
 * **Why the driver could move, after two commits said it could not.**
 * `derivePairwiseSessionKey` binds **both DTLS fingerprints** into the
 * transcript, and the local one is minted from the local description *inside*
 * negotiation. Moving negotiation moves the instant that fingerprint becomes
 * known, and the failure mode of getting it subtly wrong is key confirmation
 * *succeeding anyway* over a transcript no longer bound to the transport —
 * green tests, broken binding (§59b). What made it safe was not care: it was
 * `src/test/quorum-dtls-binding.test.js`, a test that **fails when tampered**.
 * Two real sessions mesh over a fake transport; a signalling relay rewrites one
 * peer's fingerprint and re-seals under that peer's own key, so nothing in the
 * PGP layer can see it; both ends must end up unconfirmed. That test was
 * written and watched fail-when-tampered *before* the extraction, and it holds
 * the driver's return contract in place afterwards: a link's offer and its
 * `answerRemoteOffer` hand back `{ sdp, dtlsFingerprint }` together, so an SDP
 * cannot be signalled without the fingerprint that belongs to it.
 *
 * @module lib/quorum/session
 */

import {
  assertInvite,
  buildInvitePayload,
  combineDtlsFingerprints,
  derivePairwiseSessionKey,
  decryptSessionPayload,
  encryptSessionPayload,
  exportEcdhPublicJwk,
  fetchAudienceKeys,
  generateEcdhKeyPair,
  importEcdhPublicJwk,
  openSignalingEnvelope,
  randomNonceHex,
  requireSelfInAudience,
  sealSignalingEnvelope,
} from "./crypto.js";
import { canonicalAudience, isValidRoomId } from "./room.js";
import { classifyChannelFrame, createSeenSet, shouldRelay } from "./relay.js";
import { postSignaling, startSignalingPoll } from "./signaling.js";
import { zeroKeyMaterial } from "../pgp/memory.js";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";
import {
  deregisterLink,
  patchLink,
  registerLink,
} from "../webrtc/link-registry.js";
import { iceServersOrDefault } from "../webrtc/ice.js";
import { openPeerLink } from "../webrtc/peer-link.js";

/**
 * @typedef {object} QuorumPeerState
 * @property {string} fingerprint
 * @property {"unknown"|"verified"|"connecting"|"connected"|"failed"} status
 * @property {boolean} pgpVerified
 * @property {boolean} kcVerified
 * @property {boolean} isInitiator
 * @property {import("../webrtc/peer-link.js").PeerLink|null} link
 *   The transport, as a handle. What is inside it is the driver's business.
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
 * @typedef {object} QuorumSessionOpts
 * @property {string} roomId
 * @property {string[]} audienceFprs
 * @property {import("openpgp").PrivateKey} privateKey
 * @property {string} myFingerprint
 * @property {"creator"|"joiner"} [role]
 * @property {RTCIceServer[]} [iceServers]
 *   Omitted (or null) takes the built-in STUN defaults; `[]` is a deliberate
 *   *no third party* and is honoured as written — host candidates only.
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
    // `iceServersOrDefault`, not `?.length ?:` — an empty list is a user who
    // asked for no third party, and this layer is the last one that could
    // overrule them. It no longer can.
    this.iceServers = iceServersOrDefault(opts.iceServers);
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
      peer.link?.close();
      peer.channel = null;
      peer.link = null;
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
      const link = p?.link;
      if (!link || !p) return;
      p.ignoreOffer = false;
      /** @type {import("../webrtc/peer-link.js").LocalDescriptionFacts|null} */
      let answer = null;
      try {
        answer = await link.answerRemoteOffer({
          sdp: payload.sdp,
          polite: p.polite,
          makingOffer: p.makingOffer,
        });
      } catch (err) {
        this.onError?.(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      // Glare: our own offer is in flight and wins. Remembered because the
      // candidates for the offer we just dropped will fail on arrival, by
      // design.
      if (!answer) {
        p.ignoreOffer = true;
        return;
      }
      // The answer SDP and the fingerprint of the description it came from
      // arrive together and are signalled together — a peer that ever sent one
      // without the other would be claiming a transport it is not using.
      p.localDtls = answer.dtlsFingerprint;
      const local = await this._ensureLocalEcdh(signerFpr);
      await this._sendTo(signerFpr, {
        type: "answer",
        sdp: answer.sdp,
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
      const link = p?.link;
      if (!link || !p) return;
      try {
        // An answer to an offer we rolled back arrives in a state that cannot
        // take it — stale by construction, dropped rather than surfaced.
        if (!(await link.applyRemoteAnswer(payload.sdp))) return;
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
      const link = p?.link;
      if (!link) return;
      try {
        await link.addRemoteCandidate(payload.candidate);
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
      link: null,
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
    // A link whose transport the inventory closed out from under it (the
    // Connections panel's Close nulls its holder's fields) is a husk, and this
    // peer is re-connectable — which is the question `peer.pc === null` used to
    // answer by reaching into the connection.
    if (peer.link && !peer.link.isTornDown()) return;
    const local = await this._ensureLocalEcdh(peerFpr);
    // The transport is the driver's; what it is *for* is this layer's. Every
    // callback below is either identity (which peer), protocol (what rides the
    // signalling envelope) or projection (the roster) — none of it is WebRTC,
    // and none of the WebRTC is here.
    const link = openPeerLink({
      iceServers: this.iceServers,
      onIceCandidate: (candidate) => {
        void this._sendTo(peerFpr, {
          type: "ice",
          candidate,
          ecdhPublicJwk: local.jwk,
          helloNonce: local.helloNonce,
        });
      },
      onMakingOffer: (making) => {
        peer.makingOffer = making;
      },
      // The offer and the fingerprint of the description it was made from
      // arrive in one object, and this is the only place `localDtls` is set on
      // the offering side. There is no window in which an offer has been
      // signalled but the transcript does not yet know what transport it
      // committed to — that ordering is what the DTLS binding rests on.
      onLocalOffer: async ({ sdp, dtlsFingerprint }) => {
        peer.localDtls = dtlsFingerprint;
        await this._sendTo(peerFpr, {
          type: "offer",
          sdp,
          dtlsFingerprint,
          ecdhPublicJwk: local.jwk,
          helloNonce: local.helloNonce,
        });
      },
      onConnectionState: (st) => {
        if (st === "connected") {
          if (!peer.kcVerified) peer.status = "connecting";
          else peer.status = "connected";
        } else if (st === "failed" || st === "closed" || st === "disconnected") {
          peer.status = st === "failed" ? "failed" : peer.status;
        }
        this._emitRoster();
      },
      onDataChannel: (channel) => {
        this._wireChannel(peerFpr, channel);
      },
      onError: (err) => this.onError?.(err),
    });
    peer.link = link;
    peer.status = "connecting";
    // Into the shared inventory (§57a). The **link** is the holder: the registry
    // reads `pc`/`channel` through it rather than copying them, which is why
    // registering here — before a channel exists — is correct, and why the peer
    // record no longer has to carry a connection it is not allowed to use. A
    // copied field would go stale from the first renegotiation onward, in the
    // exact direction that reads as "connected, no channel".
    //
    // What the mesh gives up is being the sole answer to "what is connected",
    // which it was never the right owner of: the five `rtc.*` diagnostics used
    // to refuse outright for any connection made another way.
    registerLink({
      id: peerFpr,
      origin: "quorum",
      role: asOfferer ? "offerer" : "answerer",
      holder: link,
      label: "quorum",
      authenticated: !!peer.kcVerified,
    });
    this._emitRoster();

    // Creating the channel is what starts negotiation, so it goes last —
    // after the connection is in the inventory and the roster has been told.
    if (asOfferer) link.openDataChannel("quorum");
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
    // carries its own proof. The liveness check matters during ICE failure: a
    // dying channel still reads "open" and would swallow the very restart offer
    // meant to revive it — that case must reach the mailbox.
    if (direct?.channel?.readyState === "open" && direct.link?.isLive()) {
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
      if (p.channel?.readyState === "open" && p.kcVerified && p.link?.isLive()) {
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
