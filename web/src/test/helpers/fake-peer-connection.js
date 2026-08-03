/**
 * A two-ended fake `RTCPeerConnection` — enough of the interface to drive a
 * real negotiation, in node, with no browser.
 *
 * It exists for one reason: the quorum session binds **both DTLS fingerprints**
 * into its key transcript, and a fingerprint only exists once a description has
 * been set. Any test of that binding has to run a real offer/answer exchange,
 * because the thing under test is *when* the fingerprint becomes known — not
 * what `derivePairwiseSessionKey` does with it once it has one.
 *
 * Each instance mints its own `a=fingerprint:` line, so the two ends of a pair
 * genuinely disagree about which fingerprint is whose, exactly as two browsers
 * would. `dtlsFingerprint()` reports what an end committed to, which is what a
 * test compares the transcript against.
 *
 * Deliberately unfaithful in two places, both to keep the handshake ordering
 * the one a test can reason about:
 *   - the link only reaches `connected` when the **offerer** applies the answer,
 *     so the answer itself always travels over signalling rather than racing
 *     onto a data channel that opened early;
 *   - `ondatachannel` fires synchronously and the channel opens a microtask
 *     later, so a handler assigned inside `ondatachannel` is always in place
 *     before `onopen`.
 */

let counter = 0;

/** @type {Map<string, FakePeerConnection>} */
const registry = new Map();

/**
 * A distinct, stable-looking SHA-256 certificate fingerprint per connection.
 * @param {number} seed
 * @returns {string}
 */
function mintFingerprint(seed) {
  const bytes = [];
  for (let i = 0; i < 32; i += 1) {
    bytes.push(
      ((seed * 37 + i * 61 + 11) % 256).toString(16).padStart(2, "0").toUpperCase()
    );
  }
  return `sha-256 ${bytes.join(":")}`;
}

class FakeDataChannel {
  /** @param {string} label */
  constructor(label) {
    this.label = label;
    this.readyState = "connecting";
    /** @type {((ev: any) => void)|null} */
    this.onopen = null;
    /** @type {((ev: any) => void)|null} */
    this.onclose = null;
    /** @type {((ev: any) => void)|null} */
    this.onmessage = null;
    /** @type {FakeDataChannel|null} */
    this._other = null;
  }

  /** @param {string} data */
  send(data) {
    if (this.readyState !== "open") {
      throw new Error("InvalidStateError: RTCDataChannel.readyState is not 'open'");
    }
    const other = this._other;
    if (!other) return;
    queueMicrotask(() => {
      if (other.readyState === "open") other.onmessage?.({ data });
    });
  }

  close() {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    queueMicrotask(() => this.onclose?.({}));
    const other = this._other;
    if (other && other.readyState !== "closed") other.close();
  }
}

export class FakePeerConnection {
  /** @type {FakePeerConnection[]} */
  static instances = [];

  /** Drop every connection and its registry entry (call between tests). */
  static reset() {
    for (const pc of FakePeerConnection.instances) {
      try {
        pc.close();
      } catch (_) {
        /* ignore */
      }
    }
    FakePeerConnection.instances = [];
    registry.clear();
  }

  /** @param {{ iceServers?: RTCIceServer[] }} [config] */
  constructor(config = {}) {
    counter += 1;
    this.iceServers = config.iceServers || [];
    this._id = `pc${counter}`;
    this._seed = counter;
    this._dtls = mintFingerprint(counter);
    this._ufrag = `ufrag${counter}`;
    this._epoch = 0;
    this._closed = false;
    this._negotiationQueued = false;
    /** @type {FakeDataChannel[]} */
    this._localChannels = [];
    this._remoteId = "";
    this.addedCandidates = [];

    this.signalingState = "stable";
    this.connectionState = "new";
    this.iceConnectionState = "new";
    this.iceGatheringState = "new";
    /** @type {{ type: string, sdp: string }|null} */
    this.localDescription = null;
    /** @type {{ type: string, sdp: string }|null} */
    this.remoteDescription = null;

    /** @type {((ev: any) => void)|null} */
    this.onicecandidate = null;
    /** @type {((ev: any) => void)|null} */
    this.onnegotiationneeded = null;
    /** @type {((ev: any) => void)|null} */
    this.onconnectionstatechange = null;
    /** @type {((ev: any) => void)|null} */
    this.ondatachannel = null;

    registry.set(this._id, this);
    FakePeerConnection.instances.push(this);
  }

  /** The certificate fingerprint this end offers in every description it makes. */
  dtlsFingerprint() {
    return this._dtls;
  }

  /**
   * @param {"offer"|"answer"} type
   * @returns {string}
   */
  _sdp(type) {
    return (
      [
        "v=0",
        `o=- ${this._seed} ${this._epoch} IN IP4 127.0.0.1`,
        "s=-",
        "t=0 0",
        "a=group:BUNDLE 0",
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
        "c=IN IP4 0.0.0.0",
        `a=ice-ufrag:${this._ufrag}`,
        "a=ice-pwd:0123456789abcdef0123",
        `a=fingerprint:${this._dtls}`,
        `a=setup:${type === "offer" ? "actpass" : "active"}`,
        "a=mid:0",
        `a=x-fake-pc:${this._id}`,
        "a=sctp-port:5000",
      ].join("\r\n") + "\r\n"
    );
  }

  /**
   * @param {string} label
   * @param {{ ordered?: boolean }} [_opts]
   * @returns {FakeDataChannel}
   */
  createDataChannel(label, _opts) {
    const channel = new FakeDataChannel(label);
    this._localChannels.push(channel);
    this._scheduleNegotiation();
    return channel;
  }

  _scheduleNegotiation() {
    if (this._negotiationQueued || this._closed) return;
    this._negotiationQueued = true;
    setTimeout(() => {
      this._negotiationQueued = false;
      if (this._closed) return;
      this.onnegotiationneeded?.({});
    }, 0);
  }

  /**
   * No-arg form only, the way the perfect-negotiation pattern uses it: the type
   * comes from `signalingState`.
   * @param {{ type?: string, sdp?: string }} [desc]
   */
  async setLocalDescription(desc) {
    if (this._closed) throw new Error("InvalidStateError: connection closed");
    const type =
      desc?.type || (this.signalingState === "have-remote-offer" ? "answer" : "offer");
    this.localDescription = {
      type,
      sdp: desc?.sdp || this._sdp(/** @type {"offer"|"answer"} */ (type)),
    };
    this.signalingState = type === "offer" ? "have-local-offer" : "stable";
    this._emitCandidates();
  }

  /** @param {{ type: string, sdp: string }} desc */
  async setRemoteDescription(desc) {
    if (this._closed) throw new Error("InvalidStateError: connection closed");
    if (desc.type === "offer") {
      // An incoming offer in `have-local-offer` is the polite peer accepting on
      // glare — the pending local offer rolls back implicitly.
      this.signalingState = "have-remote-offer";
    } else if (desc.type === "answer") {
      if (this.signalingState !== "have-local-offer") {
        throw new Error(
          `InvalidStateError: cannot set remote answer in ${this.signalingState}`
        );
      }
      this.signalingState = "stable";
    }
    this.remoteDescription = { type: desc.type, sdp: desc.sdp };
    const id = /a=x-fake-pc:(\S+)/.exec(desc.sdp || "")?.[1] || "";
    if (id) this._remoteId = id;
    if (desc.type === "answer") this._establish();
  }

  /** @param {RTCIceCandidateInit} candidate */
  async addIceCandidate(candidate) {
    if (this._closed) throw new Error("InvalidStateError: connection closed");
    if (!this._remoteId) {
      throw new Error("InvalidStateError: no remote description");
    }
    this.addedCandidates.push(candidate);
  }

  restartIce() {
    this._epoch += 1;
    this._ufrag = `ufrag${this._seed}r${this._epoch}`;
    this._scheduleNegotiation();
  }

  close() {
    if (this._closed) return;
    this._closed = true;
    this.connectionState = "closed";
    this.signalingState = "closed";
    for (const ch of this._localChannels) ch.close();
  }

  _emitCandidates() {
    setTimeout(() => {
      if (this._closed) return;
      const seed = this._seed;
      const ufrag = this._ufrag;
      this.onicecandidate?.({
        candidate: {
          candidate: `candidate:1 1 udp 2113937151 127.0.0.1 ${40000 + seed} typ host`,
          sdpMid: "0",
          sdpMLineIndex: 0,
          usernameFragment: ufrag,
          toJSON() {
            return {
              candidate: this.candidate,
              sdpMid: this.sdpMid,
              sdpMLineIndex: this.sdpMLineIndex,
              usernameFragment: this.usernameFragment,
            };
          },
        },
      });
      this.onicecandidate?.({ candidate: null });
    }, 0);
  }

  /** Both ends go live at once, when the offerer applies the answer. */
  _establish() {
    const other = registry.get(this._remoteId);
    if (!other || other._closed) return;
    other._remoteId = this._id;
    for (const end of [this, other]) {
      if (end.connectionState === "connected") continue;
      end.connectionState = "connected";
      end.iceConnectionState = "connected";
      queueMicrotask(() => end.onconnectionstatechange?.({}));
    }
    mirrorChannels(this, other);
    mirrorChannels(other, this);
  }
}

/**
 * Every channel `src` created but has not yet paired gets a twin on `dst`,
 * announced through `dst.ondatachannel` before either end opens.
 * @param {FakePeerConnection} src
 * @param {FakePeerConnection} dst
 */
function mirrorChannels(src, dst) {
  for (const channel of src._localChannels) {
    if (channel._other || channel.readyState === "closed") continue;
    const twin = new FakeDataChannel(channel.label);
    channel._other = twin;
    twin._other = channel;
    dst.ondatachannel?.({ channel: twin });
    queueMicrotask(() => {
      if (channel.readyState === "closed" || twin.readyState === "closed") return;
      channel.readyState = "open";
      twin.readyState = "open";
      channel.onopen?.({});
      twin.onopen?.({});
    });
  }
}
