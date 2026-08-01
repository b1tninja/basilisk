import { NetworkArtifact } from "basilisk-portal";

/*
 * Every body below was produced by running the real ops in a real Chromium:
 * `rtc.ice`, `rtc.gather`, `rtc.certificate`, `stun.check` and `rtc.offer`
 * against live STUN, plus a loopback `RTCPeerConnection` pair for the
 * candidate-pair, connection-state and data-channel stats. Ports, priorities,
 * foundations, timings, the DTLS fingerprint and the SDP are all as the
 * browser reported them.
 *
 * One redaction, stated because it is the only edit: the server-reflexive
 * address the probe discovered was a real home IP, so it is replaced with
 * 198.51.100.7 (RFC 5737 TEST-NET-2). The shape, port and pairing are
 * untouched — and a redacted-looking address is itself accurate here, since
 * Chromium already redacts *local* candidates to an mDNS `.local` name, which
 * is why the host row below reads as a UUID.
 */

const ICE = {
  v: 1,
  iceServers: [
    { urls: "stun:stun.cloudflare.com:3478" },
    { urls: "stun:stun.l.google.com:19302" },
  ],
};

const ICE_WITH_TURN = {
  v: 1,
  iceServers: [
    { urls: "stun:stun.cloudflare.com:3478" },
    { urls: "turns:turn.example.net:5349", username: "basilisk", credential: "s3cr3t" },
  ],
};

const CANDIDATES = {
  v: 1,
  candidates: [
    {
      type: "host",
      address: "16e934a4-16b9-4360-9d0f-ba7340ab92a7.local",
      port: 50361,
      protocol: "udp",
      foundation: "4288671826",
      priority: 2113937151,
      relatedAddress: null,
      ts: 28,
    },
    {
      type: "srflx",
      address: "198.51.100.7",
      port: 50361,
      protocol: "udp",
      foundation: "1671955043",
      priority: 1677729535,
      relatedAddress: "0.0.0.0",
      ts: 49,
    },
  ],
  byType: { host: 1, prflx: 0, srflx: 1, relay: 0 },
  total: 2,
  ms: 153,
  notes: ["no relay — no TURN configured (informational, not a failure)"],
};

const STUN_OK = {
  v: 1,
  server: "stun:stun.cloudflare.com:3478",
  ok: true,
  publicAddress: "198.51.100.7:50363",
  candidates: { host: 1, srflx: 1 },
  ms: 130,
  note: "STUN reachable — reflexive address discovered",
};

const CERTIFICATE = {
  v: 1,
  algorithm: "ECDSA/P-256",
  expires: "2026-08-31T16:01:38.000Z",
  fingerprints: [
    {
      algorithm: "sha-256",
      value:
        "bd:1c:47:6b:f6:36:9b:9a:35:20:69:ce:cc:33:6d:a1:7e:a9:d6:44:1c:54:52:7f:8d:84:9a:29:53:58:61:b7",
    },
  ],
  note: "ephemeral unless pinned — quorum.offer mints its own throwaway certificate when this op isn't used",
};

const PEER = "9f2c41ab7e6d0538c1b4a90ee7d25f3b8c07a641";

const PAIRS = {
  v: 1,
  peers: [
    {
      peer: PEER,
      role: "",
      pairs: [
        {
          local: { type: "host", label: "host:52506", address: "", port: 52506, protocol: "udp" },
          remote: { type: "host", label: "host:52508", address: "", port: 52508, protocol: "udp" },
          state: "succeeded",
          nominated: true,
          rttMs: 0,
          bytesSent: 263718,
          bytesReceived: 9221,
        },
      ],
      nominatedCount: 1,
    },
  ],
  allFailed: false,
  note: "",
};

const CONNSTATE = {
  v: 1,
  peers: [
    {
      peer: PEER,
      connectionState: "connected",
      iceConnectionState: "connected",
      signalingState: "stable",
      channelState: "open",
      verified: true,
    },
  ],
};

/** Sampled mid-burst, while the SCTP queue was genuinely behind. */
const CHANNEL_BUSY = {
  v: 1,
  peers: [
    {
      peer: PEER,
      readyState: "open",
      bufferedAmount: 244490,
      bufferedAmountLowThreshold: 65535,
      messagesSent: 200,
      messagesReceived: 0,
      ordered: true,
      backPressured: true,
    },
  ],
};

/** The same channel once it drained. */
const CHANNEL_IDLE = {
  v: 1,
  peers: [
    {
      peer: PEER,
      readyState: "open",
      bufferedAmount: 0,
      bufferedAmountLowThreshold: 65535,
      messagesSent: 200,
      messagesReceived: 200,
      ordered: true,
      backPressured: false,
    },
  ],
};

const SDP = `v=0\r
o=- 4804095152581157549 2 IN IP4 127.0.0.1\r
s=-\r
t=0 0\r
a=group:BUNDLE 0\r
a=extmap-allow-mixed\r
a=msid-semantic: WMS\r
m=application 50365 UDP/DTLS/SCTP webrtc-datachannel\r
c=IN IP4 198.51.100.7\r
a=candidate:2004875447 1 udp 2113937151 16e934a4-16b9-4360-9d0f-ba7340ab92a7.local 50365 typ host generation 0 network-cost 999\r
a=candidate:641585023 1 udp 1677729535 198.51.100.7 50365 typ srflx raddr 0.0.0.0 rport 0 generation 0 network-cost 999\r
a=ice-ufrag:DEPu\r
a=ice-pwd:JEX6iLW9ZuurF7kI99IMbm9U\r
a=ice-options:trickle\r
a=fingerprint:sha-256 8E:82:38:C2:EE:B4:08:91:7B:05:15:66:07:1C:7A:3D:21:62:88:FD:2F:D6:21:77:18:9B:FF:D3:E5:BF:D3:3D\r
a=setup:actpass\r
a=mid:0\r
a=sctp-port:5000\r
a=max-message-size:262144\r
`;

/**
 * `rtc.gather` — every candidate the browser found, typed and coloured by how
 * far the packet has to travel: host is local, srflx has been out through a
 * NAT, relay would be going through a TURN server.
 *
 * All four MDN types get a row, including the two that found nothing. That is
 * the design: a missing `relay` is the expected outcome of not configuring
 * TURN, so it renders dim with a reason rather than being hidden (which hides
 * the diagnosis) or drawn as an error (which cries wolf).
 */
export const Candidates = () => (
  <NetworkArtifact netType="candidate" data={CANDIDATES} />
);

/**
 * The two shapes that share the `endpoint` type. `rtc.ice` is pure config — no
 * network touched — and marks a TURN entry as credential-bound, because a TURN
 * URL with a username is a secret in a way a STUN URL is not. `stun.check` is
 * the one-shot NAT diagnostic that actually goes out and comes back.
 */
export const Endpoints = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 12 }}>
    <NetworkArtifact netType="endpoint" data={ICE} />
    <NetworkArtifact netType="endpoint" data={ICE_WITH_TURN} />
    <NetworkArtifact netType="endpoint" data={STUN_OK} />
  </div>
);

/**
 * `rtc.certificate` — the DTLS identity, and specifically the fingerprint the
 * remote peer actually sees. It mirrors `genkey`'s shape: a source op emitting
 * a handle plus the one public fact worth comparing.
 */
export const Certificate = () => (
  <NetworkArtifact netType="certificate" data={CERTIFICATE} />
);

/**
 * The stats family, discriminated by `netKind` on one `netType`.
 *
 * The pair matrix names the winner and, when there is more than one, keeps the
 * losing pairs visible at reduced opacity rather than showing only the
 * nominated one — debugging "why is this slow" needs the whole graph. Chromium
 * leaves `role` null even on a fully connected transport, so the row says so
 * instead of showing a blank chip.
 *
 * The channel panel's bar is back-pressure against the low-water mark, and the
 * two readings are the same channel a few hundred milliseconds apart: behind
 * by 244 KB against a 64 KB mark, then drained. ARIA carries the real byte
 * count — the bar is only its picture, quantized to 5% because a width style
 * prop is what the product's CSP refuses.
 */
export const Stats = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 12 }}>
    <NetworkArtifact netType="stats" netKind="candidate-pairs" data={PAIRS} />
    <NetworkArtifact netType="stats" netKind="data-channel" data={CHANNEL_BUSY} />
    <NetworkArtifact netType="stats" netKind="data-channel" data={CHANNEL_IDLE} />
  </div>
);

/**
 * `rtc.state` — the connection walked along its five ICE stages, with the
 * reached one bold and the exact transport states on the right. The strip is
 * the same shape the candidate type row uses.
 */
export const ConnectionState = () => (
  <NetworkArtifact netType="connstate" data={CONNSTATE} />
);

/**
 * SDP is the one network type that is genuinely text on the wire, so it is the
 * one that renders as text — `data` is unused and `content` carries it. The
 * candidate lines and the DTLS fingerprint inside are the same facts the two
 * cards above draw structurally; this is what they look like unparsed.
 */
export const Sdp = () => <NetworkArtifact netType="sdp" data={null} content={SDP} />;
