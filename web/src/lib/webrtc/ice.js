/**
 * ICE server configuration — the `RTCIceServer[]` every connection starts from.
 *
 * Lives here rather than in `lib/quorum/session.js`, where it used to, because
 * `RTCIceServer` is a WebRTC dictionary and nothing about this list is
 * quorum's: `rtc.ice`, `rtc.gather`, `peer.offer` and the mesh all resolve
 * against it. It was the smallest of the three things that made
 * `lib/toolkit/rtc-ops.js` — the module implementing the *spec* ops — import
 * from the session layer that is supposed to sit on top of it.
 *
 * Both entries are STUN only. A STUN server learns the reflexive address it
 * hands back and nothing else; a TURN relay would carry the traffic, which is
 * why there is no default one and `rtc.ice turn=` takes its credential from a
 * slot rather than a literal.
 *
 * @module lib/webrtc/ice
 */

/** @type {RTCIceServer[]} */
export const DEFAULT_ICE_SERVERS = [
  { urls: "stun:stun.cloudflare.com:3478" },
  { urls: "stun:stun.l.google.com:19302" },
];
