/**
 * ICE server configuration — the `RTCIceServer[]` every connection starts from.
 *
 * Lives here rather than in `lib/notebook/session.js`, where it used to, because
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
 * **A STUN binding request is still a packet to a third party**, and it tells
 * that third party this machine's public address. In an app whose premise is
 * that nothing leaves the machine unasked, declining it has to be sayable —
 * so `iceServersOrDefault` below is the one place the substitution happens,
 * and it distinguishes *nobody said* from *somebody said none*.
 *
 * @module lib/webrtc/ice
 */

/** @type {RTCIceServer[]} */
export const DEFAULT_ICE_SERVERS = [
  { urls: "stun:stun.cloudflare.com:3478" },
  { urls: "stun:stun.l.google.com:19302" },
];

/**
 * No ICE servers at all — host candidates only, no packet to anyone.
 *
 * A named constant rather than a bare `[]` because the whole point is that
 * this list is an *answer*: the empty array a caller passes deliberately must
 * be distinguishable, at every site, from the one that falls out of a missing
 * field. Frozen so a consumer cannot push a server into the shared value.
 *
 * @type {RTCIceServer[]}
 */
export const NO_ICE_SERVERS = Object.freeze([]);

/**
 * The one rule for *what ICE servers a connection starts from*.
 *
 * Four sites used to answer this question and three of them answered it with
 * `list?.length ? list : DEFAULT_ICE_SERVERS`, which reads an empty list as
 * "nothing was asked" and quietly substitutes public STUN. That made "no third
 * party" inexpressible: a user could write it in a recipe and the session
 * layer would overrule it one call later. The distinction the truthy test
 * cannot make is the one that matters:
 *
 *  - `null` / `undefined` — **nobody said**. Defaults fill it, and that is the
 *    only case they ever fill.
 *  - an array — **somebody said**, and an empty one is an answer, not a gap.
 *
 * Callers do not re-implement either half; `src/test/webrtc-ice-defaults.test.js`
 * fails if a module reaches for `DEFAULT_ICE_SERVERS` to make this decision on
 * its own.
 *
 * @param {RTCIceServer[] | null | undefined} requested
 * @returns {RTCIceServer[]}
 */
export function iceServersOrDefault(requested) {
  if (requested == null) return DEFAULT_ICE_SERVERS;
  if (!Array.isArray(requested)) {
    throw new TypeError("iceServers must be an RTCIceServer[] or null");
  }
  return requested;
}

/**
 * How many of a list are third parties, by role.
 *
 * The fact behind every "was this host-only by choice?" sentence on screen.
 * It is one line, which is exactly why it is written once: a panel counting
 * `stun:` entries itself is a second answer to a question the connection has
 * already answered.
 *
 * @param {RTCIceServer[] | null | undefined} servers
 * @returns {{ stun: number, turn: number, total: number }}
 */
export function iceServerCensus(servers) {
  const list = Array.isArray(servers) ? servers : [];
  let stun = 0;
  let turn = 0;
  for (const s of list) {
    const urls = Array.isArray(s?.urls) ? s.urls : [s?.urls];
    for (const u of urls) {
      if (/^turns?:/i.test(String(u || ""))) turn++;
      else if (/^stuns?:/i.test(String(u || ""))) stun++;
    }
  }
  return { stun, turn, total: stun + turn };
}
