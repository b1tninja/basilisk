/**
 * The relay, contacted only when it is actually needed.
 *
 * ## Why "fallback" cannot mean what it means everywhere else
 *
 * ICE has a fallback of its own and it is not this one. Putting a TURN server
 * in `iceServers` makes the relay *last in priority order*: the agent still
 * **allocates** on it during gathering, before any connectivity check has
 * succeeded or failed. So a relay listed as a fallback learns this machine's
 * address, and that a connection is being made, on every single call —
 * including the large majority that connect host-to-host or through a
 * reflexive address and never relay a byte. The lowest-priority candidate is
 * still an allocation, and an allocation is a disclosure.
 *
 * That is why `ice.js` ships STUN only and says so: a STUN server learns the
 * address it hands back, a relay carries the traffic. A default relay would
 * hand a third party every connection this app makes, in exchange for helping
 * with the few that fail.
 *
 * So the fallback here is **two-phase**, and the phases are separated in time
 * rather than in priority:
 *
 *  1. Gather and connect with whatever the user asked for — no TURN, ever, no
 *     matter what is configured server-side. `firstPhaseServers` is the
 *     assertion: a relay in the starting list is a bug, not a preference.
 *  2. Only once ICE has genuinely **failed**, ask for a credential, add the
 *     relay and restart ICE. A relay operator therefore only ever learns about
 *     the connections that could not be made without it.
 *
 * ## Why `setConfiguration` + `restartIce` is enough, and rebuilding is not needed
 *
 * Read from the specs rather than assumed. W3C webrtc-pc, "set the
 * configuration", step 9: *"if a new list of servers replaces the ICE Agent's
 * existing ICE servers list, no action will be taken until the next gathering
 * phase … If a script wants this to happen immediately, it should do an ICE
 * restart."* RFC 8829 (JSEP) §4.1.18 says the same from the other side: *"Any
 * changes to the STUN/TURN servers to use affect the next gathering phase"*,
 * and setting them sets the `needs-ice-restart` bit so the next offer carries
 * new ICE credentials and kicks off that gathering phase.
 *
 * Both halves are load-bearing and each is useless alone: `setConfiguration`
 * with no restart changes a list nothing will read until something else
 * triggers gathering, and `restartIce` with no `setConfiguration` re-gathers
 * from the same relay-free list. The connection object, its DTLS certificate,
 * its data channel and — for a quorum link — the session key derived over both
 * fingerprints all survive, which is the reason not to rebuild: a new
 * `RTCPeerConnection` mints a new certificate, and a transcript that commits
 * to the old fingerprint would no longer describe the transport.
 * `relay-fallback.test.js` drives both halves and fails if either is dropped.
 *
 * ## What escalation is not allowed to do
 *
 *  - **Loop.** One escalation per link. A second failure after the relay is in
 *    place is the end of the road and says so; retrying would mean a page that
 *    hammers a relay it has already proved cannot help.
 *  - **React to `disconnected`.** That state is transient by definition — ICE
 *    is still checking and frequently recovers on its own. Escalating there
 *    would contact a relay for connections that were about to work.
 *  - **Happen unasked.** `configureRelayFallback` is off until something turns
 *    it on, and a deployment with no relay configured cannot turn it on.
 *
 * @module lib/webrtc/relay-fallback
 */

import { iceServerCensus } from "./ice.js";

/**
 * What a TURN relay can and cannot observe.
 *
 * The most important paragraph in this file, and the reason it is a constant
 * rather than a sentence in a component: overstating it in either direction is
 * a defect. Understated, a user waves through a third party that sees who they
 * talk to and when. Overstated ("the relay can read your messages"), a user
 * refuses a relay that genuinely cannot, and loses the connection for nothing.
 *
 * The distinction is exact. A data channel is SCTP over **DTLS negotiated
 * between the two peers**, whose certificates are pinned to each other by the
 * fingerprints in the SDP. A TURN server is an ICE relay: it forwards UDP for
 * a client that allocated on it. It holds no DTLS key, is not a party to the
 * handshake, and cannot become one without changing a fingerprint the peers
 * have already committed to — which for a quorum link is exactly what
 * `notebook-dtls-binding.test.js` proves is caught. So it carries ciphertext.
 *
 * What it does hold is the traffic: both peers allocate on it, so it sees both
 * addresses, when the connection ran, and how many bytes crossed. That is
 * strictly more than a STUN server, which learns one address and forwards
 * nothing — and it is why this is opt-in and last-resort rather than default.
 *
 * @type {{ readsTraffic: false, seesAddresses: true, summary: string,
 *   canSee: string[], cannotSee: string[] }}
 */
export const RELAY_DISCLOSURE = Object.freeze({
  readsTraffic: /** @type {false} */ (false),
  seesAddresses: /** @type {true} */ (true),
  summary:
    "A TURN relay forwards this connection's packets. It cannot read them — " +
    "the data channel is DTLS end-to-end between the two peers and the relay " +
    "carries ciphertext it holds no key for. It can see both peers' IP " +
    "addresses, when the connection ran, and how much data crossed it.",
  canSee: Object.freeze([
    "both peers' IP addresses",
    "when the connection started and how long it lasted",
    "how many bytes crossed in each direction",
  ]),
  cannotSee: Object.freeze([
    "the contents of anything sent — DTLS is negotiated between the peers, and the relay holds no key for it",
    "the identities behind a quorum link, which are proven under a key the relay never sees",
  ]),
});

/**
 * The list phase one starts from — never a relay, whatever was asked for.
 *
 * The point of the two phases is that the relay is not contacted until it is
 * needed, and "contacted" starts at gathering. A `turn:` entry reaching the
 * constructor defeats the whole arrangement silently: the connection would
 * still work, the relay would still be last in priority, and nothing on screen
 * would change — the allocation just happens on every call. So this strips
 * them rather than trusting callers, and reports what it removed.
 *
 * `rtc.ice turn=` is not overruled by this: an explicitly configured relay is
 * a user asking for one, and goes into a connection built by the ops layer
 * directly. This is the rule for the *automatic* fallback path only, which is
 * why it takes and returns a list rather than reaching for a global.
 *
 * @param {RTCIceServer[] | null | undefined} requested
 * @returns {{ servers: RTCIceServer[], removed: number }}
 */
export function firstPhaseServers(requested) {
  const list = Array.isArray(requested) ? requested : [];
  const servers = [];
  let removed = 0;
  for (const server of list) {
    const urls = (Array.isArray(server?.urls) ? server.urls : [server?.urls])
      .filter((u) => typeof u === "string" && u);
    const kept = urls.filter((u) => !/^turns?:/i.test(u));
    removed += urls.length - kept.length;
    if (!kept.length) continue;
    // Rebuilt rather than mutated: the caller's list may be `DEFAULT_ICE_SERVERS`
    // or a frozen answer, and neither may be edited in place.
    servers.push(kept.length === urls.length ? server : { ...server, urls: kept });
  }
  return { servers, removed };
}

/**
 * The two lists, in the order ICE should try them.
 *
 * Relay entries go last. Not because that is what makes them a fallback — ICE
 * computes priority from candidate *type* and a relay candidate is bottom of
 * that order regardless — but because a reader of the resulting config should
 * see the same shape the connection has.
 *
 * Duplicates are dropped by URL, so a provider that hands back the STUN server
 * already in the base list does not produce a config naming it twice.
 *
 * @param {RTCIceServer[]} base
 * @param {RTCIceServer[]} relay
 * @returns {RTCIceServer[]}
 */
export function withRelayServers(base, relay) {
  const seen = new Set();
  /** @type {RTCIceServer[]} */
  const out = [];
  for (const server of [...(base || []), ...(relay || [])]) {
    const urls = (Array.isArray(server?.urls) ? server.urls : [server?.urls])
      .filter((u) => typeof u === "string" && u);
    const kept = urls.filter((u) => !seen.has(u.toLowerCase()));
    for (const u of kept) seen.add(u.toLowerCase());
    if (!kept.length) continue;
    out.push(kept.length === urls.length ? server : { ...server, urls: kept });
  }
  return out;
}

/**
 * What to do about a link's current state — the whole escalation rule, pure.
 *
 * Pure and exported for the same reason `offerCollisionAction` is: the rule is
 * the interesting part, and "escalates on failure, and only on failure" should
 * be assertable by enumerating every state a connection can be in rather than
 * by racing a real one into each.
 *
 * `failed` on *either* state machine counts. They are not redundant:
 * `connectionState` aggregates ICE with DTLS, and an engine can sit in
 * `connecting` while `iceConnectionState` has already given up — watching only
 * the aggregate would wait out the whole timeout before noticing.
 *
 * @param {{ connectionState?: string, iceConnectionState?: string,
 *   escalated?: boolean }} link
 * @returns {"hold"|"escalate"|"exhausted"}
 */
export function relayFallbackDecision(link) {
  const failed =
    link?.connectionState === "failed" || link?.iceConnectionState === "failed";
  // `disconnected` lands here, and that is the point. It means ICE has lost
  // contact and is still checking; it recovers on its own routinely, and the
  // browser moves it to `failed` when it does not. Treating it as failure
  // would contact a relay for connections that were about to come back.
  if (!failed) return "hold";
  return link?.escalated ? "exhausted" : "escalate";
}

/**
 * Whether a link ended up actually using the relay.
 *
 * Configured, escalated and *used* are three different facts and the UI reports
 * all three separately. A link can escalate and then connect through a
 * reflexive candidate the restart happened to find, in which case the relay
 * allocated and carried nothing.
 *
 * @param {{ via?: string }} row
 * @returns {boolean}
 */
export function relayCarriedTraffic(row) {
  return String(row?.via || "") === "relay";
}

/**
 * Put a relay in front of a live connection and re-run ICE.
 *
 * The two spec-mandated halves, together, in the one place they belong. See
 * the module docstring for the citations: `setConfiguration` alone changes a
 * list nothing reads until the next gathering phase, and `restartIce` alone
 * re-gathers from the list that already failed.
 *
 * @param {RTCPeerConnection|null} pc
 * @param {RTCIceServer[]} baseServers
 * @param {RTCIceServer[]} relayServers
 * @returns {boolean} false on an engine without `setConfiguration`/`restartIce`,
 *   or a connection already gone — never a throw out of a state-change handler.
 */
export function applyRelayServers(pc, baseServers, relayServers) {
  if (!pc || typeof pc.setConfiguration !== "function") return false;
  if (typeof pc.restartIce !== "function") return false;
  const servers = withRelayServers(baseServers || [], relayServers || []);
  if (!iceServerCensus(servers).turn) return false;
  try {
    // Spread the current configuration so the fields that may *not* change on
    // a live connection — `bundlePolicy`, `rtcpMuxPolicy`, and
    // `iceCandidatePoolSize` once a local description exists — are handed back
    // identical. Passing a bare `{ iceServers }` asks the browser to reset them
    // to their defaults, which is an InvalidModificationError on any connection
    // that did not happen to be using them.
    const current =
      typeof pc.getConfiguration === "function" ? pc.getConfiguration() || {} : {};
    pc.setConfiguration({ ...current, iceServers: servers });
    pc.restartIce();
  } catch (_) {
    return false;
  }
  return true;
}

/* ─────────────────────────── consent and source ─────────────────────────── */

/**
 * @typedef {object} RelayFallbackSettings
 * @property {boolean} enabled  the user's answer, not a deployment's
 * @property {(() => Promise<{ iceServers: RTCIceServer[] }>)|null} source
 */

/** @type {RelayFallbackSettings} */
let settings = { enabled: false, source: null };

/**
 * Turn the fallback on, and say where credentials come from.
 *
 * Off, with no source, until something calls this — the shipped state is a page
 * that will never contact a relay. Both halves are required to arm it: consent
 * with no source is a deployment that has no relay to offer, and a source with
 * no consent is a relay the user did not agree to.
 *
 * @param {Partial<RelayFallbackSettings>} patch
 * @returns {RelayFallbackSettings}
 */
export function configureRelayFallback(patch) {
  settings = {
    enabled: !!(patch?.enabled ?? settings.enabled),
    source:
      patch?.source === undefined
        ? settings.source
        : typeof patch.source === "function"
          ? patch.source
          : null,
  };
  return { ...settings };
}

/** @returns {RelayFallbackSettings} */
export function relayFallbackSettings() {
  return { ...settings };
}

/** Test-only, and the reset a page never needs. */
export function __resetRelayFallback() {
  settings = { enabled: false, source: null };
}

/* ───────────────────────────── the supervisor ───────────────────────────── */

/**
 * One link's relay status, as the panel and `rtc.state` read it.
 *
 * @typedef {object} RelayStatus
 * @property {"off"|"armed"|"escalating"|"escalated"|"exhausted"|"unavailable"} phase
 * @property {boolean} configured   a relay is in this connection's list right now
 * @property {number} at            when escalation happened, 0 if it has not
 * @property {string} reason        why `unavailable`, empty otherwise
 */

/**
 * Watch one connection and escalate it once, if it ever genuinely fails.
 *
 * Attached with `addEventListener` rather than by assigning `onconnection‑
 * statechange`: `PeerLink` owns that property and drives the roster through it,
 * and assigning here would silently delete the handler — the mistake
 * `link-registry.js` documents at its own listener.
 */
export class RelayFallback {
  /**
   * @param {RTCPeerConnection|null} pc
   * @param {{ iceServers?: RTCIceServer[], onChange?: () => void }} [opts]
   */
  constructor(pc, opts = {}) {
    /** @type {RTCPeerConnection|null} */
    this.pc = pc || null;
    /**
     * The list phase one ran on — what the relay is added *to*.
     *
     * Read off the connection when a caller does not supply it, so a link
     * registered by a layer that never named its ICE servers still escalates
     * onto the list it was actually built with rather than onto an empty one.
     * `getConfiguration()` is the browser's own record of it.
     */
    this.baseServers = Array.isArray(opts.iceServers)
      ? opts.iceServers
      : (typeof pc?.getConfiguration === "function" && pc.getConfiguration()?.iceServers) || [];
    this._onChange = typeof opts.onChange === "function" ? opts.onChange : () => {};
    const { enabled, source } = relayFallbackSettings();
    this._source = enabled ? source : null;
    /** @type {RelayStatus["phase"]} */
    this.phase = this._source ? "armed" : "off";
    this.at = 0;
    this.reason = "";
    this.escalated = false;
    this._busy = false;
    this._detach = () => {};
    if (!this.pc || !this._source) return;
    if (typeof this.pc.addEventListener !== "function") return;
    const handler = () => {
      void this._react();
    };
    this.pc.addEventListener("connectionstatechange", handler);
    this.pc.addEventListener("iceconnectionstatechange", handler);
    this._detach = () => {
      try {
        this.pc?.removeEventListener?.("connectionstatechange", handler);
        this.pc?.removeEventListener?.("iceconnectionstatechange", handler);
      } catch (_) {
        /* connection already gone */
      }
    };
  }

  /** @returns {RelayStatus} */
  status() {
    return {
      phase: this.phase,
      configured: this.escalated || iceServerCensus(this.baseServers).turn > 0,
      at: this.at,
      reason: this.reason,
    };
  }

  /** Stop watching. Idempotent; safe on a torn-down connection. */
  stop() {
    this._detach();
    this._detach = () => {};
  }

  /**
   * The state handler. Never throws — it runs off a browser event, and an
   * exception here would surface as an unhandled rejection with no connection
   * named in it.
   */
  async _react() {
    const pc = this.pc;
    if (!pc || this._busy) return;
    const decision = relayFallbackDecision({
      connectionState: pc.connectionState,
      iceConnectionState: pc.iceConnectionState,
      escalated: this.escalated,
    });
    if (decision === "hold") return;
    if (decision === "exhausted") {
      // Honest end of the road: the relay is already in the list and the
      // connection failed anyway. Nothing left to try that has not been tried.
      this._set("exhausted", "the relay was added and the connection failed anyway");
      return;
    }
    this._busy = true;
    this._set("escalating", "");
    try {
      const grant = await /** @type {() => Promise<{iceServers: RTCIceServer[]}>} */ (
        this._source
      )();
      const relay = Array.isArray(grant?.iceServers) ? grant.iceServers : [];
      if (!iceServerCensus(relay).turn) {
        this._set("unavailable", "no relay was offered");
        return;
      }
      // `escalated` is set before the apply, not after: whatever happens next,
      // this link has spent its one escalation. A failed apply that left the
      // flag clear would let the next `failed` event try again, which is the
      // loop this class exists to not have.
      this.escalated = true;
      this.at = Date.now();
      if (!applyRelayServers(pc, this.baseServers, relay)) {
        this._set("unavailable", "this engine cannot change ICE servers on a live connection");
        return;
      }
      this.baseServers = withRelayServers(this.baseServers, relay);
      this._set("escalated", "");
    } catch (err) {
      // A credential that cannot be minted is the common case on a deployment
      // with no relay configured, and it is not an error the user did anything
      // about — it is reported as "no relay available", not as a failure.
      this._set("unavailable", err instanceof Error ? err.message : String(err));
    } finally {
      this._busy = false;
    }
  }

  /**
   * @param {RelayStatus["phase"]} phase
   * @param {string} reason
   */
  _set(phase, reason) {
    this.phase = phase;
    this.reason = reason;
    try {
      this._onChange();
    } catch (_) {
      /* one broken watcher must not stop an escalation */
    }
  }
}

/**
 * Arm the fallback for one connection, or return null when it is off.
 *
 * Null rather than an inert instance, so a caller storing it has the same
 * question answered by the same field: no object means no relay will ever be
 * contacted for this link.
 *
 * @param {RTCPeerConnection|null} pc
 * @param {{ iceServers?: RTCIceServer[], onChange?: () => void }} [opts]
 * @returns {RelayFallback|null}
 */
export function armRelayFallback(pc, opts = {}) {
  const { enabled, source } = relayFallbackSettings();
  if (!enabled || !source || !pc) return null;
  return new RelayFallback(pc, opts);
}

/** The status of a link with no supervisor — the shipped state, named. */
export const RELAY_OFF = Object.freeze(
  /** @type {RelayStatus} */ ({ phase: "off", configured: false, at: 0, reason: "" })
);
