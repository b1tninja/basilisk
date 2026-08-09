/**
 * Quorum signalling — an opaque relay for sealed envelopes, in room terms.
 *
 * This module is the seam. Above it (`session.js`, `quorum-ops.js`,
 * `quorum-mount.js`) the vocabulary is *join a room, send to the room, receive
 * from the room*; below it lives one provider's protocol. A grep for the
 * vendor's name lands in `webpubsub.js` and nowhere else.
 *
 * **What replaced the mailbox.** Signalling used to be a POST-and-poll against
 * a process-global dict on the server. On Consumption Functions there is no
 * shared memory between instances, so two peers only ever met when they
 * happened to hit the same warm worker — and anyone could post to any room.
 * Now the server mints a grant scoped to one room and the state lives in the
 * signalling service. There is no fallback path: one transport, one protocol.
 *
 * The envelope is sealed end to end by `crypto.js` either way, so the relay
 * carries nothing it can read or alter — which is why swapping the wire under
 * it is a transport change and not a protocol change.
 *
 * @module lib/quorum/signaling
 */

import { fetchJson } from "../utils.js";
import { proofHeaders } from "../proof.js";
import { isValidRoomId, isValidRoomKey } from "./room.js";
import { connectWebPubSub } from "./webpubsub.js";

/** Reconnect backoff, milliseconds. Grants are short-lived, so a reconnect
 *  re-negotiates rather than reusing a URL that may already have expired. */
const RETRY_MS = [1000, 2000, 4000, 8000, 15000];

/**
 * Fraction of a grant's remaining life after which the connection is thrown
 * away and re-made.
 *
 * **Why the connection has to be recycled at all.** A grant's expiry is
 * checked when a connection is *made* and never again — the service does not
 * hang up on a connection whose token has since expired. So a token gates the
 * handshake and nothing after it, and a peer that authenticated once is
 * present for as long as it cares to hold the socket open. Recycling converts
 * "authenticated once, present forever" into "membership re-asserted every
 * cycle", which is the whole reason withholding a token can take effect at
 * all: the room is left by not being re-entered.
 *
 * **Why a fraction of the grant rather than a constant.** The server states
 * the lifetime it is willing to grant (`expires_at`); the cycle follows it,
 * so changing `BASILISK_WEBPUBSUB_TOKEN_TTL_SEC` changes the cycle without a
 * second knob that can disagree with the first. At the shipped 300 s TTL this
 * is a four-minute cycle.
 *
 * **Why less than 1.0.** The re-open happens while the grant that authorised
 * the *current* connection is still valid, so a re-negotiation that fails has
 * room to retry on a connection that still works. Recycling at expiry would
 * make every cycle a race the client loses quietly.
 *
 * A fresh negotiate means a fresh proof of work. That cost is the point: it is
 * what makes a lurker's presence a recurring expense rather than a one-off.
 */
const RECYCLE_FRACTION = 0.8;

/** Never churn faster than this, whatever a grant claims. */
const MIN_RECYCLE_MS = 5000;

/** Assumed grant life when the server did not state one. */
const DEFAULT_GRANT_MS = 300000;

/**
 * @param {{ expires_at?: number }} grant
 * @param {number} [override] explicit cycle in ms, for tests and callers that
 *   have a reason to be shorter than the grant
 * @returns {number}
 */
function recycleDelayMs(grant, override) {
  if (Number(override) > 0) return Math.max(1000, Number(override));
  const expiresAt = Number(grant?.expires_at) * 1000;
  const life =
    Number.isFinite(expiresAt) && expiresAt > Date.now()
      ? expiresAt - Date.now()
      : DEFAULT_GRANT_MS;
  return Math.max(MIN_RECYCLE_MS, Math.round(life * RECYCLE_FRACTION));
}

/**
 * A room-scoped connection grant, in the shape `/api/v1/quorum/negotiate`
 * promises. `transport` names which protocol `url`/`protocol` belong to; it is
 * the one field a second provider would change.
 *
 * @typedef {object} SignalingGrant
 * @property {number} v
 * @property {string} room
 * @property {string} [group]  what the connection may join; `room` when absent
 * @property {string} [scope]  `"lobby"` or `"room"`
 * @property {string} transport
 * @property {string} url
 * @property {string} protocol
 * @property {number} expires_at
 */

/**
 * Ask the server for a grant for one room.
 *
 * The proof-of-work header rides along because this endpoint is gated the way
 * the upload routes are — the mailbox it replaced was gated by nothing at all.
 *
 * Sending the room **key** asks for the group where signalling is broadcast;
 * sending only the id asks for that room's lobby, which is all a caller who
 * merely guessed a code can have. The key is the room digest in full and the
 * id is its first 80 bits, so the server can bind the two without learning
 * anything about the audience that produced them.
 *
 * @param {string} roomId
 * @param {{ roomKey?: string }} [opts]
 * @returns {Promise<SignalingGrant>}
 */
export async function negotiateSignaling(roomId, opts = {}) {
  const rid = String(roomId || "")
    .trim()
    .toUpperCase();
  if (!isValidRoomId(rid)) throw new Error("Invalid room id");
  const key = String(opts.roomKey || "")
    .trim()
    .toUpperCase();
  if (key && !isValidRoomKey(key)) throw new Error("Invalid room key");
  if (key && !key.startsWith(rid)) {
    throw new Error("Room key does not match room id");
  }
  const headers = await proofHeaders();
  return fetchJson("/api/v1/quorum/negotiate", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(key ? { room: rid, key } : { room: rid }),
  });
}

/**
 * Open the connection a grant describes.
 * @param {SignalingGrant} grant
 * @param {object} handlers
 */
function connectGrant(grant, handlers) {
  if (grant?.transport !== "webpubsub") {
    // Named rather than guessed: a grant this build cannot honour is a
    // deployment mismatch, and silently trying anyway would fail as "the peer
    // never answered" a layer away from the cause.
    throw new Error(
      `quorum: unsupported signalling transport ${JSON.stringify(grant?.transport ?? null)}`
    );
  }
  return connectWebPubSub({
    url: grant.url,
    protocol: grant.protocol,
    // `group` is what the grant actually authorised. It falls back to `room`
    // for a grant minted before the two were distinguished, where the room id
    // *was* the group name.
    group: grant.group || grant.room,
    ...handlers,
  });
}

/**
 * @typedef {object} SignalingChannel
 * @property {Promise<void>} ready       resolves once the room is joined
 * @property {(payload: string) => Promise<void>} send
 * @property {() => void} stop
 */

/**
 * Join a room and keep re-joining it.
 *
 * Reconnects on an unexpected close — the grant is minutes long by design, and
 * a mesh that renegotiates ICE an hour in still needs a way back to the relay.
 * Each attempt negotiates afresh, because the old URL's token has a shorter
 * life than the session does.
 *
 * It also reconnects on a **timer**, which is the part that makes the grant's
 * expiry mean something. See `RECYCLE_FRACTION`. The replacement is opened and
 * joined *before* the connection it replaces is closed, so no window exists in
 * which the room is unattended and a broadcast could be missed. The cost is a
 * second connection for the length of one handshake, which counts against the
 * signalling tier's concurrency ceiling; a room at the ceiling is at it either
 * way, and losing an invite is worse than briefly counting twice.
 *
 * @param {object} opts
 * @param {string} opts.roomId
 * @param {string} [opts.roomKey]  full room digest — asks for the signalling
 *   group rather than the lobby
 * @param {number} [opts.recycleMs]  override the cycle; the grant's own
 *   lifetime decides it otherwise
 * @param {(payload: string) => void | Promise<void>} opts.onMessage
 * @param {(err: Error) => void} [opts.onError]
 * @param {(status: string) => void} [opts.onStatus]
 * @returns {SignalingChannel}
 */
export function openSignalingChannel({
  roomId,
  roomKey,
  recycleMs,
  onMessage,
  onError,
  onStatus,
}) {
  const rid = String(roomId || "")
    .trim()
    .toUpperCase();
  if (!isValidRoomId(rid)) throw new Error("Invalid room id");

  /**
   * One connection and whether it was replaced on purpose. A retired
   * connection's close is the expected end of a cycle; any other close is a
   * drop and starts the retry ladder.
   * @typedef {{ conn: ReturnType<typeof connectGrant>, grant: SignalingGrant, retired: boolean }} Leg
   */

  let stopped = false;
  let attempt = 0;
  let opening = false;
  /** @type {Leg | null} */
  let live = null;
  /** @type {ReturnType<typeof setTimeout> | null} */
  let retryTimer = null;
  /** @type {ReturnType<typeof setTimeout> | null} */
  let recycleTimer = null;

  /** Resolves on the first successful join; later reconnects are silent. */
  let markReady = () => {};
  let markFailed = (/** @type {Error} */ _err) => {};
  const ready = new Promise((resolve, reject) => {
    markReady = () => resolve(undefined);
    markFailed = reject;
  });
  ready.catch(() => {});

  const scheduleRetry = () => {
    if (stopped || retryTimer) return;
    const delay = RETRY_MS[Math.min(attempt, RETRY_MS.length - 1)];
    attempt += 1;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      void open();
    }, delay);
  };

  /** @param {SignalingGrant} grant */
  const scheduleRecycle = (grant) => {
    if (recycleTimer) clearTimeout(recycleTimer);
    recycleTimer = setTimeout(() => {
      recycleTimer = null;
      if (stopped) return;
      onStatus?.("Re-asserting signalling membership…");
      void open();
    }, recycleDelayMs(grant, recycleMs));
  };

  /**
   * Negotiate, connect, and wait until the group is actually joined.
   * @returns {Promise<Leg>}
   */
  async function dial() {
    const grant = await negotiateSignaling(rid, { roomKey });
    if (stopped) throw new Error("quorum: signalling channel is closed");
    /** @type {Leg} */
    const leg = /** @type {any} */ ({ conn: null, grant, retired: false });
    leg.conn = connectGrant(grant, {
      onMessage: (/** @type {string} */ payload) => {
        void onMessage?.(payload);
      },
      onError,
      onStatus,
      onClose: () => {
        if (leg.retired) return; // we replaced it; this close is the plan
        if (live === leg) live = null;
        if (!stopped) {
          onStatus?.("Signalling dropped — reconnecting…");
          scheduleRetry();
        }
      },
    });
    await leg.conn.ready;
    return leg;
  }

  /**
   * Make a connection the live one, retiring whatever held that role.
   *
   * This is one path for three callers — the first join, a reconnect after a
   * drop, and the recycle timer — because all three want the same thing: a
   * freshly granted connection, joined, with nothing stale left behind. A
   * dial that fails leaves the previous connection untouched and in place.
   */
  async function open() {
    if (stopped || opening) return;
    opening = true;
    try {
      const leg = await dial();
      if (stopped) {
        leg.conn.close();
        return;
      }
      const previous = live;
      live = leg;
      if (previous && previous !== leg) {
        previous.retired = true;
        previous.conn.close();
      }
      attempt = 0;
      if (retryTimer) {
        // A retry queued by an earlier failure would build a second
        // connection and retire this one for nothing.
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      markReady();
      scheduleRecycle(leg.grant);
    } catch (err) {
      const wrapped = err instanceof Error ? err : new Error(String(err));
      onError?.(wrapped);
      // Only the first attempt can fail `ready`; after that the caller has
      // already been told the room is live and a drop is a reconnect, not a
      // failure to start.
      markFailed(wrapped);
      scheduleRetry();
    } finally {
      opening = false;
    }
  }

  void open();

  return {
    ready,
    async send(payload) {
      if (stopped) throw new Error("quorum: signalling channel is closed");
      // Awaited rather than checked: a send that lands during a reconnect
      // should wait for the socket, not fail because it arrived early.
      await ready;
      const leg = live;
      if (!leg) throw new Error("quorum: signalling channel is reconnecting");
      await leg.conn.send(String(payload));
    },
    stop() {
      stopped = true;
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      if (recycleTimer) {
        clearTimeout(recycleTimer);
        recycleTimer = null;
      }
      if (live) {
        live.retired = true;
        live.conn.close();
      }
      live = null;
    },
  };
}
