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
import { isValidRoomId } from "./room.js";
import { connectWebPubSub } from "./webpubsub.js";

/** Reconnect backoff, milliseconds. Grants are short-lived, so a reconnect
 *  re-negotiates rather than reusing a URL that may already have expired. */
const RETRY_MS = [1000, 2000, 4000, 8000, 15000];

/**
 * A room-scoped connection grant, in the shape `/api/v1/quorum/negotiate`
 * promises. `transport` names which protocol `url`/`protocol` belong to; it is
 * the one field a second provider would change.
 *
 * @typedef {object} SignalingGrant
 * @property {number} v
 * @property {string} room
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
 * @param {string} roomId
 * @returns {Promise<SignalingGrant>}
 */
export async function negotiateSignaling(roomId) {
  const rid = String(roomId || "")
    .trim()
    .toUpperCase();
  if (!isValidRoomId(rid)) throw new Error("Invalid room id");
  const headers = await proofHeaders();
  return fetchJson("/api/v1/quorum/negotiate", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ room: rid }),
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
    group: grant.room,
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
 * Join a room and stay joined.
 *
 * Reconnects on an unexpected close — the grant is minutes long by design, and
 * a mesh that renegotiates ICE an hour in still needs a way back to the relay.
 * Each attempt negotiates afresh, because the old URL's token has a shorter
 * life than the session does.
 *
 * @param {object} opts
 * @param {string} opts.roomId
 * @param {(payload: string) => void | Promise<void>} opts.onMessage
 * @param {(err: Error) => void} [opts.onError]
 * @param {(status: string) => void} [opts.onStatus]
 * @returns {SignalingChannel}
 */
export function openSignalingChannel({ roomId, onMessage, onError, onStatus }) {
  const rid = String(roomId || "")
    .trim()
    .toUpperCase();
  if (!isValidRoomId(rid)) throw new Error("Invalid room id");

  let stopped = false;
  let attempt = 0;
  /** @type {ReturnType<typeof connectGrant> | null} */
  let connection = null;
  /** @type {ReturnType<typeof setTimeout> | null} */
  let retryTimer = null;

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

  async function open() {
    if (stopped) return;
    try {
      const grant = await negotiateSignaling(rid);
      if (stopped) return;
      const conn = connectGrant(grant, {
        onMessage: (/** @type {string} */ payload) => {
          void onMessage?.(payload);
        },
        onError,
        onStatus,
        onClose: () => {
          if (connection === conn) connection = null;
          if (!stopped) {
            onStatus?.("Signalling dropped — reconnecting…");
            scheduleRetry();
          }
        },
      });
      connection = conn;
      await conn.ready;
      if (stopped) {
        conn.close();
        return;
      }
      attempt = 0;
      markReady();
    } catch (err) {
      const wrapped = err instanceof Error ? err : new Error(String(err));
      onError?.(wrapped);
      // Only the first attempt can fail `ready`; after that the caller has
      // already been told the room is live and a drop is a reconnect, not a
      // failure to start.
      markFailed(wrapped);
      scheduleRetry();
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
      const conn = connection;
      if (!conn) throw new Error("quorum: signalling channel is reconnecting");
      await conn.send(String(payload));
    },
    stop() {
      stopped = true;
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      connection?.close();
      connection = null;
    },
  };
}
