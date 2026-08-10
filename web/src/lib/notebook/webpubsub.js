/**
 * The Azure Web PubSub client protocol — the only module in the portal that
 * knows the vendor.
 *
 * A **plain browser `WebSocket`** speaks `json.webpubsub.azure.v1`; there is no
 * npm dependency here and none is needed. Everything Azure-shaped is inside
 * this file: the subprotocol name, the `joinGroup`/`sendToGroup` frames, the
 * ack contract, and the fact that the token rides in the query string (a
 * browser cannot set headers on a WebSocket handshake).
 *
 * `signaling.js` above it deals in *rooms*, and nothing further up — not the
 * session, not `quorum-ops.js`, not the mount — contains the string
 * `webpubsub`. A second provider is a sibling of this file.
 *
 * Frame shapes are from the service reference for the subprotocol, not from
 * memory:
 *   · `{type:"joinGroup", group, ackId}` / `{type:"leaveGroup", group, ackId}`
 *   · `{type:"sendToGroup", group, ackId, dataType:"text", data}`
 *   · ack: `{type:"ack", ackId, success, error:{name:"Forbidden|InternalServerError|Duplicate"}}`
 *   · group message: `{type:"message", from:"group", group, dataType, data, fromUserId}`
 *   · `{type:"system", event:"connected"|"disconnected", …}`
 *
 * `noEcho` is deliberately not sent. It is a newer field, the service declines
 * a client whose frame it cannot parse, and the caller already ignores traffic
 * it signed itself — so the field would buy nothing and could cost the whole
 * connection on an older service version.
 *
 * @module lib/notebook/webpubsub
 */

/** The subprotocol string a `new WebSocket(url, …)` must ask for. */
export const WEBPUBSUB_SUBPROTOCOL = "json.webpubsub.azure.v1";

/** How long to wait for an ack before treating the request as lost. */
const ACK_TIMEOUT_MS = 15000;

/**
 * @typedef {object} WebPubSubConnection
 * @property {Promise<void>} ready  resolves once the room is joined
 * @property {(text: string) => Promise<void>} send  publish to the room
 * @property {() => void} close
 */

/**
 * @param {object} opts
 * @param {string} opts.url         client access URL, token already in the query
 * @param {string} [opts.protocol]  subprotocol from the grant
 * @param {string} opts.group       the room
 * @param {(text: string, meta: { fromUserId?: string }) => void} opts.onMessage
 * @param {(err: Error) => void} [opts.onError]
 * @param {(status: string) => void} [opts.onStatus]
 * @param {() => void} [opts.onClose]  the socket ended; the caller decides whether to reconnect
 * @param {typeof WebSocket} [opts.WebSocketImpl]  injected in tests
 * @returns {WebPubSubConnection}
 */
export function connectWebPubSub({
  url,
  protocol = WEBPUBSUB_SUBPROTOCOL,
  group,
  onMessage,
  onError,
  onStatus,
  onClose,
  WebSocketImpl,
}) {
  const WS =
    WebSocketImpl ||
    (typeof WebSocket === "function" ? WebSocket : null);
  if (!WS) throw new Error("notebook: WebSocket is unavailable in this context");

  const socket = new WS(url, protocol);
  /** @type {Map<number, { resolve: () => void, reject: (e: Error) => void, timer: ReturnType<typeof setTimeout> }>} */
  const pending = new Map();
  let nextAckId = 1;
  let closed = false;

  /** Settle every outstanding ack — a dead socket will never answer them. */
  const failPending = (err) => {
    for (const [, waiter] of pending) {
      clearTimeout(waiter.timer);
      waiter.reject(err);
    }
    pending.clear();
  };

  /**
   * Send a frame and wait for its ack.
   * @param {Record<string, unknown>} frame
   * @returns {Promise<void>}
   */
  const request = (frame) =>
    new Promise((resolve, reject) => {
      if (closed || socket.readyState !== 1 /* OPEN */) {
        reject(new Error("notebook: signalling socket is not open"));
        return;
      }
      // `ackId` is a uint64 unique within the connection; the service treats a
      // repeat as the same message and answers `Duplicate` rather than
      // brokering it twice, which is what makes a retry safe.
      const ackId = nextAckId++;
      const timer = setTimeout(() => {
        pending.delete(ackId);
        reject(new Error(`notebook: no ack for ${frame.type} within ${ACK_TIMEOUT_MS}ms`));
      }, ACK_TIMEOUT_MS);
      pending.set(ackId, { resolve, reject, timer });
      try {
        socket.send(JSON.stringify({ ...frame, ackId }));
      } catch (err) {
        clearTimeout(timer);
        pending.delete(ackId);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });

  const ready = new Promise((resolve, reject) => {
    socket.onopen = () => {
      onStatus?.("Signalling connected");
      // The token already carries `webpubsub.group`, so the service joins on
      // connect. Asking anyway costs one frame and makes the join *observable*
      // — a token scoped to another room fails here, loudly, instead of
      // presenting as a room where nobody ever speaks.
      request({ type: "joinGroup", group }).then(resolve, reject);
    };
    socket.onerror = () => {
      // The browser deliberately withholds the reason for a failed WebSocket
      // handshake, so there is nothing to report but the fact.
      const err = new Error("notebook: signalling socket error");
      onError?.(err);
      reject(err);
    };
  });
  // A rejected `ready` that nobody has awaited yet is an unhandled rejection.
  // The caller gets the same error through `onError`, so absorb it here.
  ready.catch(() => {});

  socket.onmessage = (ev) => {
    let msg;
    try {
      msg = JSON.parse(String(ev?.data ?? ""));
    } catch (_) {
      return; // not our protocol — the service never sends non-JSON here
    }
    if (!msg || typeof msg !== "object") return;

    if (msg.type === "ack") {
      const waiter = pending.get(msg.ackId);
      if (!waiter) return;
      pending.delete(msg.ackId);
      clearTimeout(waiter.timer);
      // `Duplicate` means the service already brokered this exact request —
      // the outcome the caller wanted, reached by an earlier attempt.
      if (msg.success || msg.error?.name === "Duplicate") waiter.resolve();
      else {
        waiter.reject(
          new Error(
            `notebook: ${msg.error?.name || "request failed"}${
              msg.error?.message ? ` — ${msg.error.message}` : ""
            }`
          )
        );
      }
      return;
    }

    if (msg.type === "message" && msg.from === "group") {
      // Signalling envelopes are armored text and go on the wire as `text`.
      // A `json` payload would arrive parsed, so stringify rather than assume.
      const data = typeof msg.data === "string" ? msg.data : JSON.stringify(msg.data);
      onMessage?.(data, { fromUserId: msg.fromUserId });
      return;
    }

    if (msg.type === "system") {
      if (msg.event === "disconnected") {
        onStatus?.(`Signalling closed: ${msg.message || "by the service"}`);
      }
    }
  };

  socket.onclose = () => {
    failPending(new Error("notebook: signalling socket closed"));
    if (!closed) {
      closed = true;
      onClose?.();
    }
  };

  return {
    ready,
    async send(text) {
      await ready;
      await request({ type: "sendToGroup", group, dataType: "text", data: String(text) });
    },
    close() {
      if (closed) return;
      closed = true;
      try {
        // Best-effort and unawaited: the socket is going away either way, and
        // the service drops the membership with the connection.
        if (socket.readyState === 1) {
          socket.send(JSON.stringify({ type: "leaveGroup", group }));
        }
      } catch (_) {
        /* already gone */
      }
      failPending(new Error("notebook: signalling closed"));
      try {
        socket.close();
      } catch (_) {
        /* already gone */
      }
    },
  };
}
