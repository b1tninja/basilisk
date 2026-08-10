/**
 * Azure Web PubSub, as far as one hub and a handful of rooms are concerned —
 * in process, for the node suite.
 *
 * The service cannot run here, and the alternative (mocking
 * `lib/notebook/webpubsub.js` away) would only prove the mock agrees with
 * itself. So this stands in at the *socket*: `globalThis.WebSocket` is replaced
 * by a class that speaks the documented `json.webpubsub.azure.v1` frames —
 * joinGroup / leaveGroup / sendToGroup, ack responses, group broadcast, the
 * `connected` system message — and the real client runs unmodified above it.
 * `basilisk/portal/webpubsub_local.py` is the same protocol over a real socket
 * for the browser and dev paths; the two exist for two runtimes, not two
 * protocols.
 *
 * Authorization is **not** stubbed. Each connection's token is verified with
 * WebCrypto against the same key the test minted it with, and its `role`
 * claims are enforced per request — so a token scoped to room A gets
 * `Forbidden` here for the same reason it would from the service. That is what
 * makes the room-scoping test meaningful rather than decorative.
 *
 * @module test/helpers/webpubsub-double
 */

const SUBPROTOCOL = "json.webpubsub.azure.v1";

/** `{"alg":"HS256","typ":"JWT"}`, base64url — the header the server emits. */
const JWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

const b64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const b64urlDecode = (s) =>
  atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

/**
 * Mint a client access token the way `basilisk/portal/webpubsub.py` does.
 * @param {object} opts
 * @param {string} opts.accessKey
 * @param {string} opts.audience   `https://host/client/hubs/<hub>`
 * @param {string} [opts.userId]
 * @param {string[]} [opts.roles]
 * @param {string[]} [opts.groups]
 * @param {number} [opts.lifetimeSec]
 * @returns {Promise<string>}
 */
export async function mintClientAccessToken({
  accessKey,
  audience,
  userId = "test-user",
  roles = [],
  groups = [],
  lifetimeSec = 300,
}) {
  const now = Math.floor(Date.now() / 1000);
  /** @type {Record<string, unknown>} */
  const claims = { sub: userId };
  if (roles.length) claims.role = roles;
  if (groups.length) claims["webpubsub.group"] = groups;
  claims.nbf = now;
  claims.exp = now + lifetimeSec;
  claims.iat = now;
  claims.aud = audience;
  const payload = b64url(new TextEncoder().encode(JSON.stringify(claims)));
  const input = `${JWT_HEADER}.${payload}`;
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(accessKey),
    new TextEncoder().encode(input)
  );
  return `${input}.${b64url(sig)}`;
}

/** The two role strings that scope a connection to one room. */
export const roomRoles = (room) => [
  `webpubsub.joinLeaveGroup.${room}`,
  `webpubsub.sendToGroup.${room}`,
];

/**
 * @param {string} accessKey
 * @param {string} token
 * @returns {Promise<Record<string, any>>}
 */
async function verifyToken(accessKey, token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3 || parts[0] !== JWT_HEADER) throw new Error("bad token");
  const expected = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(accessKey),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  if (b64url(expected) !== parts[2]) throw new Error("bad signature");
  const claims = JSON.parse(b64urlDecode(parts[1]));
  if (Number(claims.exp || 0) < Date.now() / 1000) throw new Error("expired");
  return claims;
}

/**
 * @param {Record<string, any>} claims
 * @param {"joinLeaveGroup"|"sendToGroup"} verb
 * @param {string} group
 */
function permits(claims, verb, group) {
  const roles = Array.isArray(claims.role) ? claims.role : [];
  return roles.includes(`webpubsub.${verb}`) || roles.includes(`webpubsub.${verb}.${group}`);
}

/**
 * Install the double over `globalThis.WebSocket`.
 *
 * @param {object} [opts]
 * @param {string} [opts.accessKey]
 * @param {string} [opts.endpoint]  http(s) origin the grants point at
 * @param {string} [opts.hub]
 * @param {(text: string) => string | Promise<string>} [opts.transform]
 *   Applied to every published payload before it is broadcast. This is the
 *   seam a tamper test needs — the relay is the only place an attacker sits.
 * @returns {{
 *   accessKey: string, endpoint: string, hub: string,
 *   audience: string,
 *   clientUrl: (token: string) => string,
 *   grantFor: (room: string, opts?: { roles?: string[], groups?: string[] }) => Promise<object>,
 *   settled: () => Promise<void>,
 *   restore: () => void,
 * }}
 */
export function installWebPubSubDouble({
  accessKey = "test-access-key",
  endpoint = "https://double.webpubsub.test",
  hub = "quorum",
  transform,
} = {}) {
  const audience = `${endpoint}/client/hubs/${hub}`;
  const clientPath = `/client/hubs/${hub}`;
  const wsOrigin = endpoint.replace(/^http:/, "ws:").replace(/^https:/, "wss:");

  /** @type {Set<FakeWebPubSubSocket>} */
  const sockets = new Set();
  /** Broadcasts are serialised so the order published is the order delivered. */
  let queue = Promise.resolve();

  class FakeWebPubSubSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;

    /**
     * @param {string} url
     * @param {string|string[]} [protocols]
     */
    constructor(url, protocols) {
      const asked = Array.isArray(protocols) ? protocols : [protocols];
      if (!asked.includes(SUBPROTOCOL)) {
        throw new Error(`double: subprotocol ${SUBPROTOCOL} is required`);
      }
      this.url = String(url);
      this.protocol = SUBPROTOCOL;
      this.readyState = 0;
      this.onopen = null;
      this.onclose = null;
      this.onerror = null;
      this.onmessage = null;
      /** @type {Set<string>} */
      this.groups = new Set();
      this.claims = null;
      sockets.add(this);
      void this._handshake();
    }

    async _handshake() {
      try {
        const parsed = new URL(this.url, wsOrigin);
        if (parsed.pathname !== clientPath) throw new Error("unknown hub");
        // Browsers cannot set headers on a WebSocket handshake, so the token
        // is in the query string. Anything else here is a client bug.
        const token = parsed.searchParams.get("access_token") || "";
        this.claims = await verifyToken(accessKey, token);
      } catch (err) {
        this.readyState = 3;
        sockets.delete(this);
        this.onerror?.({ type: "error", message: String(err) });
        this.onclose?.({ type: "close", code: 1008 });
        return;
      }
      this.readyState = 1;
      this.onopen?.({ type: "open" });
      this._deliver({
        type: "system",
        event: "connected",
        userId: this.claims.sub,
        connectionId: `double-${sockets.size}`,
      });
      for (const g of this.claims["webpubsub.group"] || []) {
        if (permits(this.claims, "joinLeaveGroup", g)) this.groups.add(String(g));
      }
    }

    _deliver(message) {
      this.onmessage?.({ data: JSON.stringify(message) });
    }

    _ack(ackId, success, name = "", message = "") {
      if (ackId === undefined || ackId === null) return;
      const body = { type: "ack", ackId, success };
      if (!success) body.error = { name, message };
      this._deliver(body);
    }

    /** @param {string} raw */
    send(raw) {
      if (this.readyState !== 1) throw new Error("double: socket is not open");
      const frame = JSON.parse(String(raw));
      const { type, group, ackId } = frame;

      if (type === "ping") {
        this._deliver({ type: "pong" });
        return;
      }
      if (type === "joinGroup" || type === "leaveGroup") {
        if (!permits(this.claims, "joinLeaveGroup", group)) {
          this._ack(ackId, false, "Forbidden", `no joinLeaveGroup permission for ${group}`);
          return;
        }
        if (type === "joinGroup") this.groups.add(group);
        else this.groups.delete(group);
        this._ack(ackId, true);
        return;
      }
      if (type === "sendToGroup") {
        if (!permits(this.claims, "sendToGroup", group)) {
          this._ack(ackId, false, "Forbidden", `no sendToGroup permission for ${group}`);
          return;
        }
        const dataType = frame.dataType || "json";
        const noEcho = Boolean(frame.noEcho);
        const fromUserId = this.claims.sub;
        queue = queue.then(async () => {
          const data =
            transform && dataType === "text" ? await transform(String(frame.data)) : frame.data;
          for (const sock of [...sockets]) {
            if (sock.readyState !== 1 || !sock.groups.has(group)) continue;
            if (noEcho && sock === this) continue;
            sock._deliver({
              type: "message",
              from: "group",
              group,
              dataType,
              data,
              fromUserId,
            });
          }
        });
        this._ack(ackId, true);
        return;
      }
      this._ack(ackId, false, "InternalServerError", `unsupported request type ${type}`);
    }

    close() {
      if (this.readyState === 3) return;
      this.readyState = 3;
      sockets.delete(this);
      this.onclose?.({ type: "close", code: 1000 });
    }
  }

  const realWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = /** @type {any} */ (FakeWebPubSubSocket);

  return {
    accessKey,
    endpoint,
    hub,
    audience,
    clientUrl: (token) => `${wsOrigin}${clientPath}?access_token=${token}`,
    async grantFor(room, { roles, groups } = {}) {
      const token = await mintClientAccessToken({
        accessKey,
        audience,
        userId: `u-${Math.random().toString(16).slice(2)}`,
        roles: roles || roomRoles(room),
        groups: groups || [room],
      });
      return {
        v: 1,
        room,
        transport: "webpubsub",
        url: `${wsOrigin}${clientPath}?access_token=${token}`,
        protocol: SUBPROTOCOL,
        expires_at: Math.floor(Date.now() / 1000) + 300,
      };
    },
    settled: () => queue,
    /** Drop every live connection, the way a service restart would. */
    dropAll() {
      for (const sock of [...sockets]) sock.close();
    },
    restore() {
      for (const sock of [...sockets]) sock.close();
      sockets.clear();
      globalThis.WebSocket = realWebSocket;
    },
  };
}
