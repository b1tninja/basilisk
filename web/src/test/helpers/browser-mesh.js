/**
 * Two browsers, a real signalling hub, and a room they can both reach.
 *
 * This is the arrangement `quorum-key-confirmation.e2e.js` assembled inline and
 * `placed-journey.e2e.js` needs an identical copy of: `openPeers` for the pages,
 * `startLocalHub` for the relay, `createQuorumRoom` for the keyserver and the
 * envelope record, and the three-way wiring that makes them one system. It moved
 * here the moment a second caller existed, for the reason this repo states
 * everywhere it has paid for the alternative — a second copy agrees until the
 * first case only one of them learns about, and the two then disagree about what
 * "the peers meshed" means.
 *
 * Nothing about the arrangement changed in the move. What follows is the note
 * that was on it in its old home, because every line of it is still the reason:
 *
 * > The order matters and is the awkward part. The token's audience is the
 * > origin the page dials, which is the dist server's — so the server has to
 * > exist before the connection string can be written, and the hub has to exist
 * > before a grant can name a port. Nothing negotiates until the session opens,
 * > so filling `state` after `openPeers` is in time.
 * >
 * > `routes` answers negotiate itself rather than proxying Flask: the real
 * > endpoint is gated by proof-of-work and two rate limits that have nothing to
 * > do with what either suite is about, and minting the grant here keeps the
 * > subject the session rather than the portal.
 *
 * @module test/helpers/browser-mesh
 */

import { openPeers } from "./browser-peers.js";
import { connectionFor, startLocalHub } from "./webpubsub-hub.js";
import { mintClientAccessToken, roomRoles } from "./webpubsub-double.js";

/**
 * Open the pages and the hub, and wire signalling between them.
 *
 * @param {Awaited<ReturnType<typeof import("./quorum-room.js").createQuorumRoom>>} room
 * @param {{ count?: number }} [opts]
 * @returns {Promise<
 *   | { ok: true, fx: import("./browser-peers.js").PeerFixture, close: () => Promise<void> }
 *   | { ok: false, reason: string, kind: ""|"absent"|"broken" }
 * >}
 */
export async function openMesh(room, opts = {}) {
  const { count = 2 } = opts;
  const accessKey = "browser-suite-access-key";
  const hubName = "notebook";
  /** @type {{ port: number|null, origin: string }} */
  const state = { port: null, origin: "" };

  const routes = (req, res) => {
    const [path] = (req.url || "/").split("?");
    if (path === "/api/v1/notebook/negotiate") {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", async () => {
        const parsed = JSON.parse(body || "{}");
        const group = String(parsed.key || parsed.room || "").toUpperCase();
        const token = await mintClientAccessToken({
          accessKey,
          audience: `${state.origin}/client/hubs/${hubName}`,
          userId: `peer-${Math.random().toString(36).slice(2, 8)}`,
          roles: roomRoles(group),
        });
        const url = `${state.origin.replace(/^http/, "ws")}/client/hubs/${hubName}?access_token=${token}`;
        const grant = {
          v: 1,
          room: String(parsed.room || "").toUpperCase(),
          group,
          scope: parsed.key ? "room" : "lobby",
          transport: "webpubsub",
          url,
          protocol: "json.webpubsub.azure.v1",
          expires_at: Math.floor(Date.now() / 1000) + 300,
        };
        const payload = JSON.stringify(grant);
        res.writeHead(200, {
          "content-type": "application/json",
          "content-length": String(Buffer.byteLength(payload)),
        });
        res.end(payload);
      });
      return true;
    }
    return room.routes(req, res);
  };

  /**
   * Every signalling envelope, on its way to the hub.
   *
   * The room used to see these as mailbox POSTs, which is where its `tamper`
   * hook and its record of what was signalled both lived. Signalling is a
   * WebSocket now, so the frames are handed to the same function instead —
   * `intercept` opens, records, rewrites and re-seals under the signer's own
   * key exactly as before. The hub rebroadcasts whatever it receives, so
   * rewriting on the way in *is* a relay rewriting in flight.
   *
   * Frames that are not a `sendToGroup` carrying text, and envelopes the room
   * leaves alone, are returned unchanged so the tunnel forwards the original
   * bytes.
   */
  const onSignal = async (text) => {
    /** @type {any} */
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return text;
    }
    if (msg?.type !== "sendToGroup" || typeof msg.data !== "string") return text;
    const out = await room.intercept(msg.data);
    return out === msg.data ? text : JSON.stringify({ ...msg, data: out });
  };

  const fx = await openPeers({
    path: "/toolkit",
    count,
    routes,
    upgrade: () => state.port,
    onSignal,
  });
  state.origin = fx.origin;

  const started = await startLocalHub({
    connection: connectionFor(fx.origin, accessKey),
    hub: hubName,
  });
  if (!started.ok) {
    await fx.close();
    return { ok: false, reason: started.reason, kind: started.kind };
  }
  state.port = started.hub.port;
  return {
    ok: true,
    fx,
    close: async () => {
      await started.hub.stop();
      await fx.close();
    },
  };
}
