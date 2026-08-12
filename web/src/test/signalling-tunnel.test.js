/**
 * The signalling tunnel cannot lose an envelope quietly.
 *
 * `serveDist` forwards the page's WebSocket upgrade to the local hub, and when
 * a caller supplies `onSignal` it reads each client frame on the way through.
 * That hook is the seam a *tamper* sits in: `quorum-key-confirmation.e2e.js`
 * rewrites one DTLS fingerprint there and proves key confirmation refuses it.
 *
 * Which makes the failure mode specific and nasty. A frame the tunnel could not
 * read used to be forwarded with no record — the peers still meshed, the
 * envelope still crossed, and only the *observation* was gone. The room then
 * counted one fewer envelope and the tamper was simply never applied, so a
 * security test could report a refusal it had not provoked. Nothing said so.
 *
 * Two frames do it, and both are exercised here against the real tunnel rather
 * than a description of it:
 *
 * - a **fragmented** text message (`fin=0`, then continuations), which the
 *   reader cannot hand over whole;
 * - an `onSignal` that **throws**, whose `.catch` forwarded the original and
 *   dropped the error with it.
 *
 * Both are dormant today — Chromium does not fragment below about 128 KB and
 * the largest envelope in that suite is ~2 KB — so this is not a fix aimed at a
 * live bug. It removes the ability to be silently wrong, and these are the two
 * tests that would notice if it came back.
 *
 * Node-only: a raw socket speaking the frame format, and a stub hub. No
 * browser, so it belongs in the fast suite where CI actually runs it.
 */
import { createServer } from "node:net";
import { connect } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { serveDist } from "./helpers/browser-peers.js";

/** The dist root is irrelevant here — nothing fetches a file. */
const ROOT = new URL(".", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

/** @type {(() => Promise<void>)[]} */
let cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.reverse()) await fn().catch(() => {});
  cleanup = [];
});

/**
 * A stand-in for the local hub: accepts the upgrade, answers 101, and records
 * every byte the tunnel forwards. The tunnel copies the handshake verbatim, so
 * this only has to be a WebSocket server to the extent the handshake needs.
 */
async function stubHub() {
  /** @type {Buffer[]} */
  const received = [];
  const server = createServer((socket) => {
    let handshaken = false;
    socket.on("data", (chunk) => {
      if (!handshaken) {
        handshaken = true;
        socket.write(
          "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        );
        return;
      }
      received.push(chunk);
    });
    socket.on("error", () => {});
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", () => r(undefined)));
  const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
  cleanup.push(
    () =>
      new Promise((r) => {
        server.close(() => r(undefined));
      })
  );
  return { port, bytes: () => Buffer.concat(received) };
}

/** One masked client frame, built by hand so the fragmentation bits are ours. */
function clientFrame(opcode, payload, fin = true) {
  const body = Buffer.from(payload, "utf8");
  const head = Buffer.from([(fin ? 0x80 : 0x00) | opcode, 0x80 | body.length]);
  const mask = Buffer.from([1, 2, 3, 4]);
  const masked = Buffer.alloc(body.length);
  for (let i = 0; i < body.length; i += 1) masked[i] = body[i] ^ mask[i % 4];
  return Buffer.concat([head, mask, masked]);
}

/**
 * Open the tunnel, upgrade through it, and hand back a socket to write frames
 * on. `onSignal` is whatever the test wants to prove about.
 */
async function tunnel(onSignal) {
  const hub = await stubHub();
  const server = await serveDist(ROOT, null, () => hub.port, onSignal);
  cleanup.push(() => server.close());
  const url = new URL(server.origin);
  const socket = connect(Number(url.port), url.hostname);
  cleanup.push(async () => socket.destroy());
  await new Promise((r) => socket.once("connect", () => r(undefined)));
  socket.write(
    `GET /ws HTTP/1.1\r\nHost: ${url.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
      "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\n\r\n"
  );
  await new Promise((r) => socket.once("data", () => r(undefined)));
  return { socket, server, hub };
}

/** Frames are forwarded asynchronously through a promise chain. */
const settle = () => new Promise((r) => setTimeout(r, 120));

describe("the signalling tunnel", () => {
  it("intercepts a whole text frame, and records no fault for it", async () => {
    // The ordinary path, asserted first so the two below are a difference and
    // not just a pair of failures.
    /** @type {string[]} */
    const seen = [];
    const { socket, server, hub } = await tunnel(async (text) => {
      seen.push(text);
      return text;
    });
    socket.write(clientFrame(0x1, '{"type":"sendToGroup"}'));
    await settle();

    expect(seen).toEqual(['{"type":"sendToGroup"}']);
    expect(server.tunnelFaults()).toEqual([]);
    expect(hub.bytes().length).toBeGreaterThan(0);
  });

  it("records a fault for a fragmented text message rather than passing it on unseen", async () => {
    /** @type {string[]} */
    const seen = [];
    const { socket, server, hub } = await tunnel(async (text) => {
      seen.push(text);
      return text;
    });
    // `fin=0` opens the message; opcode 0 continues it. Neither can be shown
    // to the hook whole, and both used to be forwarded without a word.
    socket.write(clientFrame(0x1, '{"type":"sendTo', false));
    socket.write(clientFrame(0x0, 'Group"}', true));
    await settle();

    expect(seen, "a fragment must not be handed over as if it were a message").toEqual([]);
    const faults = server.tunnelFaults();
    expect(faults).toHaveLength(2);
    for (const f of faults) expect(f).toMatch(/uninterceptable frame/);
    // Still forwarded: the point is that the run reaches its assertions and
    // fails on the fault, not that the peers die mid-handshake.
    expect(hub.bytes().length).toBeGreaterThan(0);
  });

  it("records a fault when the hook throws, instead of swallowing it", async () => {
    const { socket, server, hub } = await tunnel(async () => {
      throw new Error("the relay could not open this");
    });
    socket.write(clientFrame(0x1, '{"type":"sendToGroup"}'));
    await settle();

    expect(server.tunnelFaults()).toEqual([
      "onSignal threw: the relay could not open this",
    ]);
    // The original frame goes on, so a thrown hook is a recorded fault and not
    // a peer that never answered — which is the harder failure to read.
    expect(hub.bytes().length).toBeGreaterThan(0);
  });

  it("forwards control frames without calling them faults", async () => {
    // Close, ping and pong carry no signalling. Treating them as losses would
    // make the fault list noise, and a noisy guard is one people stop reading.
    /** @type {string[]} */
    const seen = [];
    const { socket, server } = await tunnel(async (text) => {
      seen.push(text);
      return text;
    });
    socket.write(clientFrame(0x9, ""));
    socket.write(clientFrame(0xa, ""));
    await settle();

    expect(seen).toEqual([]);
    expect(server.tunnelFaults()).toEqual([]);
  });
});
