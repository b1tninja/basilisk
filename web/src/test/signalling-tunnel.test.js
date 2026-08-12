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
 * A **fragmented** text message was the first way in, and it is now reassembled
 * rather than merely reported: the fragments are held, joined, and shown to the
 * hook as one message. Chromium does not fragment below about 128 KB and the
 * largest envelope measured in that suite is ~2 KB, so this is not a live bug
 * today — but a placed-run handoff carries a cell's produced values and a
 * manifest cell can carry an armored key, and the gap between 2 KB and 128 KB is
 * smaller than it sounds.
 *
 * The fault is what reassembly *cannot* handle, and stays for exactly that: a
 * continuation with nothing open, a message interrupted by another, a binary
 * frame, a close or a disconnect mid-message, and a hook that throws. Every one
 * of them still forwards the bytes — the peers keep meshing and the run fails on
 * an assertion rather than on a dead peer — but none of them is silent any more.
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

  it("reassembles a fragmented text message and shows the hook the whole thing", async () => {
    /** @type {string[]} */
    const seen = [];
    const { socket, server, hub } = await tunnel(async (text) => {
      seen.push(text);
      return text;
    });
    // `fin=0` opens the message; opcode 0 continues it; `fin=1` ends it. Three
    // fragments rather than two, so "joined in order" is a real claim and not
    // a coincidence of concatenating a pair.
    socket.write(clientFrame(0x1, '{"type":"sendTo', false));
    socket.write(clientFrame(0x0, 'Group","data":"', false));
    socket.write(clientFrame(0x0, 'abc"}', true));
    await settle();

    expect(seen).toEqual(['{"type":"sendToGroup","data":"abc"}']);
    expect(server.tunnelFaults()).toEqual([]);
    // Unchanged, so the client's own frames go on byte for byte — the hub sees
    // what it would have seen with no tunnel in the way.
    expect(hub.bytes().length).toBeGreaterThan(0);
  });

  it("holds nothing back when a control frame lands between fragments", async () => {
    // RFC 6455 §5.4 lets a ping arrive in the middle of a fragmented message,
    // and it is the case people get wrong: treat it as a continuation and the
    // message is corrupt; buffer it and the keepalive never arrives. It goes
    // straight on, and the message still reassembles around it.
    /** @type {string[]} */
    const seen = [];
    const { socket, server, hub } = await tunnel(async (text) => {
      seen.push(text);
      return text;
    });
    socket.write(clientFrame(0x1, "one ", false));
    socket.write(clientFrame(0x9, "hb")); // ping, mid-message
    socket.write(clientFrame(0x0, "two", true));
    await settle();

    expect(seen).toEqual(["one two"]);
    expect(server.tunnelFaults()).toEqual([]);
    // The ping reached the hub ahead of the fragments it interrupted, which is
    // what "forwarded immediately" means and is harmless: it is out of band.
    const wire = hub.bytes();
    expect(wire.length).toBeGreaterThan(0);
    expect(wire[0] & 0x0f, "the ping is first on the wire").toBe(0x9);
  });

  it("rewrites a reassembled message as one frame when the hook changes it", async () => {
    // The tamper path, over a fragmented message. The rewrite cannot preserve
    // the client's fragmentation — the payload length just changed — so it goes
    // as a single frame, which is what the hub reads anyway.
    const { socket, server, hub } = await tunnel(async () => "REWRITTEN");
    socket.write(clientFrame(0x1, "one ", false));
    socket.write(clientFrame(0x0, "two", true));
    await settle();

    expect(server.tunnelFaults()).toEqual([]);
    const wire = hub.bytes();
    expect(wire[0] & 0x80, "fin").toBe(0x80);
    expect(wire[0] & 0x0f, "text opcode").toBe(0x1);
    const mask = wire.subarray(2, 6);
    const body = Buffer.from(wire.subarray(6));
    for (let i = 0; i < body.length; i += 1) body[i] ^= mask[i % 4];
    expect(body.toString("utf8")).toBe("REWRITTEN");
  });

  it("names a continuation that continues nothing, and forwards it", async () => {
    // Reassembly has no answer for this; the fault is the answer.
    /** @type {string[]} */
    const seen = [];
    const { socket, server, hub } = await tunnel(async (text) => {
      seen.push(text);
      return text;
    });
    socket.write(clientFrame(0x0, "orphan", true));
    await settle();

    expect(seen).toEqual([]);
    expect(server.tunnelFaults()).toEqual([
      "continuation frame with no message open; it was forwarded unread",
    ]);
    expect(hub.bytes().length).toBeGreaterThan(0);
  });

  it("names a message left unfinished when the client goes away", async () => {
    // Held fragments are not quietly discarded on disconnect: they go on, and
    // the fact that nobody read them is recorded.
    const { socket, server, hub } = await tunnel(async (text) => text);
    socket.write(clientFrame(0x1, "never finished", false));
    await settle();
    socket.end();
    await settle();

    expect(server.tunnelFaults()).toEqual([
      "the client went away mid-message: a fragmented text message was never" +
        " finished, so its fragments were forwarded unread",
    ]);
    expect(hub.bytes().length).toBeGreaterThan(0);
  });

  it("names a binary frame, because signalling here is text", async () => {
    const { socket, server, hub } = await tunnel(async (text) => text);
    socket.write(clientFrame(0x2, " "));
    await settle();

    expect(server.tunnelFaults()).toHaveLength(1);
    expect(server.tunnelFaults()[0]).toMatch(/binary frame/);
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
