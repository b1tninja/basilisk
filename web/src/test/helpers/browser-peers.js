/**
 * Two real browsers, the real built app, and a place to carry a blob between
 * them (§ WebRTC transport proof).
 *
 * Everything else in `src/test/` runs under `environment: "node"`, so nothing
 * there has ever touched an `RTCPeerConnection` — the transport was asserted
 * only through its roster/negotiation *logic*. This helper is the missing
 * half: it serves `dist/` over `http://127.0.0.1` and opens the page in two
 * isolated browser contexts, which is the smallest arrangement in which an
 * offer can actually reach an answerer.
 *
 * Three constraints shaped it, each learned the hard way:
 *
 *  - **A secure context is mandatory.** `RTCPeerConnection.generateCertificate`
 *    and everything under `crypto.subtle` are gated on it, so `about:blank`
 *    and `page.setContent()` fail with "The WebCrypto API is not available".
 *    `http://127.0.0.1` is trustworthy by origin, `http://localhost` resolves
 *    through the hosts file and is not worth the ambiguity — hence the literal
 *    loopback IP everywhere below.
 *
 *  - **The page under test must be the shipped one.** Importing a module into
 *    a blank page would test the module and skip the Content-Security-Policy,
 *    which is the strictest thing about this app and the most likely thing to
 *    silently forbid ICE. So the server mirrors Flask's clean URLs, serves the
 *    real hashed bundles, and the real `<meta http-equiv>` policy applies.
 *
 *  - **A violated CSP is invisible unless you listen.** A blocked `connect-src`
 *    does not throw where the call was made; it fires
 *    `securitypolicyviolation` on the document and is otherwise silent. The
 *    listener is installed via `addInitScript`, i.e. before any app code runs,
 *    because a violation during module evaluation is exactly the one worth
 *    catching.
 *
 * Playwright and its Chromium are already devDependencies of this package —
 * this helper adds nothing to `package.json`.
 *
 * @module test/helpers/browser-peers
 */

import { createServer } from "node:http";
import { connect } from "node:net";
import { randomBytes } from "node:crypto";

import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

/** Spelled once so an editor cannot turn a literal request terminator into LF. */
const CRLF = String.fromCharCode(13, 10);

/** The built app. Run `npm run build` before the e2e suite. */
export const DIST_ROOT = fileURLToPath(new URL("../../../dist/", import.meta.url));

/**
 * Flask's clean URLs (`basilisk/portal/static.py`), mirrored so a test can ask
 * for `/toolkit` the way a person does. Kept in this shape rather than
 * imported from `scripts/basilisk-dev-server.js` because that plugin is
 * `apply: "serve"` and importing it would pull Vite into the test process.
 */
const CLEAN_URLS = {
  "/": "/index.html",
  "/search": "/index.html",
  "/my-keys": "/my-keys.html",
  "/key": "/key.html",
  "/stats": "/stats.html",
  "/encrypt": "/encrypt.html",
  "/decrypt": "/decrypt.html",
  "/verify": "/verify.html",
  "/toolkit": "/toolkit.html",
  "/toolkit-widgets": "/toolkit-widgets.html",
  "/quorum": "/quorum.html",
  "/preferences": "/preferences.html",
};

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".wasm": "application/wasm",
  ".map": "application/json; charset=utf-8",
};


/**
 * Client→server WebSocket frames, one at a time, with a hook on the text ones.
 *
 * The tunnel forwards bytes because it does not need to understand them. This
 * is the exception: a relay tamper has to reach the payload, and the mailbox
 * that used to be that seam sees none of this traffic any more.
 *
 * Only unfragmented text frames are opened. Continuations, binary and control
 * frames are forwarded as the exact bytes that arrived — a pump that
 * reassembled fragments would be reimplementing the protocol to inspect
 * messages this suite's signalling never sends.
 *
 * Rewrites are re-masked with a fresh key, because client→server frames must
 * be masked and reusing the original key on different plaintext is not how
 * that works. Frames the hook leaves alone are forwarded byte-identical rather
 * than re-encoded, so an untouched relay stays untouched.
 *
 * The hook is async and delivery order is the protocol's, so frames are
 * chained rather than raced.
 */
function pumpFrames(socket, upstream, onSignal, onFault) {
  let buf = Buffer.alloc(0);
  let chain = Promise.resolve();
  /**
   * The fragmented text message currently open, held until its final frame.
   *
   * `payloads` is what `onSignal` will be shown; `frames` is the wire exactly
   * as the client wrote it, kept so an unchanged message can be forwarded
   * byte-for-byte rather than re-encoded into a shape the client never sent.
   * @type {{ payloads: Buffer[], frames: Buffer[] }|null}
   */
  let open = null;

  /**
   * Let go of a half-built message — loudly, and without passing it on.
   *
   * Both halves matter, and the second was missing. These fragments were
   * forwarded once, on the reasoning that dropping a frame is worse than
   * letting it through unread. That reasoning holds for a *complete* message
   * the tunnel could not inspect; it is wrong here, because a message that
   * never received its final frame is not a message. Forwarding the pieces
   * hands the hub a truncated payload the client never finished sending, and
   * leaves the room's record of it missing — the same silent loss closed for
   * every other case.
   *
   * So: fault, and drop. Nothing downstream is entitled to half a message, and
   * a run that needed it fails on the fault rather than on whatever the hub
   * made of the fragments.
   */
  const abandonOpen = (why) => {
    if (!open) return;
    onFault(why);
    open = null;
  };

  /**
   * @param {string} text     the whole message
   * @param {Buffer} original the frames it arrived in
   */
  const deliver = async (text, original) => {
    let out;
    try {
      out = await onSignal(text);
    } catch (err) {
      // A hook that threw must not silently drop the message *or* the fact
      // that it threw. The original goes on so the peers still mesh; the fault
      // is what stops the run reading as a clean pass over an envelope the
      // relay never actually inspected.
      onFault(`onSignal threw: ${err instanceof Error ? err.message : String(err)}`);
      try {
        upstream.write(original);
      } catch {
        /* the socket is already gone */
      }
      return;
    }
    // A rewrite is re-encoded as one unfragmented frame. That is a shape the
    // client did not send, and it is the right one: the hub reads messages,
    // the fragmentation was the client's own buffering, and preserving it
    // would mean splitting a payload whose length just changed.
    upstream.write(typeof out === "string" && out !== text ? encodeTextFrame(out) : original);
  };

  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      const frame = readClientFrame(buf);
      if (!frame) break;
      buf = buf.subarray(frame.size);
      const { fin, opcode, payload, bytes } = frame;
      chain = chain
        .then(async () => {
          // Control frames — close, ping, pong — carry no signalling, are never
          // fragmented, and RFC 6455 lets them arrive *between* the fragments
          // of a message. So they go straight on rather than into the buffer;
          // a ping overtaking held fragments is a keepalive arriving early and
          // means nothing to the hub.
          //
          // Close is the exception: it ends the conversation, so whatever is
          // being held has to go first or the server never sees it at all.
          if (opcode >= 0x8) {
            if (opcode === 0x8) {
              abandonOpen(
                "closed mid-message: a fragmented text message was still open when the" +
                  " client sent close, so nothing was forwarded"
              );
            }
            upstream.write(bytes);
            return;
          }

          // Binary. The hub speaks `json.webpubsub.azure.v1`, which is text, so
          // this is signalling in a form the tunnel cannot read — forwarded, and
          // named, because "the relay saw everything" would stop being true.
          if (opcode === 0x2) {
            onFault(
              `binary frame (${payload.length} bytes): signalling here is text, so a` +
                " binary message crossed without being read"
            );
            upstream.write(bytes);
            return;
          }

          if (opcode === 0x1) {
            // A new message while one is open is a protocol error on the
            // client's side. Nothing sensible can be reassembled from it.
            abandonOpen(
              "a new text message began while a fragmented one was still open;" +
                " the unfinished fragments were dropped and nothing was forwarded"
            );
            if (fin) {
              await deliver(payload.toString("utf8"), bytes);
              return;
            }
            open = { payloads: [payload], frames: [bytes] };
            return;
          }

          // Continuation.
          if (!open) {
            onFault(
              "continuation frame with no message open; it was forwarded unread"
            );
            upstream.write(bytes);
            return;
          }
          open.payloads.push(payload);
          open.frames.push(bytes);
          if (!fin) return;
          const whole = open;
          open = null;
          await deliver(
            Buffer.concat(whole.payloads).toString("utf8"),
            Buffer.concat(whole.frames)
          );
        })
        .catch((err) => {
          // `deliver` forwards its own bytes on every path, so anything landing
          // here is the tunnel itself failing. Recorded rather than swallowed;
          // writing again could duplicate a frame.
          onFault(`tunnel failed on a frame: ${err instanceof Error ? err.message : String(err)}`);
        });
    }
  });
  socket.on("end", () => {
    chain.finally(() => {
      abandonOpen(
        "the client went away mid-message: a fragmented text message was never" +
          " finished, so nothing was forwarded"
      );
      upstream.end();
    });
  });
}

/** One masked frame, or null when the buffer does not hold a whole one yet. */
function readClientFrame(buf) {
  if (buf.length < 2) return null;
  const fin = (buf[0] & 0x80) !== 0;
  const opcode = buf[0] & 0x0f;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f;
  let off = 2;
  if (len === 126) {
    if (buf.length < off + 2) return null;
    len = buf.readUInt16BE(off);
    off += 2;
  } else if (len === 127) {
    if (buf.length < off + 8) return null;
    len = Number(buf.readBigUInt64BE(off));
    off += 8;
  }
  let mask = null;
  if (masked) {
    if (buf.length < off + 4) return null;
    mask = buf.subarray(off, off + 4);
    off += 4;
  }
  if (buf.length < off + len) return null;
  const body = buf.subarray(off, off + len);
  const payload = Buffer.from(body);
  if (mask) for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
  return { size: off + len, fin, opcode, payload, bytes: Buffer.from(buf.subarray(0, off + len)) };
}

/** A masked text frame, as a client must send. */
function encodeTextFrame(text) {
  const payload = Buffer.from(text, "utf8");
  const n = payload.length;
  let header;
  if (n < 126) {
    header = Buffer.from([0x81, 0x80 | n]);
  } else if (n < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(n, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(n), 2);
  }
  const mask = randomBytes(4);
  const masked = Buffer.alloc(n);
  for (let i = 0; i < n; i += 1) masked[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([header, mask, masked]);
}

/**
 * Serve a directory on loopback.
 *
 * No headers are added on top of what the files declare. That is the point:
 * the toolkit page ships its policy in a `<meta http-equiv>` tag, so serving
 * the bytes unmodified is what makes the production CSP the one under test.
 *
 * One escape hatch: `routes`. A page can construct an `RTCPeerConnection` off
 * static files alone, but it cannot run a *quorum session* — that bootstraps
 * through an HTTP mailbox and a keyserver, both same-origin and therefore both
 * inside `connect-src 'self'`. `routes` gets first refusal on every request and
 * says whether it answered; anything it declines falls through to the files, so
 * the default behaviour is byte-for-byte what it was.
 *
 * @param {string} root absolute directory to serve
 * @param {((req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => boolean)|null} [routes]
 * @returns {Promise<{ origin: string, close: () => Promise<void> }>}
 */
export async function serveDist(root = DIST_ROOT, routes = null, upgradeTarget = null, onSignal = null) {
  /**
   * Frames the tunnel could not show `onSignal`, and hooks that threw.
   *
   * Read by whoever asserts on the intercepted traffic. Both entries mean the
   * same thing — an envelope crossed and the relay did not see it — and both
   * used to be silent, which made `room.signalled()` a count nobody could
   * trust and a tamper something that might simply never have been applied.
   * @type {string[]}
   */
  const tunnelFaults = [];
  const server = createServer((req, res) => {
    if (routes && routes(req, res)) return;
    const url = req.url || "/";
    const path = decodeURIComponent(url.split("?")[0].split("#")[0]);
    const mapped = CLEAN_URLS[path] || path;
    // `normalize` collapses `..` before the prefix check, so a traversal
    // attempt lands outside `root` and is refused rather than served.
    const file = normalize(join(root, mapped));
    if (!file.startsWith(normalize(root).replace(/[\\/]$/, "") + sep)) {
      res.writeHead(403).end("forbidden");
      return;
    }
    stat(file)
      .then((s) => {
        if (!s.isFile()) throw new Error("not a file");
        return readFile(file);
      })
      .then((body) => {
        res.writeHead(200, {
          "content-type": MIME[extname(file).toLowerCase()] || "application/octet-stream",
          "content-length": String(body.byteLength),
          "cache-control": "no-store",
        });
        res.end(body);
      })
      .catch(() => {
        res.writeHead(404, { "content-type": "text/plain" }).end("not found");
      });
  });

  // Signalling has to arrive on the page's own origin: `connect-src 'self'` is
  // the shipped policy and the reason the keyserver is proxied rather than
  // redirected to. So the WebSocket upgrade is tunnelled to whatever port the
  // hub actually bound; the handshake is forwarded verbatim.
  //
  // Server→client is piped untouched. Client→server is read frame by frame
  // when `onSignal` is given, because that is the seam a relay tamper needs and
  // the mailbox — which used to be that seam — no longer sees any of this. The
  // hub rebroadcasts whatever it receives, so rewriting on the way *in* is
  // exactly a relay rewriting in flight.
  server.on("upgrade", (req, socket, head) => {
    const port = typeof upgradeTarget === "function" ? upgradeTarget(req) : upgradeTarget;
    if (!port) {
      socket.destroy();
      return;
    }
    const upstream = connect(port, "127.0.0.1", () => {
      const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
      }
      upstream.write(lines.join(CRLF) + CRLF + CRLF);
      if (head?.length) upstream.write(head);
      upstream.pipe(socket);
      if (onSignal) {
        pumpFrames(socket, upstream, onSignal, (why) => tunnelFaults.push(why));
      } else socket.pipe(upstream);
    });
    const bail = () => {
      upstream.destroy();
      socket.destroy();
    };
    upstream.on("error", bail);
    socket.on("error", bail);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    // Port 0 = whatever is free, so two runs never collide.
    server.listen(0, "127.0.0.1", () => resolve(undefined));
  });
  const addr = /** @type {import("node:net").AddressInfo} */ (server.address());
  return {
    origin: `http://127.0.0.1:${addr.port}`,
    tunnelFaults: () => tunnelFaults.slice(),
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve(undefined));
      }),
  };
}

/**
 * Chromium flags that make a *local* WebRTC connection observable.
 *
 * `WebRtcHideLocalIpsWithMdns` is on by default and replaces every host
 * candidate's address with a random `<uuid>.local` name, resolvable only by
 * mDNS. Two contexts in one browser can often still resolve each other, but
 * the candidate rows then carry no address, which is precisely the field a
 * connectivity test needs to report. Turning it off is a *test observability*
 * choice, not a workaround for a defect: production keeps the redaction, and
 * `describeCandidate` in `rtc-ops.js` already documents that it labels pairs
 * `type:port` because the address is blank there.
 */
export const WEBRTC_FLAGS = [
  "--disable-features=WebRtcHideLocalIpsWithMdns",
  "--autoplay-policy=no-user-gesture-required",
];

/**
 * What a failed browser launch means: an absent install, or a real fault.
 *
 * Pure and exported so both branches can be asserted, because the environment
 * only ever exercises one of them and the interesting one is the branch that
 * must *not* swallow a genuine failure. This is `ssh-format.test.js`'s lesson
 * applied: those tests guarded on `ssh-keygen` *availability*, so when the
 * binary refused for an unrelated reason they went red instead of skipping.
 * The mirror-image trap lives here — a broken WebRTC stack, a crashed browser
 * or a sandbox refusal must not be able to disguise itself as "no browser" and
 * skip the transport suite into a green run.
 *
 * Only a missing download is a skip. Everything else is the environment
 * failing, and is reported as such.
 *
 * @param {string} message
 * @returns {"absent"|"broken"}
 */
export function classifyLaunchFailure(message) {
  const m = String(message);
  // Playwright's own wording when the browser binary was never fetched.
  if (/Executable doesn't exist/i.test(m)) return "absent";
  if (/playwright install/i.test(m)) return "absent";
  if (/Cannot find (?:module|package) 'playwright'/i.test(m)) return "absent";
  if (/ERR_MODULE_NOT_FOUND/.test(m)) return "absent";
  return "broken";
}

/**
 * Whether a browser can be launched at all.
 *
 * @returns {Promise<{ ok: boolean, reason: string, kind: ""|"absent"|"broken" }>}
 */
export async function chromiumAvailability() {
  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch (err) {
    const msg = describe(err);
    return { ok: false, reason: `playwright not importable: ${msg}`, kind: classifyLaunchFailure(msg) };
  }
  try {
    const browser = await chromium.launch({ args: WEBRTC_FLAGS });
    await browser.close();
    return { ok: true, reason: "", kind: "" };
  } catch (err) {
    const msg = describe(err);
    return { ok: false, reason: msg, kind: classifyLaunchFailure(msg) };
  }
}

/** @param {unknown} err */
function describe(err) {
  return err instanceof Error ? err.message : String(err);
}

/**
 * @typedef {object} Peer
 * @property {import("playwright").BrowserContext} context
 * @property {import("playwright").Page} page
 * @property {string} name
 * @property {() => Promise<{ directive: string, blocked: string }[]>} cspViolations
 *   Every `securitypolicyviolation` the document has fired so far.
 * @property {() => string[]} pageErrors  uncaught exceptions and console errors
 */

/**
 * @typedef {object} PeerFixture
 * @property {string} origin
 * @property {Peer[]} peers
 * @property {import("playwright").Browser} browser
 * @property {() => Promise<void>} close
 */

/**
 * Open the same page of the real app in N isolated browser contexts.
 *
 * Contexts, not tabs: separate storage, separate permissions, no shared
 * JavaScript realm. Two peers that could see each other's globals would prove
 * nothing about a transport.
 *
 * They do share one browser *process*, which is deliberate — it is what lets a
 * host-candidate-only connection complete with no STUN, no TURN, and no
 * network beyond the loopback interface. That connection is the test that must
 * always run.
 *
 * @param {{
 *   path?: string,
 *   count?: number,
 *   root?: string,
 *   headless?: boolean,
 *   routes?: ((req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => boolean)|null,
 * }} [opts]
 * @returns {Promise<PeerFixture>}
 */
export async function openPeers(opts = {}) {
  const {
    path = "/toolkit",
    count = 2,
    root = DIST_ROOT,
    headless = true,
    routes = null,
    upgrade = null,
    onSignal = null,
  } = opts;
  const { chromium } = await import("playwright");
  const server = await serveDist(root, routes, upgrade, onSignal);
  const browser = await chromium.launch({ headless, args: WEBRTC_FLAGS });

  /** @type {Peer[]} */
  const peers = [];
  for (let i = 0; i < count; i += 1) {
    const context = await browser.newContext();
    const name = String.fromCharCode(65 + i); // A, B, C…
    // Before any app script: the violation record has to exist by the time the
    // first module is evaluated, or a policy failure during boot is lost.
    await context.addInitScript(() => {
      /** @type {{ directive: string, blocked: string }[]} */
      const seen = [];
      Object.defineProperty(window, "__cspViolations", { value: seen });
      addEventListener("securitypolicyviolation", (e) => {
        seen.push({
          directive: e.effectiveDirective || e.violatedDirective,
          blocked: e.blockedURI,
        });
      });
    });
    const page = await context.newPage();
    /** @type {string[]} */
    const errors = [];
    page.on("pageerror", (err) => errors.push(`pageerror: ${err.message}`));
    page.on("console", (msg) => {
      if (msg.type() === "error") errors.push(`console: ${msg.text()}`);
    });
    await page.goto(`${server.origin}${path}`, { waitUntil: "load" });
    peers.push({
      context,
      page,
      name,
      cspViolations: () => page.evaluate(() => window.__cspViolations || []),
      pageErrors: () => errors.slice(),
    });
  }

  return {
    origin: server.origin,
    peers,
    browser,
    /** Envelopes the signalling tunnel forwarded without being able to see them. */
    tunnelFaults: server.tunnelFaults,
    close: async () => {
      await browser.close();
      await server.close();
    },
  };
}

/**
 * Poll an in-page predicate until it holds.
 *
 * `page.waitForFunction` would be the obvious tool and is the wrong one here:
 * it evaluates in a fresh scope each tick, so it cannot see a peer connection
 * held in a closure, and it reports a timeout without saying what the state
 * actually was. This returns the last observed value on both paths, which is
 * the difference between "ICE failed" and "ICE was still `checking`".
 *
 * @template T
 * @param {() => Promise<T>} sample
 * @param {(v: T) => boolean} done
 * @param {{ timeout?: number, interval?: number, what?: string }} [opts]
 * @returns {Promise<T>}
 */
export async function until(sample, done, opts = {}) {
  const { timeout = 15000, interval = 100, what = "condition" } = opts;
  const deadline = Date.now() + timeout;
  let last = await sample();
  while (!done(last)) {
    if (Date.now() > deadline) {
      throw new Error(`${what} timed out after ${timeout}ms; last: ${JSON.stringify(last)}`);
    }
    await new Promise((r) => setTimeout(r, interval));
    last = await sample();
  }
  return last;
}
