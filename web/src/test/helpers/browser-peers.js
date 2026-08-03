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
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

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
export async function serveDist(root = DIST_ROOT, routes = null) {
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

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    // Port 0 = whatever is free, so two runs never collide.
    server.listen(0, "127.0.0.1", () => resolve(undefined));
  });
  const addr = /** @type {import("node:net").AddressInfo} */ (server.address());
  return {
    origin: `http://127.0.0.1:${addr.port}`,
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
  } = opts;
  const { chromium } = await import("playwright");
  const server = await serveDist(root, routes);
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
