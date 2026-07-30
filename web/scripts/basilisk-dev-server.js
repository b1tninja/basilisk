/**
 * Vite *serve* helpers so local URLs match Flask (`basilisk/portal/static.py`)
 * and CSP allows Vite HMR / CSS injection (production HTML stays strict).
 *
 * Production packaging is unchanged — this plugin is `apply: "serve"` only.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** @type {Record<string, string>} */
const STATIC_PAGES = {
  "my-keys": "/my-keys.html",
  key: "/key.html",
  stats: "/stats.html",
  search: "/index.html",
  encrypt: "/encrypt.html",
  decrypt: "/decrypt.html",
  verify: "/verify.html",
  toolkit: "/toolkit.html",
  quorum: "/quorum.html",
  preferences: "/preferences.html",
  // Local visual fixtures (not registered on Flask)
  "tool-card-preview": "/tool-card-preview.html",
};

/**
 * The production CSP for a page, as a report-only policy.
 *
 * Read from the page's own HTML so there is one source of truth — a hardcoded
 * copy here would drift from the real policy and start reporting violations
 * that are not real, or worse, miss ones that are.
 *
 * `connect-src` is widened for HMR's websocket: that is a dev-server fact, not
 * something that would fail in production, and reporting it on every reload
 * would bury the findings that matter.
 *
 * @param {string} htmlPath  absolute path to the page's HTML
 * @returns {string} policy, or "" when the page has none
 */
function reportOnlyCspFor(htmlPath) {
  if (cspCache.has(htmlPath)) return cspCache.get(htmlPath);
  let csp = "";
  try {
    const html = readFileSync(htmlPath, "utf8");
    const m = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)"/i);
    if (m) {
      csp = m[1].replace(
        /connect-src 'self'/,
        "connect-src 'self' ws: wss: http://127.0.0.1:* http://localhost:*"
      );
    }
  } catch {
    /* page has no HTML on disk — nothing to mirror */
  }
  cspCache.set(htmlPath, csp);
  return csp;
}

/** @type {Map<string, string>} */
const cspCache = new Map();

/**
 * @returns {import("vite").Plugin}
 */
export function basiliskDevServer() {
  return {
    name: "basilisk-dev-server",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (!req.url || req.method !== "GET") return next();
        const q = req.url.indexOf("?");
        const path = q >= 0 ? req.url.slice(0, q) : req.url;
        const query = q >= 0 ? req.url.slice(q) : "";

        if (path === "/search") {
          req.url = `/index.html${query}`;
          return next();
        }

        // Extensionless page routes — same map as Flask register_static_portal.
        if (path.startsWith("/") && !path.slice(1).includes("/")) {
          const page = path.slice(1);
          const target = STATIC_PAGES[page];
          if (target) {
            req.url = `${target}${query}`;
          }
        }

        // Mirror the page's production CSP as report-only, so a violation that
        // would break the built app is visible now. Header, not <meta>: the
        // meta form of report-only is parsed and then ignored by every browser,
        // which fails in the most unhelpful way available.
        const htmlPath = (req.url.split("?")[0] || "").replace(/^\//, "");
        if (htmlPath.endsWith(".html")) {
          const csp = reportOnlyCspFor(join(server.config.root, htmlPath));
          if (csp) res.setHeader("Content-Security-Policy-Report-Only", csp);
        }
        return next();
      });
    },
    transformIndexHtml(html) {
      // Vite injects <style> + small inline module hooks; production uses
      // external CSS/importmaps so CSP stays strict there.
      //
      // Relaxing the *enforcing* policy is unavoidable — strict CSP breaks HMR
      // outright. The cost was that CSP violations became invisible during
      // development and only appeared in the built app, which is how a pile of
      // inline styles accumulated behind a passing test. So the production
      // policy is also served as report-only, from the middleware above, so
      // the browser enforces the relaxed one (dev keeps working) while still
      // firing `securitypolicyviolation` for anything production would refuse.
      // `lib/boot-diagnostics.js` listens and reports those as "would break in
      // production" rather than as live failures.
      return html
        .replace(
          /script-src 'self' 'wasm-unsafe-eval'/,
          "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'"
        )
        .replace(/style-src 'self'/, "style-src 'self' 'unsafe-inline'")
        .replace(
          /connect-src 'self' https:\/\/keys\.openpgp\.org https:\/\/keys\.mailvelope\.com/,
          "connect-src 'self' ws: wss: http://127.0.0.1:* http://localhost:* https://keys.openpgp.org https://keys.mailvelope.com"
        );
    },
  };
}
