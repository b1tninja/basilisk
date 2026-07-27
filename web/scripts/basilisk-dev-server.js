/**
 * Vite *serve* helpers so local URLs match Flask (`basilisk/portal/static.py`)
 * and CSP allows Vite HMR / CSS injection (production HTML stays strict).
 *
 * Production packaging is unchanged — this plugin is `apply: "serve"` only.
 */

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
        return next();
      });
    },
    transformIndexHtml(html) {
      // Vite injects <style> + small inline module hooks; production uses
      // external CSS/importmaps so CSP stays strict there.
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
