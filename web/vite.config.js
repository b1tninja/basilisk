import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import sri from "vite-plugin-sri-gen";
import { basiliskExternalizeImportMaps } from "./scripts/externalize-importmaps.js";
import { basiliskDevServer } from "./scripts/basilisk-dev-server.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: ".",
  publicDir: "public",
  resolve: {
    // Array form because one of these has to be anchored: a bare
    // `react-remove-scroll-bar` is ours, but `react-remove-scroll-bar/constants`
    // must still reach the real package, and a string alias would rewrite both.
    alias: [
      { find: "@", replacement: resolve(__dirname, "src") },
      {
        // Radix's Dialog and Menu pull in `react-remove-scroll`, whose
        // scrollbar half delivers its CSS by appending a `<style>` element at
        // runtime — refused by `style-src 'self'`, so in production the modal
        // scroll lock never applied and every open logged a violation.
        // `lib/scroll-lock` keeps the attribute and drops the injection; the
        // rules it stands in for are declared in `css/site.css`.
        find: /^react-remove-scroll-bar$/,
        replacement: resolve(__dirname, "src/lib/scroll-lock.js"),
      },
    ],
  },
  // crypto-worker → toolkit/engine uses dynamic import(); IIFE cannot code-split.
  // All Worker() call sites already pass { type: "module" }.
  worker: {
    format: "es",
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Content-hashed filenames + SRI (below) pin each deploy; do not disable.
    rollupOptions: {
      // Eight pages. `encrypt.html` and `decrypt.html` were meta-refreshes into
      // toolkit fragments and the nav already pointed past them; `quorum.html`
      // and `my-keys.html` were retired into the Keys tray and `/published`.
      // Flask 301s all four (`basilisk/portal/static.py`), so no route 404s.
      input: {
        index: resolve(__dirname, "index.html"),
        published: resolve(__dirname, "published.html"),
        key: resolve(__dirname, "key.html"),
        stats: resolve(__dirname, "stats.html"),
        verify: resolve(__dirname, "verify.html"),
        toolkit: resolve(__dirname, "toolkit.html"),
        toolkitWidgets: resolve(__dirname, "toolkit-widgets.html"),
        preferences: resolve(__dirname, "preferences.html"),
      },
      output: {
        /**
         * `notebook/session.js` keeps a chunk of its own.
         *
         * It had one for as long as `quorum.html` existed, because that page's
         * eager graph and the toolkit's lazy one both reached it and Rollup
         * hoists shared code. Retiring the page left `quorum-ops.js` as the
         * only importer, so Rollup inlined the module — and an inlined module
         * is not an *exported binding of any chunk*.
         *
         * That is what this restores. `placed-run-arc.e2e.js` and
         * `quorum-key-confirmation.e2e.js` are the only tests that drive the
         * **shipped** session rather than one compiled from source — two real
         * browsers, one relay, key confirmation over the bytes a deploy would
         * serve — and they find the class by its export. Inlined, it has no
         * name to find, and the suite that watches a substituted DTLS
         * fingerprint get refused would have gone quiet rather than red.
         *
         * **This chunk is preloaded on every page**, because the shared-chunk
         * graph reaches it — exactly as `session-*.js` was before the
         * retirement, so nothing here is new. It is still worth saying out
         * loud, because `kernel.js` imports the session dynamically so that
         * WebRTC stays out of the base bundle, and a `<link modulepreload>`
         * quietly undoes half of that. Fixing it means filtering the entry's
         * preload list (`build.modulePreload.resolveDependencies`), which is a
         * question about preloading and not about which pages exist.
         */
        manualChunks(id) {
          const path = id.replace(/\\/g, "/");
          // OpenPGP keeps the chunk it has always had. Naming one module by
          // hand makes Rollup recompute the whole assignment, and the first
          // thing it did was fold 390 kB of OpenPGP into the session's chunk —
          // undoing the split that keeps it a single cached download shared by
          // every page. Stated rather than discovered again.
          if (path.includes("/node_modules/openpgp/")) return "openpgp";
          if (path.endsWith("/lib/notebook/session.js")) return "notebook-session";
          return undefined;
        },
      },
    },
  },
  plugins: [
    // Dev-only: Flask-parity clean URLs + CSP that allows Vite CSS/HMR.
    basiliskDevServer(),
    react(),
    tailwindcss(),
    sri({
      algorithm: "sha384",
      crossorigin: "anonymous",
    }),
    // Must run after sri-gen writes the inline integrity importmap.
    // Also writes /integrity/module-roots.json Merkle pins for CDN cross-checks.
    basiliskExternalizeImportMaps(),
  ],
  test: {
    environment: "node",
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
});
