import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import sri from "vite-plugin-sri-gen";
import { basiliskExternalizeImportMaps } from "./scripts/externalize-importmaps.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: ".",
  publicDir: "public",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Content-hashed filenames + SRI (below) pin each deploy; do not disable.
    rollupOptions: {
      input: {
        index: resolve(__dirname, "index.html"),
        myKeys: resolve(__dirname, "my-keys.html"),
        key: resolve(__dirname, "key.html"),
        stats: resolve(__dirname, "stats.html"),
        encrypt: resolve(__dirname, "encrypt.html"),
        decrypt: resolve(__dirname, "decrypt.html"),
        verify: resolve(__dirname, "verify.html"),
        toolkit: resolve(__dirname, "toolkit.html"),
        quorum: resolve(__dirname, "quorum.html"),
      },
    },
  },
  plugins: [
    sri({
      algorithm: "sha384",
      crossorigin: "anonymous",
    }),
    // Must run after sri-gen writes the inline integrity importmap.
    // Also writes /integrity/module-roots.json Merkle pins for CDN cross-checks.
    basiliskExternalizeImportMaps(),
  ],
});
