import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  // Mirrors vite.config.js. Without this alias, importing anything that
  // reaches `@/lib/cn` — which is every component — fails to resolve, so a
  // component's exported helpers had to be moved into `lib/` purely to be
  // testable. Tests still run in `node`, so *rendering* remains out of scope;
  // this only makes the logic importable.
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "src"),
    },
  },
  test: {
    environment: "node",
    include: ["src/test/**/*.test.js"],
    // Key generation with Curve25519 is fast (~50 ms) but allow headroom.
    timeout: 20000,
  },
});
