import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/test/**/*.test.js"],
    // Key generation with Curve25519 is fast (~50 ms) but allow headroom.
    timeout: 20000,
  },
});
