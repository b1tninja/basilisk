import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

/**
 * The browser half of the suite. Separate from `vitest.config.js` on purpose.
 *
 * `npx vitest run` must stay a fast, hermetic, `environment: "node"` pass that
 * needs no browser download and no loopback socket. These specs need both, so
 * they live behind their own config and their own filename suffix — `.e2e.js`,
 * which the default `include` of `src/test/**\/*.test.js` cannot match, so
 * there is no way to pick them up by accident.
 *
 *     npm run test:e2e
 *
 * Requires `npm run build` first: the point is to drive the *shipped* bundle
 * under the *production* CSP, so there is nothing to serve until dist exists.
 */
export default defineConfig({
  resolve: {
    alias: { "@": resolve(import.meta.dirname, "src") },
  },
  test: {
    environment: "node",
    include: ["src/test/e2e/**/*.e2e.js"],
    // ICE, DTLS and SCTP each have their own backoff; a cold browser launch is
    // seconds on its own. Generous, because a flaky-looking timeout here would
    // be read as a transport defect.
    testTimeout: 120000,
    hookTimeout: 120000,
    // One browser at a time: two peers must be able to see each other's host
    // candidates, and parallel files racing for the same loopback interface
    // turns a real result into a scheduling artifact.
    fileParallelism: false,
    // Every run also lands on disk, because a failure here is expensive to
    // reproduce. A rare one — three sightings before it was caught, always
    // straight after a full node suite — was chased twice with nothing left to
    // read: the terminal had scrolled and the run had already passed on a
    // retry. `expected 'in-progress' to be 'succeeded'` is the whole diagnosis
    // and it fits in one line of this file. Overwritten each run; the node
    // suite is fast enough to re-run and does not need one.
    reporters: ["default", ["junit", { outputFile: "test-results/e2e.xml" }]],
  },
});
