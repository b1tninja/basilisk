/**
 * Ports for the servers the browser suite spawns.
 *
 * Lives in the fast suite because the property is about the allocator, not
 * about a browser — and because this is where CI runs.
 */
import { createServer } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

/** @type {(() => Promise<void>)[]} */
let cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.reverse()) await fn().catch(() => {});
  cleanup = [];
});

/**
 * One port, named before the process that wants it.
 *
 * Flask takes its port on the command line, so it has to be chosen by probe:
 * bind 0, read what the OS gave, let go. The window between letting go and the
 * server binding is real and cannot be closed here — but it fails loudly
 * (`startBasilisk` waits for `/health` and throws with the process's own
 * "Address already in use").
 *
 * **There used to be a second port,** for the signalling double, and this file
 * existed mostly because of it: `placed-run-arc.e2e.js` called a one-port
 * helper twice in a row, nothing stopped the OS handing back the same number
 * twice, and the double then failed to bind inside a server that came up fine.
 * That is gone rather than guarded. The double binds its own socket and
 * `basilisk/serve.py` publishes the port back into its own settings before the
 * app is built, so no caller needs two numbers and none can conflate them —
 * which is why the allocator now returns one port and this file no longer
 * asserts that a batch of them is distinct.
 */
describe("port allocation for spawned servers", () => {
  it("hands back a usable port, and lets go of it", async () => {
    // Held during the choosing and released after: a probe still listening
    // would turn every allocation into a port nothing else can use, and the
    // server it was chosen for is the thing that must be able to bind.
    const { freePort } = await import("./helpers/basilisk-server.js");
    const port = await freePort();
    expect(port).toBeGreaterThan(0);

    const taken = createServer();
    await new Promise((resolve, reject) => {
      taken.once("error", reject);
      taken.listen(port, "127.0.0.1", () => resolve(undefined));
    });
    cleanup.push(
      () =>
        new Promise((r) => {
          taken.close(() => r(undefined));
        })
    );
    expect(
      /** @type {import("node:net").AddressInfo} */ (taken.address()).port
    ).toBe(port);
  });

  it("reads the signalling socket out of a policy, and says so when there is none", async () => {
    // How `startBasilisk` learns the port it did not choose. A deployment
    // without signalling has no ws source at all, and "" has to mean that
    // rather than being mistaken for one.
    const { wsSource } = await import("./helpers/basilisk-server.js");
    expect(
      wsSource("default-src 'none'; connect-src 'self' https://keys.openpgp.org ws://127.0.0.1:5051; img-src 'self'")
    ).toBe("ws://127.0.0.1:5051");
    expect(wsSource("connect-src 'self' wss://x.webpubsub.azure.com;")).toBe(
      "wss://x.webpubsub.azure.com"
    );
    expect(wsSource("default-src 'none'; connect-src 'self';")).toBe("");
    expect(wsSource(null)).toBe("");
  });
});
