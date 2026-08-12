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
 * Ports named before the process that wants them.
 *
 * Flask takes its port on the command line and the signalling double takes its
 * own inside a connection string that must be in the environment before the
 * interpreter starts, so both are chosen by probe: bind 0, read what the OS
 * gave, let go. The window between letting go and the server binding is real
 * and cannot be closed here — but it fails loudly (`startBasilisk` waits for
 * `/health` and throws with the process's own "Address already in use").
 *
 * What was *silent* is the collision this suite caused itself.
 * `placed-run-arc.e2e.js` called a one-port helper twice in a row, once for the
 * hub and once for Flask, and nothing stopped the OS handing back the same
 * number twice — after which the double fails to bind inside a server that
 * came up fine, and the arc simply never signals.
 */
describe("port allocation for spawned servers", () => {
  it("hands back distinct ports, because it holds them all at once", async () => {
    const { freePorts } = await import("./helpers/basilisk-server.js");
    // Enough that a sequential allocator reusing a just-released number would
    // show up; the property is structural, not statistical, but a single pair
    // would pass by luck on any implementation.
    const ports = await freePorts(40);
    expect(ports).toHaveLength(40);
    expect(new Set(ports).size).toBe(40);
    for (const p of ports) expect(p).toBeGreaterThan(0);
  });

  it("releases them, so the server they were chosen for can bind", async () => {
    // Held during the choosing and let go after: a probe still listening would
    // turn every allocation into a port nothing else can use.
    const { freePorts } = await import("./helpers/basilisk-server.js");
    const [port] = await freePorts(1);
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
});
