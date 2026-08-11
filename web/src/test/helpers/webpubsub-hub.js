/**
 * The local Web PubSub hub, as a real socket, for the browser suite.
 *
 * `webpubsub-double.js` stands in at `globalThis.WebSocket` and is right for
 * the node suite, where both sides of a pair live in one process. It cannot
 * serve two browser contexts: it brokers `sendToGroup` through a `Set` of
 * sockets it holds itself, so each page would install its own copy and neither
 * peer would ever see the other's signals. Two browsers need a server.
 *
 * That server already exists and is already trusted for this path —
 * `basilisk/portal/webpubsub_local.py`, which `basilisk serve` starts whenever
 * `WEB_PUBSUB_CONNECTION` points at loopback. There is no `ws` dependency in
 * this package, so the alternative was hand-rolling RFC 6455 in Node beside a
 * Python implementation the dev path already relies on. This spawns that
 * instead.
 *
 * ## The port the token names is not the port the hub binds
 *
 * The page must dial **same-origin**: `connect-src 'self'` is the shipped
 * policy, and it is the reason `basilisk-server.js` proxies the keyserver
 * rather than redirecting to it. A WebSocket to another port is refused for
 * exactly the same reason.
 *
 * So the connection string advertises the *dist server's* origin — that is
 * what the minted token's `aud` is checked against — while `start(port)` binds
 * the hub somewhere else entirely, and the dist server tunnels the upgrade
 * across. `LocalWebPubSub.start()` taking an explicit port is what makes the
 * two separable.
 *
 * @module test/helpers/webpubsub-hub
 */

import { spawn } from "node:child_process";
import { pythonCandidates, classifyPythonFailure, REPO_ROOT } from "./basilisk-server.js";

/**
 * Start the hub, print the port it bound, and block.
 *
 * Written as `-c` rather than a file so there is no script to keep in step
 * with the helper that runs it.
 */
const BOOT = `
import json, sys, threading
from basilisk.portal.webpubsub import parse_connection_string
from basilisk.portal.webpubsub_local import LocalWebPubSub

conn, hub, want = sys.argv[1], sys.argv[2], int(sys.argv[3])
endpoint = parse_connection_string(conn)
server = LocalWebPubSub(endpoint, hub=hub, host="127.0.0.1")
# 0 means "any free port". Passing "want or None" would send 0 to the
# endpoint fallback inside start(), which is the dist port and taken.
port = server.start(want)
print(json.dumps({"port": port}), flush=True)
threading.Event().wait()
`;

/**
 * @typedef {object} LocalHub
 * @property {number} port      what the hub actually bound
 * @property {string} accessKey the key its tokens are signed with
 * @property {string} hub
 * @property {() => Promise<void>} stop
 */

/**
 * @param {{ connection: string, hub?: string, timeoutMs?: number }} opts
 * @returns {Promise<{ ok: true, hub: LocalHub } | { ok: false, reason: string, kind: ""|"absent"|"broken" }>}
 */
export async function startLocalHub({ connection, hub = "notebook", timeoutMs = 15000 }) {
  let lastReason = "no python candidate ran";
  let lastKind = /** @type {""|"absent"|"broken"} */ ("absent");

  for (const exe of pythonCandidates()) {
    let child;
    try {
      child = spawn(exe, ["-c", BOOT, connection, hub, "0"], {
        cwd: REPO_ROOT,
        env: { ...process.env, PYTHONUNBUFFERED: "1" },
      });
    } catch (err) {
      lastReason = String(err instanceof Error ? err.message : err);
      lastKind = classifyPythonFailure(lastReason);
      continue;
    }

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));

    /** Resolves with the bound port, or rejects with whatever the process said. */
    const port = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      const check = () => {
        const line = stdout.split("\n").find((l) => l.trim().startsWith("{"));
        if (!line) return;
        try {
          const parsed = JSON.parse(line);
          if (typeof parsed.port === "number") {
            clearTimeout(timer);
            resolve(parsed.port);
          }
        } catch {
          /* a partial line — wait for the rest */
        }
      };
      child.stdout.on("data", check);
      child.on("error", () => {
        clearTimeout(timer);
        resolve(null);
      });
      child.on("close", () => {
        clearTimeout(timer);
        resolve(null);
      });
      check();
    });

    if (port === null) {
      child.kill();
      // An interpreter that is present and a hub that will not start is a real
      // failure, reported with what the process wrote — the same rule
      // `basilisk-server.js` states for the app itself. A harness that filed
      // "the hub raised on boot" under "no Python" would skip itself green on
      // the day signalling broke.
      lastReason = (stderr || stdout || "the hub exited without naming a port").trim();
      lastKind = classifyPythonFailure(lastReason);
      continue;
    }

    return {
      ok: true,
      hub: {
        port,
        accessKey: accessKeyOf(connection),
        hub,
        stop: async () => {
          child.kill();
          await new Promise((r) => setTimeout(r, 50));
        },
      },
    };
  }

  return { ok: false, reason: lastReason, kind: lastKind };
}

/** The `AccessKey=` field, which is what the hub verifies tokens against. */
function accessKeyOf(connection) {
  for (const segment of String(connection || "").split(";")) {
    const [k, ...rest] = segment.split("=");
    if (k.trim().toLowerCase() === "accesskey") return rest.join("=").trim();
  }
  return "";
}

/**
 * A connection string for a hub whose tokens are minted for `origin`.
 *
 * `Endpoint` is the audience, not the address — see the module note. It is the
 * dist server's origin because that is where the page dials.
 *
 * @param {string} origin
 * @param {string} accessKey
 */
export const connectionFor = (origin, accessKey) =>
  `Endpoint=${origin};AccessKey=${accessKey};Version=1.0;`;
