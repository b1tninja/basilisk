/**
 * A real TURN relay, on this machine, for the length of one suite.
 *
 * **Why a container and not a public relay.** `relay` is the only ICE candidate
 * type this repo has never obtained in a test. The srflx half is proven — a
 * public STUN server returns a reflexive address through the production CSP in
 * `stun-discovery.e2e.js` — but every TURN assertion so far has been made
 * against `turn.example.net`, a host that does not answer, so "no relay
 * candidate" was the *expected* result everywhere and a broken relay path
 * would have looked identical. Pointing the suite at somebody else's public
 * relay would swap that blind spot for a flake: credentials rotate, rate limits
 * bite, and a red run would mean nothing. A local coturn with credentials this
 * file chose is deterministic and offline.
 *
 * **Why no NAT simulation.** Basilisk does not implement ICE, Chromium does —
 * so containers on separate networks would mostly exercise Chromium's ICE
 * stack. `iceTransportPolicy: "relay"` reaches the same place from the other
 * side: the agent discards host and srflx candidates and *only* a relay
 * candidate can win, which is exactly the path a peer behind symmetric NAT
 * depends on, with no NAT anywhere in the picture.
 *
 * **Why the relay port range is not published.** The obvious
 * `-p 49152-65535:49152-65535/udp` publishes ~16k ports and is slow or refused
 * outright. Narrowing it with `--min-port`/`--max-port` is the usual advice;
 * measured here, *no* relay port needs publishing at all. Both peers are TURN
 * clients of the same server, so every packet — ALLOCATE, CREATE_PERMISSION,
 * CHANNEL_BIND and the data itself — rides the listening port, and the relayed
 * transport address is only ever reached from inside the container. The range
 * is still narrowed so a misconfiguration cannot silently allocate 16k ports.
 * Container start measured 653 ms this way.
 *
 * The relayed address the browser is handed is therefore the container's own
 * `172.17.0.x`, unreachable from the host — and that is correct, not a
 * workaround: a TURN client never sends to a relayed address directly.
 *
 * Nothing here is added to `package.json`. coturn is dev infrastructure pulled
 * by the Docker CLI, and `docker` is invoked through `node:child_process`.
 *
 * @module test/helpers/coturn
 */

import { spawn, spawnSync } from "node:child_process";
import { createSocket } from "node:dgram";
import { randomBytes } from "node:crypto";

/** Pinned, so a `latest` that changes its flags cannot turn a green run red. */
export const COTURN_IMAGE = "coturn/coturn:4.6.2";

/** Chosen here, so the suite can assert a *wrong* one is refused. */
export const TURN_REALM = "basilisk.test";
export const TURN_USER = "basilisk";
export const TURN_CREDENTIAL = "basilisk-test-credential";

/**
 * What a failed `docker` invocation means.
 *
 * This is the `ssh-format.test.js` lesson applied to a second optional
 * dependency. Those tests guarded on `ssh-keygen` *availability*, so when the
 * binary refused a fixture for an unrelated reason (an over-wide ACL on a fresh
 * Windows clone) they went **red instead of skipping** — a guard that asked
 * "is the tool there?" when the question was "will the tool answer?".
 *
 * The mirror-image trap is the one that matters here, and it is the worse of
 * the two: a relay suite that treats *every* Docker complaint as "no Docker"
 * would skip itself green on the exact day the relay path broke. So the
 * answers are separated, and only the environmental ones stand down:
 *
 *  - `absent`  — no `docker` on PATH. Not news.
 *  - `daemon`  — CLI present, engine not running. Not news.
 *  - `image`   — the image is neither cached nor pullable, i.e. offline with a
 *                cold cache. Not news.
 *  - `broken`  — anything else. Docker answered and something went wrong, which
 *                is news, and is reported as a failure rather than a skip.
 *
 * Pure and exported because a given machine only ever exercises one branch, and
 * the branch that must never swallow a real fault is the one no CI run will
 * reach.
 *
 * @param {string} message
 * @returns {"absent"|"daemon"|"image"|"broken"}
 */
export function classifyDockerFailure(message) {
  const m = String(message);
  // No binary: spawn's ENOENT, plus the shells' own wording.
  if (/ENOENT/.test(m)) return "absent";
  if (/'docker' is not recognized|command not found|not found in \$PATH/i.test(m)) {
    return "absent";
  }
  // CLI present, engine not. Docker Desktop's npipe wording and dockerd's socket.
  if (/cannot find the file specified/i.test(m) && /pipe/i.test(m)) return "daemon";
  if (/failed to connect to the docker (?:api|daemon)/i.test(m)) return "daemon";
  if (/Is the docker daemon running/i.test(m)) return "daemon";
  if (/docker daemon is not running/i.test(m)) return "daemon";
  if (/Cannot connect to the Docker daemon/i.test(m)) return "daemon";
  // Offline with a cold cache. Note this is deliberately *not* matched on the
  // bare word "pull": `docker pull` reporting a manifest error for a tag that
  // exists would be news about the pin, not about the network.
  if (/dial tcp|no such host|network is unreachable|i\/o timeout/i.test(m)) return "image";
  if (/TLS handshake timeout|proxyconnect|certificate signed by unknown/i.test(m)) {
    return "image";
  }
  return "broken";
}

/** @param {string[]} args @param {number} [timeout] */
function docker(args, timeout = 120000) {
  const r = spawnSync("docker", args, { encoding: "utf8", timeout });
  const out = `${r.stdout || ""}${r.stderr || ""}`.trim();
  if (r.error) return { ok: false, text: `${r.error.message} ${out}`.trim() };
  if (r.status !== 0) return { ok: false, text: out || `docker exited ${r.status}` };
  return { ok: true, text: out };
}

/**
 * One STUN Binding request, straight from node, before any browser is involved.
 *
 * The gotcha this exists for: a container that is *running* is not a container
 * that is *reachable*. Docker Desktop publishes a UDP port through a userspace
 * proxy that comes up a beat after `docker run` returns, and coturn opens its
 * listeners across several threads. Without this, a suite that raced the
 * listener would report "no relay candidate" — indistinguishable from a broken
 * relay path, and the suite exists to tell those apart.
 *
 * A raw 20-byte Binding request rather than a log-scrape, because it measures
 * the thing that matters (a packet from this process reaches coturn and comes
 * back) and does not depend on coturn's log wording. RFC 5389 §6: type
 * `0x0001`, zero length, magic cookie `0x2112A442`, 12 random transaction
 * bytes; a success response is type `0x0101` echoing the transaction id.
 *
 * @param {number} port
 * @param {{ attempts?: number, each?: number }} [opts]
 * @returns {Promise<boolean>}
 */
export async function stunReachable(port, opts = {}) {
  const { attempts = 40, each = 250 } = opts;
  for (let i = 0; i < attempts; i += 1) {
    if (await bindingRequest(port, each)) return true;
  }
  return false;
}

/** @param {number} port @param {number} timeout */
function bindingRequest(port, timeout) {
  return new Promise((resolve) => {
    const tx = randomBytes(12);
    const msg = Buffer.alloc(20);
    msg.writeUInt16BE(0x0001, 0);
    msg.writeUInt16BE(0, 2);
    msg.writeUInt32BE(0x2112a442, 4);
    tx.copy(msg, 8);

    const sock = createSocket("udp4");
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        sock.close();
      } catch (_) {
        /* already closed */
      }
      resolve(v);
    };
    const timer = setTimeout(() => finish(false), timeout);
    sock.on("error", () => finish(false));
    sock.on("message", (buf) => {
      finish(
        buf.length >= 20 &&
          buf.readUInt16BE(0) === 0x0101 &&
          buf.subarray(8, 20).equals(tx)
      );
    });
    sock.send(msg, port, "127.0.0.1", (err) => {
      if (err) finish(false);
    });
  });
}

/** A free UDP port, so two runs on one machine never collide. */
function freeUdpPort() {
  return new Promise((resolve, reject) => {
    const sock = createSocket("udp4");
    sock.once("error", reject);
    sock.bind(0, "127.0.0.1", () => {
      const { port } = sock.address();
      sock.close(() => resolve(port));
    });
  });
}

/**
 * @typedef {object} Coturn
 * @property {number} port          published on 127.0.0.1
 * @property {string} url           `turn:127.0.0.1:<port>`
 * @property {string} username
 * @property {string} credential
 * @property {string} realm
 * @property {string} container
 * @property {() => string} logs    coturn's stdout so far
 * @property {() => void} stop
 */

/**
 * @typedef {object} CoturnStatus
 * @property {boolean} ok
 * @property {string} reason
 * @property {""|"absent"|"daemon"|"image"|"broken"} kind
 * @property {Coturn|null} relay
 */

/**
 * Bring up coturn, or say precisely why not.
 *
 * @returns {Promise<CoturnStatus>}
 */
export async function startCoturn() {
  const stand = (kind, reason) => ({ ok: false, reason, kind, relay: null });

  const ver = docker(["version", "--format", "{{.Server.Version}}"], 30000);
  if (!ver.ok) {
    const kind = classifyDockerFailure(ver.text);
    // A Docker that is present, running, and unhappy for some third reason is
    // news; it must not be filed under "no Docker".
    return stand(kind, `docker version failed: ${ver.text}`);
  }

  // Cached first, so a machine that has already pulled it never needs a
  // network, which is what makes the suite genuinely offline after one run.
  if (!docker(["image", "inspect", COTURN_IMAGE], 30000).ok) {
    const pulled = docker(["pull", COTURN_IMAGE], 300000);
    if (!pulled.ok) {
      const kind = classifyDockerFailure(pulled.text);
      return stand(
        kind === "broken" ? "image" : kind,
        `could not obtain ${COTURN_IMAGE}: ${pulled.text}`
      );
    }
  }

  const port = await freeUdpPort();
  const container = `basilisk-coturn-${process.pid}-${randomBytes(3).toString("hex")}`;
  const run = docker(
    [
      "run",
      "-d",
      "--rm",
      "--name",
      container,
      // Loopback only: this relay is for this machine and must not be an open
      // relay on the LAN for as long as the suite runs.
      "-p",
      `127.0.0.1:${port}:3478/udp`,
      COTURN_IMAGE,
      "-n", // no config file; every setting is on this command line and visible
      "--listening-port=3478",
      // Narrow, and never published — see the note at the top of this file.
      "--min-port=49160",
      "--max-port=49179",
      // Long-term credentials: what WebRTC uses, and what a browser silently
      // gets a 401 for when it is missing. A relay with no credentials yields
      // no relay candidate and looks exactly like a relay that is down.
      "--lt-cred-mech",
      `--realm=${TURN_REALM}`,
      `--user=${TURN_USER}:${TURN_CREDENTIAL}`,
      // No TLS: a self-signed cert would be refused by Chromium anyway, so
      // `turns:` is asserted as a *scheme* rather than as a live listener.
      "--no-tls",
      "--no-dtls",
      "--no-cli",
      "--fingerprint",
      "--log-file=stdout",
      // Per-packet lines (`incoming packet ALLOCATE processed, success`). Off
      // by default, and without them the log records only session open/close —
      // so the suite could confirm a relay pair from inside Chromium and had no
      // way to confirm from outside it that anything was ever relayed.
      "--verbose",
    ],
    120000
  );
  if (!run.ok) {
    const kind = classifyDockerFailure(run.text);
    return stand(kind, `could not start coturn: ${run.text}`);
  }

  const stop = () => {
    spawnSync("docker", ["rm", "-f", container], { encoding: "utf8", timeout: 60000 });
  };

  // Reachable, not merely running.
  if (!(await stunReachable(port))) {
    const logs = docker(["logs", container], 30000).text;
    stop();
    // Docker answered every call and the relay still will not speak STUN. That
    // is an environment fault worth a red run, not a reason to stand down.
    return stand("broken", `coturn started but answered no STUN binding on ${port}: ${logs}`);
  }

  return {
    ok: true,
    reason: "",
    kind: "",
    relay: {
      port,
      url: `turn:127.0.0.1:${port}`,
      username: TURN_USER,
      credential: TURN_CREDENTIAL,
      realm: TURN_REALM,
      container,
      logs: () => docker(["logs", container], 30000).text,
      stop,
    },
  };
}
