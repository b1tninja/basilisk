/**
 * `basilisk agent --ssh` — the socket half of §30c.
 *
 * Node can bind both flavours of what OpenSSH clients look for: a Unix
 * domain socket at `$SSH_AUTH_SOCK`, and on Windows the named pipe
 * `\\.\pipe\openssh-ssh-agent`. `net.createServer` handles both; the path
 * is the only difference, which is why this file is short.
 *
 * The protocol lives in ssh-agent-protocol.js and knows nothing about
 * sockets. Here we do framing, connection lifetime, and the TTY prompt for
 * confirm-flagged keys.
 */

import net from "node:net";
import { createInterface } from "node:readline";
import { readFileSync } from "node:fs";

import { parseOpensshPrivateKey } from "../src/lib/ssh/openssh-key-v1.js";
import { sshFingerprint } from "../src/lib/ssh/fingerprint.js";
import { buildPublicBlob, concatBytes, writeMpint } from "../src/lib/ssh/wire.js";
import { handleAgentRequest, readFrames, SIGN_FLAGS } from "./ssh-agent-protocol.js";

/** The path an OpenSSH client will look for, per platform. */
export function defaultAgentPath() {
  if (process.platform === "win32") return "\\\\.\\pipe\\openssh-ssh-agent";
  return process.env.SSH_AUTH_SOCK || "/tmp/basilisk-ssh-agent.sock";
}

/**
 * Turn an openssh-key-v1 file into an agent key.
 *
 * The signing here is the raw SSH signature format (RFC 4253 / RFC 8332),
 * *not* sshsig: sshsig is the detached-file envelope, while the agent signs
 * the session identity blob a client hands it. Conflating the two is the
 * classic way an ssh-agent reimplementation fails against real clients.
 *
 * @param {string} path
 * @param {{ confirm?: boolean, passphrase?: string }} [opts]
 *   A passphrase-protected file opens with `passphrase`; without one the
 *   codec says so by name. The CLI has no prompt wired for it yet, so the
 *   practical route is still an unencrypted file or `ssh-keygen -p`.
 */
export async function agentKeyFromFile(path, opts = {}) {
  const material = await parseOpensshPrivateKey(readFileSync(path, "utf8"), {
    passphrase: String(opts.passphrase || ""),
  });
  const publicBlob = buildPublicBlob(material);
  const fingerprint = await sshFingerprint(publicBlob);
  return {
    publicBlob,
    comment: material.comment || path,
    fingerprint,
    confirm: !!opts.confirm,
    /** @param {Uint8Array} data @param {number} flags */
    async sign(data, flags) {
      if (material.type === "ssh-ed25519") {
        const { ed25519 } = await import("@noble/curves/ed25519.js");
        return { sigType: "ssh-ed25519", sigBlob: ed25519.sign(data, material.priv) };
      }
      if (material.type.startsWith("ecdsa-sha2-")) {
        const curve = { nistp256: "P-256", nistp384: "P-384", nistp521: "P-521" }[
          material.curveName
        ];
        const hash = { "P-256": "SHA-256", "P-384": "SHA-384", "P-521": "SHA-512" }[curve];
        const orderLen = { "P-256": 32, "P-384": 48, "P-521": 66 }[curve];
        const { pkcs8FromEcScalar } = await import("../src/lib/toolkit/encode.js");
        const key = await crypto.subtle.importKey(
          "pkcs8",
          pkcs8FromEcScalar(material.scalar, curve),
          { name: "ECDSA", namedCurve: curve },
          false,
          ["sign"]
        );
        const raw = new Uint8Array(
          await crypto.subtle.sign({ name: "ECDSA", hash }, key, data)
        );
        return {
          sigType: material.type,
          sigBlob: concatBytes([
            writeMpint(raw.subarray(0, orderLen)),
            writeMpint(raw.subarray(orderLen)),
          ]),
        };
      }
      if (material.type === "ssh-rsa") {
        // The client's flags pick the hash; bare ssh-rsa is SHA-1 and every
        // current server has stopped accepting it, so default to sha2-512
        // rather than emitting something that will simply be rejected.
        const useSha256 = (flags & SIGN_FLAGS.RSA_SHA2_256) !== 0;
        const sigType = useSha256 ? "rsa-sha2-256" : "rsa-sha2-512";
        const hash = useSha256 ? "SHA-256" : "SHA-512";
        const { rsaPrivateJwkFromSsh } = await import("./rsa-jwk.js");
        const key = await crypto.subtle.importKey(
          "jwk",
          rsaPrivateJwkFromSsh(material),
          { name: "RSASSA-PKCS1-v1_5", hash },
          false,
          ["sign"]
        );
        return {
          sigType,
          sigBlob: new Uint8Array(
            await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data)
          ),
        };
      }
      throw new Error(`ssh-agent: cannot sign with ${material.type}`);
    },
  };
}

/**
 * Ask on the terminal, mirroring `ssh-add -c`. Without a TTY there is
 * nobody to ask, and the protocol layer turns that into SSH_AGENT_FAILURE.
 * @param {{ comment: string, fingerprint?: string }} key
 * @param {Uint8Array} data
 */
export async function ttyConfirm(key, data) {
  if (!process.stdin.isTTY) return false;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  const hex = Buffer.from(digest).toString("hex").slice(0, 16);
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await new Promise((resolve) =>
      rl.question(
        `Allow use of ${key.comment}${key.fingerprint ? ` (${key.fingerprint})` : ""}? ` +
          `payload sha256:${hex}… [y/N] `,
        resolve
      )
    );
    return /^y(es)?$/i.test(String(answer).trim());
  } finally {
    rl.close();
  }
}

/**
 * Start the agent. Returns the server plus the path it bound, so callers
 * (and tests) can connect without guessing.
 *
 * @param {{
 *   keys: import("./ssh-agent-protocol.js").AgentKey[],
 *   path?: string,
 *   confirm?: (key: *, data: Uint8Array) => Promise<boolean>,
 *   log?: (line: string) => void,
 * }} opts
 */
export function startSshAgent(opts) {
  const path = opts.path || defaultAgentPath();
  const log = opts.log || (() => {});
  const host = {
    keys: () => opts.keys,
    confirm: opts.confirm || ttyConfirm,
    log,
  };

  const server = net.createServer((socket) => {
    /** @type {Uint8Array} */
    let buf = new Uint8Array(0);
    socket.on("data", async (chunk) => {
      buf = concatBytes([buf, new Uint8Array(chunk)]);
      const { messages, rest } = readFrames(buf);
      buf = rest;
      for (const msg of messages) {
        try {
          socket.write(Buffer.from(await handleAgentRequest(msg, host)));
        } catch (err) {
          log(`ssh-agent: request failed — ${err?.message || err}`);
        }
      }
    });
    // A client hanging up mid-request is ordinary (ssh exits); it must never
    // take the agent down with it.
    socket.on("error", () => socket.destroy());
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, () => resolve({ server, path }));
  });
}
