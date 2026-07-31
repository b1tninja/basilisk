/**
 * The ssh-agent protocol (draft-miller-ssh-agent), §30c.
 *
 * This is the piece that makes Basilisk a *real* agent rather than a
 * metaphor: `ssh`, `git` and `scp` speak this over `$SSH_AUTH_SOCK` (or
 * `\\.\pipe\openssh-ssh-agent` on Windows), and they do not care what is on
 * the other end. gpg-agent's own `enable-ssh-support` does exactly this —
 * being an ssh-agent is the established way a PGP keystore serves SSH
 * clients, not a detour.
 *
 * Deliberately transport-free: `handleAgentRequest` maps one request frame
 * to one response frame, so the whole protocol is testable with an
 * in-process client and no socket at all. The socket server (agent-server)
 * only does framing and I/O.
 *
 * Scope: request-identities and sign-request. Adding, removing and locking
 * keys are *not* implemented — the keys come from the vault or the CLI's
 * own store, and an agent that let a remote client add keys to your keyring
 * would be a different, worse thing. Unsupported messages get
 * SSH_AGENT_FAILURE, which is what every client already handles.
 */

import {
  buildPublicBlob,
  concatBytes,
  SshReader,
  writeString,
  writeText,
  writeU32,
} from "../src/lib/ssh/wire.js";

/** Message numbers we answer or emit. */
export const MSG = /** @type {const} */ ({
  FAILURE: 5,
  SUCCESS: 6,
  REQUEST_IDENTITIES: 11,
  IDENTITIES_ANSWER: 12,
  SIGN_REQUEST: 13,
  SIGN_RESPONSE: 14,
});

/** Signature flags a client may send (draft-miller-ssh-agent §5.3). */
export const SIGN_FLAGS = /** @type {const} */ ({
  RSA_SHA2_256: 0x02,
  RSA_SHA2_512: 0x04,
});

/** Frame a message body with its 4-byte length prefix. */
export function frame(body) {
  return concatBytes([writeU32(body.length), body]);
}

/**
 * Pull whole frames out of a rolling buffer.
 * @param {Uint8Array} buf
 * @returns {{ messages: Uint8Array[], rest: Uint8Array }}
 */
export function readFrames(buf) {
  /** @type {Uint8Array[]} */
  const messages = [];
  let off = 0;
  while (buf.length - off >= 4) {
    const len =
      ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;
    if (buf.length - off - 4 < len) break;
    messages.push(buf.subarray(off + 4, off + 4 + len));
    off += 4 + len;
  }
  return { messages, rest: buf.subarray(off) };
}

const failure = () => frame(new Uint8Array([MSG.FAILURE]));

/**
 * @typedef {object} AgentKey
 * @property {Uint8Array} publicBlob  RFC 4253 public blob
 * @property {string} comment
 * @property {boolean} [confirm]  Per-key confirmation, mirroring `ssh-add -c`
 * @property {(data: Uint8Array, flags: number) => Promise<{ sigType: string, sigBlob: Uint8Array }>} sign
 */

/**
 * Answer one agent request.
 *
 * @param {Uint8Array} body  One unframed request message
 * @param {{
 *   keys: () => Promise<AgentKey[]> | AgentKey[],
 *   confirm?: (key: AgentKey, data: Uint8Array) => Promise<boolean>,
 *   log?: (line: string) => void,
 * }} host
 * @returns {Promise<Uint8Array>}  One framed response
 */
export async function handleAgentRequest(body, host) {
  if (!body.length) return failure();
  const type = body[0];

  if (type === MSG.REQUEST_IDENTITIES) {
    const keys = await host.keys();
    const parts = [new Uint8Array([MSG.IDENTITIES_ANSWER]), writeU32(keys.length)];
    for (const k of keys) {
      parts.push(writeString(k.publicBlob), writeText(k.comment || ""));
    }
    return frame(concatBytes(parts));
  }

  if (type === MSG.SIGN_REQUEST) {
    const r = new SshReader(body.subarray(1));
    /** @type {Uint8Array} */
    let wanted;
    /** @type {Uint8Array} */
    let data;
    /** @type {number} */
    let flags;
    try {
      wanted = r.string("sign request key blob");
      data = r.string("sign request data");
      flags = r.u32("sign request flags");
    } catch (_) {
      return failure();
    }

    const keys = await host.keys();
    const b64 = (b) => Buffer.from(b).toString("base64");
    const key = keys.find((k) => b64(k.publicBlob) === b64(wanted));
    if (!key) return failure();

    if (key.confirm) {
      // §27f: without a way to ask a human, refusing is the correct
      // degradation for a gate whose whole point is a human. The agent stays
      // up — one refused request is not a reason to drop every other client.
      const ok = host.confirm ? await host.confirm(key, data).catch(() => false) : false;
      if (!ok) {
        host.log?.(
          `ssh-agent: refused a signature for ${key.comment || "a confirm-flagged key"} — confirmation unavailable or declined`
        );
        return failure();
      }
    }

    try {
      const { sigType, sigBlob } = await key.sign(data, flags);
      const sig = concatBytes([writeText(sigType), writeString(sigBlob)]);
      return frame(concatBytes([new Uint8Array([MSG.SIGN_RESPONSE]), writeString(sig)]));
    } catch (err) {
      host.log?.(`ssh-agent: signing failed — ${err?.message || err}`);
      return failure();
    }
  }

  // Everything else — add, remove, lock, extensions. Answering FAILURE is
  // both honest and what every client already handles.
  return failure();
}

/** Public blob from typed wire material, re-exported for host construction. */
export { buildPublicBlob };
