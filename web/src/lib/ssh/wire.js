/**
 * RFC 4253 wire primitives and the OpenSSH public-key formats built on them
 * (§29, design_handoff_agent_ssh).
 *
 * Everything SSH puts on a wire — public blobs, the openssh-key-v1
 * container, sshsig envelopes, the agent protocol — is the same three
 * primitives: uint32, length-prefixed string, and mpint (a string holding a
 * big-endian two's-complement integer). This module owns those primitives
 * and the public-key blob layer; the private container and signature
 * formats build on it.
 *
 * Malformed input fails naming the *field* being read, never a byte
 * offset — "truncated string: public key algorithm" tells the user which
 * part of which structure was cut, which is the difference between a
 * diagnosis and a hex dump.
 */

import { base64ToBytes, bytesToBase64 } from "../toolkit/encode.js";

/** Concatenate byte arrays. */
export function concatBytes(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const TE = new TextEncoder();
const TD = new TextDecoder();

/** Sequential reader over an RFC 4253 buffer. Every read names its field. */
export class SshReader {
  /** @param {Uint8Array} bytes */
  constructor(bytes) {
    this.bytes = bytes;
    this.off = 0;
  }

  /** @param {string} field */
  u32(field) {
    if (this.off + 4 > this.bytes.length) {
      throw new Error(`SSH wire: truncated uint32: ${field}`);
    }
    const b = this.bytes;
    const v =
      (b[this.off] << 24) | (b[this.off + 1] << 16) | (b[this.off + 2] << 8) | b[this.off + 3];
    this.off += 4;
    return v >>> 0;
  }

  /** Length-prefixed byte string. @param {string} field */
  string(field) {
    const len = this.u32(field);
    if (this.off + len > this.bytes.length) {
      throw new Error(`SSH wire: truncated string: ${field}`);
    }
    const out = this.bytes.subarray(this.off, this.off + len);
    this.off += len;
    return out;
  }

  /** Length-prefixed UTF-8 text. @param {string} field */
  text(field) {
    return TD.decode(this.string(field));
  }

  /** mpint, returned as unsigned big-endian bytes (leading 0x00 stripped). @param {string} field */
  mpint(field) {
    let b = this.string(field);
    while (b.length > 1 && b[0] === 0) b = b.subarray(1);
    return b;
  }

  remaining() {
    return this.bytes.length - this.off;
  }

  /** Assert the structure consumed its whole buffer. @param {string} what */
  done(what) {
    if (this.off !== this.bytes.length) {
      throw new Error(`SSH wire: ${this.remaining()} trailing bytes after ${what}`);
    }
  }
}

/** @param {number} v */
export function writeU32(v) {
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
}

/** @param {Uint8Array} bytes */
export function writeString(bytes) {
  return concatBytes([writeU32(bytes.length), bytes]);
}

/** @param {string} text */
export function writeText(text) {
  return writeString(TE.encode(text));
}

/** Unsigned big-endian bytes → mpint field (0x00 prefixed when the high bit is set). */
export function writeMpint(bytes) {
  let b = bytes;
  while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  if (b.length && b[0] & 0x80) b = concatBytes([new Uint8Array([0]), b]);
  if (b.length === 1 && b[0] === 0) b = new Uint8Array(0);
  return writeString(b);
}

/** ECDSA key-type name per curve, and back. */
export const ECDSA_CURVES = /** @type {const} */ ({
  "ecdsa-sha2-nistp256": "nistp256",
  "ecdsa-sha2-nistp384": "nistp384",
  "ecdsa-sha2-nistp521": "nistp521",
});

/** WebCrypto curve names for the SSH curve identifiers. */
export const NIST_CURVE_WEB = /** @type {const} */ ({
  nistp256: "P-256",
  nistp384: "P-384",
  nistp521: "P-521",
});

/**
 * Parse an RFC 4253 public-key blob into typed fields.
 *
 * @param {Uint8Array} blob
 * @returns {{ type: string, blob: Uint8Array } & Record<string, *>}
 *   ssh-ed25519 → `{ pub }`; ecdsa-sha2-* → `{ curveName, point }` (point is
 *   the uncompressed 0x04-prefixed SEC1 encoding); ssh-rsa → `{ e, n }`.
 */
export function parsePublicBlob(blob) {
  const r = new SshReader(blob);
  const type = r.text("public key algorithm");
  if (type === "ssh-ed25519") {
    const pub = r.string("ed25519 public key");
    if (pub.length !== 32) {
      throw new Error(`SSH wire: ed25519 public key must be 32 bytes, got ${pub.length}`);
    }
    r.done("ssh-ed25519 public key");
    return { type, pub, blob };
  }
  if (type in ECDSA_CURVES) {
    const curveName = r.text("ecdsa curve name");
    if (curveName !== ECDSA_CURVES[/** @type {keyof typeof ECDSA_CURVES} */ (type)]) {
      throw new Error(`SSH wire: curve name "${curveName}" does not match key type "${type}"`);
    }
    const point = r.string("ecdsa public point");
    if (point[0] !== 4) {
      throw new Error("SSH wire: ecdsa public point is not uncompressed (leading 0x04)");
    }
    r.done("ecdsa public key");
    return { type, curveName, point, blob };
  }
  if (type === "ssh-rsa") {
    const e = r.mpint("rsa public exponent");
    const n = r.mpint("rsa modulus");
    r.done("ssh-rsa public key");
    return { type, e, n, blob };
  }
  throw new Error(`SSH wire: unsupported key type "${type}"`);
}

/**
 * Build the RFC 4253 public blob from typed fields (inverse of
 * `parsePublicBlob`; `blob` on the input is ignored).
 * @param {{ type: string } & Record<string, *>} key
 */
export function buildPublicBlob(key) {
  if (key.type === "ssh-ed25519") {
    return concatBytes([writeText(key.type), writeString(key.pub)]);
  }
  if (key.type in ECDSA_CURVES) {
    return concatBytes([
      writeText(key.type),
      writeText(ECDSA_CURVES[/** @type {keyof typeof ECDSA_CURVES} */ (key.type)]),
      writeString(key.point),
    ]);
  }
  if (key.type === "ssh-rsa") {
    return concatBytes([writeText(key.type), writeMpint(key.e), writeMpint(key.n)]);
  }
  throw new Error(`SSH wire: unsupported key type "${key.type}"`);
}

/**
 * Parse the one-line public form (`ssh-ed25519 AAAA… comment`).
 * @param {string} line
 */
export function parsePublicLine(line) {
  const trimmed = String(line || "").trim();
  const m = trimmed.match(/^(\S+)\s+(\S+)(?:\s+(.*))?$/);
  if (!m) throw new Error("SSH public line: expected `<type> <base64> [comment]`");
  const blob = base64ToBytes(m[2]);
  const parsed = parsePublicBlob(blob);
  if (parsed.type !== m[1]) {
    throw new Error(
      `SSH public line: leading type "${m[1]}" does not match blob type "${parsed.type}"`
    );
  }
  return { ...parsed, comment: m[3] || "" };
}

/**
 * Format the one-line public form.
 * @param {Uint8Array} blob
 * @param {string} [comment]
 */
export function formatPublicLine(blob, comment = "") {
  const { type } = parsePublicBlob(blob);
  const b64 = bytesToBase64(blob);
  return comment ? `${type} ${b64} ${comment}` : `${type} ${b64}`;
}
