/**
 * The openssh-key-v1 private-key container (§29, design_handoff_agent_ssh).
 *
 * The format OpenSSH has written since 7.8 (PROTOCOL.key): an armored blob
 * holding `"openssh-key-v1\0"`, cipher/KDF names, the public blob, and a
 * (possibly encrypted) private section. This module reads and writes the
 * **unencrypted** form only — the encrypted form's KDF is `bcrypt_pbkdf`,
 * which no Web API provides, and a passphrase-protected file is refused by
 * name (§29f) rather than half-supported. Vault protection (§28) is the
 * story for keys at rest.
 */

import { base64ToBytes, bytesToBase64 } from "../toolkit/encode.js";
import {
  ECDSA_CURVES,
  SshReader,
  buildPublicBlob,
  concatBytes,
  parsePublicBlob,
  writeMpint,
  writeString,
  writeText,
  writeU32,
} from "./wire.js";

const MAGIC = "openssh-key-v1\0";
const ARMOR = "OPENSSH PRIVATE KEY";

/** §29f, verbatim — asserted by tests; the wording is the feature. */
export const ENCRYPTED_KEY_MESSAGE =
  'This key is passphrase-protected with bcrypt, which Basilisk cannot run yet. Decrypt it outside (`ssh-keygen -p -N ""`) or import the key another way.';

const TE = new TextEncoder();
const TD = new TextDecoder();

/** @param {string} pem */
function unarmor(pem) {
  const m = String(pem || "").match(
    /-----BEGIN OPENSSH PRIVATE KEY-----\r?\n([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/
  );
  if (!m) throw new Error("openssh-key-v1: no OPENSSH PRIVATE KEY armor found");
  return base64ToBytes(m[1].replace(/\s+/g, ""));
}

/** ssh-keygen wraps this armor at 70 columns; match it so exports diff clean. */
function armor(bytes) {
  const b64 = bytesToBase64(bytes);
  const lines = b64.match(/.{1,70}/g) || [];
  return `-----BEGIN ${ARMOR}-----\n${lines.join("\n")}\n-----END ${ARMOR}-----\n`;
}

/**
 * Parse an unencrypted openssh-key-v1 PEM into typed key material.
 *
 * @param {string} pem
 * @returns {{
 *   type: string,
 *   publicBlob: Uint8Array,
 *   comment: string,
 *   pub?: Uint8Array, priv?: Uint8Array,
 *   curveName?: string, point?: Uint8Array, scalar?: Uint8Array,
 *   n?: Uint8Array, e?: Uint8Array, d?: Uint8Array,
 *   iqmp?: Uint8Array, p?: Uint8Array, q?: Uint8Array,
 * }}
 *   ed25519 → `pub` (32) and `priv` (the 32-byte seed; the container's
 *   64-byte field is seed‖pub and the redundant half is checked, then
 *   dropped). ecdsa → `curveName`/`point`/`scalar`. rsa → `n e d iqmp p q`.
 */
export function parseOpensshPrivateKey(pem) {
  const outer = new SshReader(unarmor(pem));
  const magic = outer.bytes.subarray(0, MAGIC.length);
  if (TD.decode(magic) !== MAGIC) {
    throw new Error("openssh-key-v1: bad magic (not an OpenSSH private key)");
  }
  outer.off = MAGIC.length;

  const cipher = outer.text("cipher name");
  const kdf = outer.text("kdf name");
  outer.string("kdf options");
  if (cipher !== "none" || kdf !== "none") {
    throw new Error(ENCRYPTED_KEY_MESSAGE);
  }
  const nkeys = outer.u32("key count");
  if (nkeys !== 1) {
    throw new Error(`openssh-key-v1: expected 1 key, found ${nkeys}`);
  }
  const publicBlob = new Uint8Array(outer.string("public key blob"));
  const pub = parsePublicBlob(publicBlob);

  const r = new SshReader(outer.string("private key section"));
  outer.done("openssh-key-v1 container");
  const check1 = r.u32("checkint 1");
  const check2 = r.u32("checkint 2");
  if (check1 !== check2) {
    // On an encrypted file this is where a wrong passphrase surfaces; on an
    // unencrypted one it means corruption.
    throw new Error("openssh-key-v1: checkint mismatch — file is corrupt");
  }
  const type = r.text("private key algorithm");
  if (type !== pub.type) {
    throw new Error(
      `openssh-key-v1: private key type "${type}" does not match public "${pub.type}"`
    );
  }

  /** @type {Record<string, *>} */
  let fields;
  if (type === "ssh-ed25519") {
    const pubAgain = r.string("ed25519 public key");
    const priv64 = r.string("ed25519 private key");
    if (priv64.length !== 64) {
      throw new Error(`openssh-key-v1: ed25519 private field must be 64 bytes, got ${priv64.length}`);
    }
    const seed = priv64.subarray(0, 32);
    const pubHalf = priv64.subarray(32);
    if (bytesToBase64(pubHalf) !== bytesToBase64(pubAgain)) {
      throw new Error("openssh-key-v1: ed25519 private field's public half disagrees");
    }
    fields = { pub: new Uint8Array(pubAgain), priv: new Uint8Array(seed) };
  } else if (type in ECDSA_CURVES) {
    const curveName = r.text("ecdsa curve name");
    const point = new Uint8Array(r.string("ecdsa public point"));
    const scalar = new Uint8Array(r.mpint("ecdsa private scalar"));
    fields = { curveName, point, scalar };
  } else if (type === "ssh-rsa") {
    fields = {
      n: new Uint8Array(r.mpint("rsa modulus")),
      e: new Uint8Array(r.mpint("rsa public exponent")),
      d: new Uint8Array(r.mpint("rsa private exponent")),
      iqmp: new Uint8Array(r.mpint("rsa iqmp")),
      p: new Uint8Array(r.mpint("rsa prime p")),
      q: new Uint8Array(r.mpint("rsa prime q")),
    };
  } else {
    throw new Error(`openssh-key-v1: unsupported key type "${type}"`);
  }

  const comment = r.text("comment");
  // Padding is 1,2,3,… up to the cipher block size (8 for "none").
  const pad = r.bytes.subarray(r.off);
  for (let i = 0; i < pad.length; i++) {
    if (pad[i] !== i + 1) {
      throw new Error("openssh-key-v1: bad padding in private section");
    }
  }
  return { type, publicBlob, comment, ...fields };
}

/**
 * Encode typed key material as an **unencrypted** openssh-key-v1 PEM.
 * The §29f warning belongs to the op that calls this, not here — this is
 * the codec, and a codec that editorialises gets copied around it.
 *
 * @param {ReturnType<typeof parseOpensshPrivateKey> | Record<string, *>} key
 * @param {{ comment?: string }} [opts]
 */
export function encodeOpensshPrivateKey(key, opts = {}) {
  const comment = opts.comment ?? key.comment ?? "";
  const publicBlob = key.publicBlob ? key.publicBlob : buildPublicBlob(key);

  /** @type {Uint8Array[]} */
  const priv = [];
  // checkint: random is what ssh-keygen does; the value is only compared
  // with its twin, so any 32-bit value round-trips.
  const check = new Uint8Array(4);
  crypto.getRandomValues(check);
  const checkU32 = writeU32((check[0] << 24) | (check[1] << 16) | (check[2] << 8) | check[3]);
  priv.push(checkU32, checkU32);
  priv.push(writeText(key.type));
  if (key.type === "ssh-ed25519") {
    priv.push(writeString(key.pub));
    priv.push(writeString(concatBytes([key.priv, key.pub])));
  } else if (key.type in ECDSA_CURVES) {
    priv.push(writeText(key.curveName), writeString(key.point), writeMpint(key.scalar));
  } else if (key.type === "ssh-rsa") {
    priv.push(
      writeMpint(key.n),
      writeMpint(key.e),
      writeMpint(key.d),
      writeMpint(key.iqmp),
      writeMpint(key.p),
      writeMpint(key.q)
    );
  } else {
    throw new Error(`openssh-key-v1: unsupported key type "${key.type}"`);
  }
  priv.push(writeText(comment));

  let section = concatBytes(priv);
  const blockSize = 8; // cipher "none"
  const padLen = (blockSize - (section.length % blockSize)) % blockSize;
  if (padLen) {
    const pad = new Uint8Array(padLen);
    for (let i = 0; i < padLen; i++) pad[i] = i + 1;
    section = concatBytes([section, pad]);
  }

  const container = concatBytes([
    TE.encode(MAGIC),
    writeText("none"),
    writeText("none"),
    writeString(new Uint8Array(0)),
    writeU32(1),
    writeString(publicBlob),
    writeString(section),
  ]);
  return armor(container);
}
