/**
 * The openssh-key-v1 private-key container (§29, design_handoff_agent_ssh).
 *
 * The format OpenSSH has written since 7.8 (PROTOCOL.key): an armored blob
 * holding `"openssh-key-v1\0"`, cipher/KDF names, the public blob, and a
 * (possibly encrypted) private section. Both forms round-trip here — the
 * encrypted one via `bcrypt_pbkdf` (see `bcrypt-pbkdf.js`) and `aes256-ctr`,
 * which is the pair `ssh-keygen` itself writes.
 *
 * Reading and writing are async because both halves of the encrypted path go
 * through `crypto.subtle` (SHA-512 inside the KDF, AES-CTR over the private
 * section). The unencrypted path does no async work but keeps the same
 * signature: one function that sometimes needs awaiting is the shape that
 * gets called wrong.
 *
 * A passphrase is not a substitute for vault protection (§28) — it is what
 * makes an *exported* file safe to move. Both stories are supported now.
 */

import { base64ToBytes, bytesToBase64 } from "../toolkit/encode.js";
import { bcryptPbkdf } from "./bcrypt-pbkdf.js";
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

/**
 * What `ssh-keygen` writes when you give it a passphrase, and therefore what
 * we write: AES-256 in counter mode, keyed by `bcrypt_pbkdf`. The 48 bytes
 * the KDF is asked for are the 32-byte key followed by the 16-byte counter
 * block, in that order.
 */
const CIPHER = "aes256-ctr";
const CIPHER_KEY_LEN = 32;
const CIPHER_IV_LEN = 16;
const CIPHER_BLOCK = 16;
const KDF = "bcrypt";
const SALT_LEN = 16;

/**
 * `ssh-keygen`'s own default (`sshkey.c`'s `DEFAULT_ROUNDS`), confirmed
 * against OpenSSH 10.3 output rather than remembered — it was 16 in older
 * releases, and writing 16 today would produce a file that opens fine but
 * is quietly weaker than the one `ssh-keygen -p` would have written.
 */
export const DEFAULT_KDF_ROUNDS = 24;

/** §29f, verbatim — asserted by tests; the wording is the feature. */
export const ENCRYPTED_KEY_MESSAGE =
  "This key is passphrase-protected. Give the passphrase to open it (Inputs → passphrase), or decrypt it outside with `ssh-keygen -p -N \"\"`.";

/** The other half of §29f: the passphrase arrived, and it was the wrong one. */
export const WRONG_PASSPHRASE_MESSAGE =
  "That passphrase does not open this key — the decrypted block failed its own checksum.";

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
 * Derive the cipher key and counter block for one container.
 *
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {number} rounds
 */
async function deriveCipherKey(passphrase, salt, rounds) {
  const derived = await bcryptPbkdf(
    TE.encode(passphrase),
    salt,
    CIPHER_KEY_LEN + CIPHER_IV_LEN,
    rounds
  );
  const key = await crypto.subtle.importKey(
    "raw",
    derived.subarray(0, CIPHER_KEY_LEN),
    "AES-CTR",
    false,
    ["encrypt", "decrypt"]
  );
  const counter = derived.slice(CIPHER_KEY_LEN);
  derived.fill(0);
  return { key, counter };
}

/**
 * AES-256-CTR over the private section. The whole 16-byte block is the
 * counter (`length: 128`), which is what OpenSSH's CTR does — a shorter
 * counter width would agree for short keys and diverge for long ones.
 *
 * CTR is its own inverse, so one function serves both directions.
 *
 * @param {CryptoKey} key
 * @param {Uint8Array} counter
 * @param {Uint8Array} bytes
 */
async function aesCtr(key, counter, bytes) {
  const out = await crypto.subtle.encrypt(
    { name: "AES-CTR", counter, length: 128 },
    key,
    bytes.slice()
  );
  return new Uint8Array(out);
}

/**
 * Parse an openssh-key-v1 PEM into typed key material.
 *
 * @param {string} pem
 * @param {{ passphrase?: string }} [opts]
 * @returns {Promise<{
 *   type: string,
 *   publicBlob: Uint8Array,
 *   comment: string,
 *   pub?: Uint8Array, priv?: Uint8Array,
 *   curveName?: string, point?: Uint8Array, scalar?: Uint8Array,
 *   n?: Uint8Array, e?: Uint8Array, d?: Uint8Array,
 *   iqmp?: Uint8Array, p?: Uint8Array, q?: Uint8Array,
 *   encrypted?: boolean, kdfRounds?: number,
 * }>}
 *   ed25519 → `pub` (32) and `priv` (the 32-byte seed; the container's
 *   64-byte field is seed‖pub and the redundant half is checked, then
 *   dropped). ecdsa → `curveName`/`point`/`scalar`. rsa → `n e d iqmp p q`.
 *   `encrypted` records how the file arrived, so a re-encode can keep a
 *   protected key protected instead of silently exporting it bare.
 */
export async function parseOpensshPrivateKey(pem, opts = {}) {
  const passphrase = String(opts.passphrase ?? "");
  const outer = new SshReader(unarmor(pem));
  const magic = outer.bytes.subarray(0, MAGIC.length);
  if (TD.decode(magic) !== MAGIC) {
    throw new Error("openssh-key-v1: bad magic (not an OpenSSH private key)");
  }
  outer.off = MAGIC.length;

  const cipher = outer.text("cipher name");
  const kdf = outer.text("kdf name");
  const kdfOptions = outer.string("kdf options");
  const encrypted = cipher !== "none" || kdf !== "none";
  let kdfRounds = 0;
  if (encrypted) {
    if (kdf !== KDF) {
      throw new Error(
        `openssh-key-v1: unsupported KDF "${kdf}" — only "${KDF}" (what ssh-keygen writes) is understood`
      );
    }
    if (cipher !== CIPHER) {
      // aes256-gcm and chacha20-poly1305 are legal here and carry an auth
      // tag this reader does not parse; naming the cipher beats failing
      // later with a length error.
      throw new Error(
        `openssh-key-v1: unsupported cipher "${cipher}" — this build reads "${CIPHER}". Re-encrypt with \`ssh-keygen -p -Z ${CIPHER}\`.`
      );
    }
    if (!passphrase) throw new Error(ENCRYPTED_KEY_MESSAGE);
  }
  const nkeys = outer.u32("key count");
  if (nkeys !== 1) {
    throw new Error(`openssh-key-v1: expected 1 key, found ${nkeys}`);
  }
  const publicBlob = new Uint8Array(outer.string("public key blob"));
  const pub = parsePublicBlob(publicBlob);

  let section = new Uint8Array(outer.string("private key section"));
  outer.done("openssh-key-v1 container");
  if (encrypted) {
    const kr = new SshReader(kdfOptions);
    const salt = new Uint8Array(kr.string("bcrypt salt"));
    kdfRounds = kr.u32("bcrypt rounds");
    kr.done("bcrypt kdf options");
    if (!salt.length) throw new Error("openssh-key-v1: bcrypt kdf options carry an empty salt");
    if (kdfRounds < 1) throw new Error("openssh-key-v1: bcrypt rounds must be at least 1");
    if (section.length % CIPHER_BLOCK !== 0) {
      throw new Error(
        `openssh-key-v1: encrypted section is ${section.length} bytes, not a multiple of the ${CIPHER_BLOCK}-byte block`
      );
    }
    const { key, counter } = await deriveCipherKey(passphrase, salt, kdfRounds);
    section = await aesCtr(key, counter, section);
  }

  const r = new SshReader(section);
  const check1 = r.u32("checkint 1");
  const check2 = r.u32("checkint 2");
  if (check1 !== check2) {
    // This is exactly where a wrong passphrase surfaces — the checkint pair
    // is the container's only integrity check (PROTOCOL.key §3), and saying
    // "corrupt" to someone who simply mistyped would send them hunting.
    throw new Error(encrypted ? WRONG_PASSPHRASE_MESSAGE : "openssh-key-v1: checkint mismatch — file is corrupt");
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
  // Padding is 1,2,3,… up to the cipher block size (8 for "none", 16 here).
  const pad = r.bytes.subarray(r.off);
  for (let i = 0; i < pad.length; i++) {
    if (pad[i] !== i + 1) {
      throw new Error("openssh-key-v1: bad padding in private section");
    }
  }
  return { type, publicBlob, comment, encrypted, kdfRounds, ...fields };
}

/**
 * Encode typed key material as an openssh-key-v1 PEM — unencrypted, or
 * passphrase-protected when `opts.passphrase` is a non-empty string.
 *
 * The §29f warning belongs to the op that calls this, not here — this is
 * the codec, and a codec that editorialises gets copied around it. What the
 * codec *does* owe the caller is that an empty passphrase means "no
 * encryption" and never "encrypted with nothing", which is why the check
 * below is on the string's length rather than on the key's presence.
 *
 * @param {Awaited<ReturnType<typeof parseOpensshPrivateKey>> | Record<string, *>} key
 * @param {{ comment?: string, passphrase?: string, rounds?: number }} [opts]
 * @returns {Promise<string>}
 */
export async function encodeOpensshPrivateKey(key, opts = {}) {
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

  const passphrase = String(opts.passphrase ?? "");
  let section = concatBytes(priv);
  const blockSize = passphrase ? CIPHER_BLOCK : 8; // 8 is the "none" cipher's
  const padLen = (blockSize - (section.length % blockSize)) % blockSize;
  if (padLen) {
    const pad = new Uint8Array(padLen);
    for (let i = 0; i < padLen; i++) pad[i] = i + 1;
    section = concatBytes([section, pad]);
  }

  if (!passphrase) {
    return armor(
      concatBytes([
        TE.encode(MAGIC),
        writeText("none"),
        writeText("none"),
        writeString(new Uint8Array(0)),
        writeU32(1),
        writeString(publicBlob),
        writeString(section),
      ])
    );
  }

  const rounds = Number(opts.rounds) > 0 ? Math.floor(Number(opts.rounds)) : DEFAULT_KDF_ROUNDS;
  const salt = new Uint8Array(SALT_LEN);
  crypto.getRandomValues(salt);
  const { key: cipherKey, counter } = await deriveCipherKey(passphrase, salt, rounds);
  section = await aesCtr(cipherKey, counter, section);

  return armor(
    concatBytes([
      TE.encode(MAGIC),
      writeText(CIPHER),
      writeText(KDF),
      // kdfoptions is itself a string holding `string salt` + `uint32 rounds`
      // (PROTOCOL.key §2) — a nested length prefix that is easy to drop.
      writeString(concatBytes([writeString(salt), writeU32(rounds)])),
      writeU32(1),
      writeString(publicBlob),
      writeString(section),
    ])
  );
}
