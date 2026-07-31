/**
 * The sshsig detached-signature format (§29) — what `ssh-keygen -Y sign`
 * emits and `ssh-keygen -Y verify` checks, and the format git uses for
 * SSH-signed commits (OpenSSH PROTOCOL.sshsig).
 *
 * The envelope binds a *namespace* into the signed data, so a signature
 * made for `git` can never verify as a `file` signature — the check is
 * cryptographic, not advisory, and the mismatch error (§31c) says so.
 *
 * Math: ed25519 through `@noble/curves` (RFC 8032, deterministic — our
 * output is byte-identical to ssh-keygen's for the same key, payload and
 * namespace, and a fixture asserts exactly that); ECDSA and RSA through
 * SubtleCrypto. All of it rides the `webcrypto` CAST suite.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToBase64Url,
  pkcs8FromEcScalar,
} from "../toolkit/encode.js";
import {
  ECDSA_CURVES,
  NIST_CURVE_WEB,
  SshReader,
  buildPublicBlob,
  concatBytes,
  parsePublicBlob,
  writeMpint,
  writeString,
  writeText,
  writeU32,
} from "./wire.js";

const MAGIC = new TextEncoder().encode("SSHSIG");
const ARMOR = "SSH SIGNATURE";
const VERSION = 1;

/** Per-curve hash and the raw component length WebCrypto uses. */
const ECDSA_PARAMS = /** @type {const} */ ({
  nistp256: { hash: "SHA-256", orderLen: 32 },
  nistp384: { hash: "SHA-384", orderLen: 48 },
  nistp521: { hash: "SHA-512", orderLen: 66 },
});

/** @param {string} pem */
function unarmor(pem) {
  const m = String(pem || "").match(
    /-----BEGIN SSH SIGNATURE-----\r?\n([\s\S]*?)-----END SSH SIGNATURE-----/
  );
  if (!m) throw new Error("sshsig: no SSH SIGNATURE armor found");
  return base64ToBytes(m[1].replace(/\s+/g, ""));
}

/** ssh-keygen wraps sshsig armor at 70 columns; match it byte for byte. */
function armor(bytes) {
  const b64 = bytesToBase64(bytes);
  const lines = b64.match(/.{1,70}/g) || [];
  return `-----BEGIN ${ARMOR}-----\n${lines.join("\n")}\n-----END ${ARMOR}-----\n`;
}

/**
 * Parse an sshsig armor into its envelope fields.
 * @param {string} pem
 */
export function parseSshsig(pem) {
  const r = new SshReader(unarmor(pem));
  const magic = r.bytes.subarray(0, MAGIC.length);
  for (let i = 0; i < MAGIC.length; i++) {
    if (magic[i] !== MAGIC[i]) throw new Error("sshsig: bad magic (not an SSH signature)");
  }
  r.off = MAGIC.length;
  const version = r.u32("sshsig version");
  if (version !== VERSION) {
    throw new Error(`sshsig: unsupported version ${version} (expected ${VERSION})`);
  }
  const publicBlob = new Uint8Array(r.string("public key"));
  const namespace = r.text("namespace");
  r.string("reserved");
  const hashAlg = r.text("hash algorithm");
  if (hashAlg !== "sha512" && hashAlg !== "sha256") {
    throw new Error(`sshsig: unsupported hash algorithm "${hashAlg}"`);
  }
  const sig = new SshReader(r.string("signature"));
  r.done("sshsig envelope");
  const sigType = sig.text("signature algorithm");
  const sigBlob = new Uint8Array(sig.string("signature blob"));
  sig.done("signature");
  return { publicBlob, namespace, hashAlg, sigType, sigBlob };
}

/** The exact bytes an sshsig signature covers. */
async function signedData(payload, namespace, hashAlg) {
  const digest = new Uint8Array(
    await crypto.subtle.digest(hashAlg === "sha256" ? "SHA-256" : "SHA-512", payload)
  );
  return concatBytes([
    MAGIC,
    writeText(namespace),
    writeString(new Uint8Array(0)),
    writeText(hashAlg),
    writeString(digest),
  ]);
}

const b64u = (bytes) => bytesToBase64Url(bytes).replace(/=+$/, "");

/** @param {Uint8Array} b */
function bytesToBigInt(b) {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

/** @param {bigint} v  @param {number} [len]  fixed-length big-endian when given */
function bigIntToBytes(v, len) {
  let hex = v.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  if (len != null) {
    if (out.length > len) out = out.subarray(out.length - len);
    else if (out.length < len) {
      const padded = new Uint8Array(len);
      padded.set(out, len - out.length);
      out = padded;
    }
  }
  return out;
}

/** RSA private JWK from the container's n/e/d/p/q/iqmp (CRT exponents derived). */
function rsaPrivateJwk(key) {
  const d = bytesToBigInt(key.d);
  const p = bytesToBigInt(key.p);
  const q = bytesToBigInt(key.q);
  return {
    kty: "RSA",
    n: b64u(key.n),
    e: b64u(key.e),
    d: b64u(key.d),
    p: b64u(key.p),
    q: b64u(key.q),
    dp: b64u(bigIntToBytes(d % (p - 1n))),
    dq: b64u(bigIntToBytes(d % (q - 1n))),
    qi: b64u(key.iqmp),
  };
}

/** WebCrypto raw ECDSA (r‖s) → the SSH mpint-pair signature blob. */
function ecdsaRawToBlob(raw, orderLen) {
  const r = raw.subarray(0, orderLen);
  const s = raw.subarray(orderLen);
  return concatBytes([writeMpint(r), writeMpint(s)]);
}

/** SSH mpint-pair signature blob → WebCrypto raw (r‖s). */
function ecdsaBlobToRaw(blob, orderLen) {
  const r = new SshReader(blob);
  const rPart = r.mpint("ecdsa r");
  const sPart = r.mpint("ecdsa s");
  r.done("ecdsa signature blob");
  return concatBytes([
    bigIntToBytes(bytesToBigInt(rPart), orderLen),
    bigIntToBytes(bytesToBigInt(sPart), orderLen),
  ]);
}

/**
 * Sign a payload in sshsig format.
 *
 * @param {Uint8Array} payload
 * @param {Record<string, *>} key  Typed private material from
 *   `parseOpensshPrivateKey` (or the same shape built elsewhere).
 * @param {{ namespace?: string, hash?: "sha512"|"sha256" }} [opts]
 * @returns {Promise<string>} armored sshsig
 */
export async function sshsigSign(payload, key, opts = {}) {
  const namespace = opts.namespace || "file";
  const hashAlg = opts.hash || "sha512";
  if (!namespace) throw new Error("sshsig: namespace must not be empty");
  const publicBlob = key.publicBlob ? key.publicBlob : buildPublicBlob(key);
  const data = await signedData(payload, namespace, hashAlg);

  let sigType;
  let sigBlob;
  if (key.type === "ssh-ed25519") {
    sigType = "ssh-ed25519";
    sigBlob = ed25519.sign(data, key.priv);
  } else if (key.type in ECDSA_CURVES) {
    const curve = ECDSA_CURVES[/** @type {keyof typeof ECDSA_CURVES} */ (key.type)];
    const { hash, orderLen } = ECDSA_PARAMS[curve];
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8FromEcScalar(key.scalar, NIST_CURVE_WEB[curve]),
      { name: "ECDSA", namedCurve: NIST_CURVE_WEB[curve] },
      false,
      ["sign"]
    );
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash }, cryptoKey, data)
    );
    sigType = key.type;
    sigBlob = ecdsaRawToBlob(raw, orderLen);
  } else if (key.type === "ssh-rsa") {
    // ssh-keygen refuses to make new ssh-rsa (SHA-1) signatures for sshsig
    // and signs rsa-sha2-512; so do we.
    sigType = "rsa-sha2-512";
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      rsaPrivateJwk(key),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
      false,
      ["sign"]
    );
    sigBlob = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, data));
  } else {
    throw new Error(`sshsig: unsupported key type "${key.type}"`);
  }

  const envelope = concatBytes([
    MAGIC,
    writeU32(VERSION),
    writeString(publicBlob),
    writeText(namespace),
    writeString(new Uint8Array(0)),
    writeText(hashAlg),
    writeString(concatBytes([writeText(sigType), writeString(sigBlob)])),
  ]);
  return armor(envelope);
}

/**
 * Verify an sshsig signature over a payload.
 *
 * Fail-loud: throws naming the failure; returns `true` on success. The
 * namespace check precedes the math — a valid signature under the wrong
 * namespace is *meant* to fail, and the error explains that rather than
 * reporting a bad signature (§31c, exact string).
 *
 * @param {Uint8Array} payload
 * @param {string} signatureArmor
 * @param {{ namespace?: string, publicBlob?: Uint8Array }} [opts]
 *   `publicBlob` pins the signer: verification fails if the envelope's key
 *   differs. Without it, the envelope's own key is used — the caller then
 *   only learns "signed by the embedded key", which is why `ssh.verify`
 *   requires `key=`.
 */
export async function sshsigVerify(payload, signatureArmor, opts = {}) {
  const namespace = opts.namespace || "file";
  const sig = parseSshsig(signatureArmor);
  if (sig.namespace !== namespace) {
    throw new Error(
      `ssh.verify: signature was made under namespace "${sig.namespace}", but namespace="${namespace}" was requested — a signature never transfers between namespaces.`
    );
  }
  if (opts.publicBlob) {
    if (bytesToBase64(opts.publicBlob) !== bytesToBase64(sig.publicBlob)) {
      throw new Error("ssh.verify: signature was made by a different key than key= names");
    }
  }
  const pub = parsePublicBlob(sig.publicBlob);
  const data = await signedData(payload, sig.namespace, sig.hashAlg);

  let ok = false;
  if (pub.type === "ssh-ed25519") {
    if (sig.sigType !== "ssh-ed25519") {
      throw new Error(`sshsig: signature algorithm "${sig.sigType}" does not fit an ed25519 key`);
    }
    ok = ed25519.verify(sig.sigBlob, data, pub.pub);
  } else if (pub.type in ECDSA_CURVES) {
    if (sig.sigType !== pub.type) {
      throw new Error(`sshsig: signature algorithm "${sig.sigType}" does not fit "${pub.type}"`);
    }
    const curve = ECDSA_CURVES[/** @type {keyof typeof ECDSA_CURVES} */ (pub.type)];
    const { hash, orderLen } = ECDSA_PARAMS[curve];
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      pub.point,
      { name: "ECDSA", namedCurve: NIST_CURVE_WEB[curve] },
      false,
      ["verify"]
    );
    ok = await crypto.subtle.verify(
      { name: "ECDSA", hash },
      cryptoKey,
      ecdsaBlobToRaw(sig.sigBlob, orderLen),
      data
    );
  } else if (pub.type === "ssh-rsa") {
    const hash =
      sig.sigType === "rsa-sha2-512"
        ? "SHA-512"
        : sig.sigType === "rsa-sha2-256"
          ? "SHA-256"
          : null;
    if (!hash) {
      throw new Error(
        `sshsig: rsa signature algorithm "${sig.sigType}" is not supported (rsa-sha2-256/512 only)`
      );
    }
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: b64u(pub.n), e: b64u(pub.e) },
      { name: "RSASSA-PKCS1-v1_5", hash },
      false,
      ["verify"]
    );
    ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, sig.sigBlob, data);
  } else {
    throw new Error(`sshsig: unsupported key type "${pub.type}"`);
  }

  if (!ok) throw new Error("sshsig: signature does not verify over this payload");
  return true;
}
