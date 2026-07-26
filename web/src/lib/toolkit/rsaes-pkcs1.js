/**
 * Pure-JS RSAES-PKCS1-v1_5 (RFC 8017 §7.2).
 * SubtleCrypto does not expose this algorithm; kept for interop only.
 * Prefer RSA-OAEP (`rsaoaep`) for new work.
 */

import { jwkFieldToBytes } from "./encode.js";

/**
 * @param {Uint8Array} bytes
 * @returns {bigint}
 */
function bytesToBigInt(bytes) {
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

/**
 * @param {bigint} n
 * @param {number} len
 * @returns {Uint8Array}
 */
function bigIntToBytes(n, len) {
  if (n < 0n) throw new Error("RSAES: negative integer");
  const out = new Uint8Array(len);
  let x = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("RSAES: integer too large for modulus");
  return out;
}

/**
 * @param {bigint} base
 * @param {bigint} exp
 * @param {bigint} mod
 */
function modPow(base, exp, mod) {
  if (mod <= 0n) throw new Error("RSAES: invalid modulus");
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/**
 * @param {JsonWebKey} jwk
 * @returns {{ n: bigint, e: bigint, d?: bigint, k: number }}
 */
function parseRsaJwk(jwk) {
  if (!jwk || jwk.kty !== "RSA") {
    throw new Error("RSAES-PKCS1-v1_5 requires an RSA JWK");
  }
  const nBytes = jwkFieldToBytes(jwk.n);
  const eBytes = jwkFieldToBytes(jwk.e);
  const n = bytesToBigInt(nBytes);
  const e = bytesToBigInt(eBytes);
  const k = nBytes.length;
  if (k < 11) throw new Error("RSAES: modulus too small");
  /** @type {{ n: bigint, e: bigint, d?: bigint, k: number }} */
  const out = { n, e, k };
  if (jwk.d) out.d = bytesToBigInt(jwkFieldToBytes(jwk.d));
  return out;
}

/**
 * Non-zero random PS for EME-PKCS1-v1_5.
 * @param {number} len
 */
function randomNonZero(len) {
  const out = new Uint8Array(len);
  let filled = 0;
  while (filled < len) {
    const chunk = crypto.getRandomValues(new Uint8Array(len - filled + 8));
    for (let i = 0; i < chunk.length && filled < len; i++) {
      if (chunk[i] !== 0) out[filled++] = chunk[i];
    }
  }
  return out;
}

/**
 * @param {JsonWebKey} jwk  public (or private) RSA JWK
 * @param {Uint8Array} plain
 * @returns {Uint8Array}
 */
export function rsaesPkcs1Encrypt(jwk, plain) {
  const { n, e, k } = parseRsaJwk(jwk);
  const mLen = plain.length;
  if (mLen > k - 11) {
    throw new Error(
      `RSAES-PKCS1-v1_5 plaintext too long (max ${k - 11} bytes for this key)`
    );
  }
  const ps = randomNonZero(k - mLen - 3);
  const em = new Uint8Array(k);
  em[0] = 0x00;
  em[1] = 0x02;
  em.set(ps, 2);
  em[2 + ps.length] = 0x00;
  em.set(plain, 3 + ps.length);
  const c = modPow(bytesToBigInt(em), e, n);
  return bigIntToBytes(c, k);
}

/**
 * @param {JsonWebKey} jwk  private RSA JWK (must include d)
 * @param {Uint8Array} cipher
 * @returns {Uint8Array}
 */
export function rsaesPkcs1Decrypt(jwk, cipher) {
  const { n, d, k } = parseRsaJwk(jwk);
  if (d == null) {
    throw new Error("RSAES-PKCS1-v1_5 decrypt requires a private RSA JWK (d)");
  }
  if (cipher.length !== k) {
    throw new Error(
      `RSAES-PKCS1-v1_5 ciphertext must be ${k} bytes (got ${cipher.length})`
    );
  }
  const em = bigIntToBytes(modPow(bytesToBigInt(cipher), d, n), k);
  if (em[0] !== 0x00 || em[1] !== 0x02) {
    throw new Error("RSAES-PKCS1-v1_5 decryption error (bad padding)");
  }
  let sep = -1;
  for (let i = 2; i < em.length; i++) {
    if (em[i] === 0x00) {
      sep = i;
      break;
    }
  }
  if (sep < 0 || sep < 10) {
    throw new Error("RSAES-PKCS1-v1_5 decryption error (bad padding)");
  }
  return em.subarray(sep + 1);
}

/** Tags applied to pipeline values produced by discouraged algorithms. */
export const LEGACY_CRYPTO_TAGS = ["legacy", "discouraged"];
