/**
 * Single source of truth for OpenPGP algorithm name maps + formatting.
 */

/** @type {Record<number, string>} */
export const PUBLIC_KEY_ALGOS = {
  1: "RSA (Encrypt or Sign)",
  2: "RSA Encrypt-Only",
  3: "RSA Sign-Only",
  16: "ElGamal",
  17: "DSA",
  18: "ECDH",
  19: "ECDSA",
  22: "EdDSA (legacy)",
  25: "X25519",
  26: "X448",
  27: "Ed25519",
  28: "Ed448",
};

/** @type {Record<number, string>} */
export const SYMMETRIC = {
  1: "IDEA",
  2: "TripleDES",
  3: "CAST5",
  4: "Blowfish",
  7: "AES-128",
  8: "AES-192",
  9: "AES-256",
  10: "Twofish",
};

/** @type {Record<number, string>} */
export const AEAD = {
  1: "EAX",
  2: "OCB",
  3: "GCM",
};

/** @type {Record<number, string>} */
export const HASH = {
  1: "MD5",
  2: "SHA-1",
  3: "RIPEMD-160",
  8: "SHA-256",
  9: "SHA-384",
  10: "SHA-512",
  11: "SHA-224",
};

/** @type {Record<number, string>} */
export const COMPRESSION = {
  0: "Uncompressed",
  1: "ZIP",
  2: "ZLIB",
  3: "BZip2",
};

/** @type {Record<number, string>} */
export const S2K_TYPES = {
  0: "simple",
  1: "salted",
  3: "iterated",
  4: "argon2",
};

/**
 * Resolve a numeric or string algorithm id against a name map.
 * @param {Record<number, string>} map
 * @param {number|string|null|undefined} value
 * @returns {string|null}
 */
export function algoName(map, value) {
  if (value == null) return null;
  if (typeof value === "string") return value;
  return map[value] || `algo ${value}`;
}

/**
 * Format OpenPGP.js key algorithm info for display.
 * @param {{ algorithm?: string, algo?: string, curve?: string, bits?: number } | null | undefined} info
 * @returns {string}
 */
export function formatAlgo(info) {
  if (!info) return "—";
  const parts = [info.algorithm || info.algo || ""];
  if (info.curve) parts.push(info.curve);
  if (info.bits) parts.push(`${info.bits}-bit`);
  return parts.filter(Boolean).join(" / ") || "—";
}

/**
 * Normalize S2K type from OpenPGP.js (numeric enum or string name).
 * @param {{ type?: number|string } | null | undefined} s2k
 * @returns {string|null}
 */
export function s2kTypeName(s2k) {
  if (!s2k || s2k.type == null) return null;
  if (typeof s2k.type === "string") return s2k.type;
  return S2K_TYPES[s2k.type] || String(s2k.type);
}
