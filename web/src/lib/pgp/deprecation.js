/**
 * RFC 9580 §9.1 deprecation warnings for legacy algorithms.
 * Informational only — do not refuse interoperability.
 * @module lib/pgp/deprecation
 */

import { HASH, algoName } from "./algos.js";

/**
 * @param {{ algorithm?: string, algo?: string, curve?: string } | null | undefined} info
 * @returns {string[]}
 */
export function warningsForAlgoInfo(info) {
  /** @type {string[]} */
  const out = [];
  if (!info) return out;
  const alg = String(info.algorithm || info.algo || "").toLowerCase();
  if (alg.includes("eddsalegacy") || alg === "eddsa") {
    out.push(
      "EdDSA Legacy (algorithm 22) is deprecated in RFC 9580 §9.1. Prefer Ed25519 (27) for new keys."
    );
  }
  if (alg.includes("elgamal")) {
    out.push("ElGamal is deprecated in RFC 9580 §9.1. Prefer modern encryption algorithms.");
  }
  if (alg === "dsa") {
    out.push("DSA is deprecated in RFC 9580 §9.1. Prefer Ed25519 / ECDSA for signatures.");
  }
  return out;
}

/**
 * @param {number|string|null|undefined} hashAlgorithm
 * @returns {string[]}
 */
export function warningsForHashAlgo(hashAlgorithm) {
  if (hashAlgorithm == null) return [];
  const name =
    typeof hashAlgorithm === "string"
      ? hashAlgorithm.toLowerCase()
      : (algoName(HASH, hashAlgorithm) || "").toLowerCase();
  if (name === "sha-1" || name === "sha1" || hashAlgorithm === 2) {
    return [
      "This key's self-signature uses SHA-1, which is deprecated for signatures in RFC 9580 §9.1.",
    ];
  }
  return [];
}

/**
 * Collect deprecation notices for a primary key and optional subkeys / self-sig hash.
 * @param {{
 *   primary?: { algorithm?: string, algo?: string, curve?: string } | null,
 *   subkeys?: Array<{ algorithm?: string, algo?: string, curve?: string } | null>,
 *   hashAlgorithm?: number|string|null,
 * }} opts
 * @returns {string[]}
 */
export function collectDeprecationWarnings(opts = {}) {
  /** @type {string[]} */
  const warnings = [];
  const seen = new Set();
  const add = (list) => {
    for (const w of list) {
      if (!seen.has(w)) {
        seen.add(w);
        warnings.push(w);
      }
    }
  };
  add(warningsForAlgoInfo(opts.primary));
  for (const sub of opts.subkeys || []) {
    add(warningsForAlgoInfo(sub));
  }
  add(warningsForHashAlgo(opts.hashAlgorithm));
  return warnings;
}
