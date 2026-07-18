/**
 * Parse algorithm preference subpackets from a key's primary self-signature
 * (RFC 9580 §5.2.3.14–17, §5.2.3.25).
 * @module lib/pgp/preferences
 */

import { AEAD, COMPRESSION, HASH, SYMMETRIC, algoName } from "./algos.js";
import { notationsFromSignature } from "./notations.js";

/** RFC 9580 §5.2.3.25 — No-modify preference (bit 7 of first byte). */
const KEY_SERVER_NO_MODIFY = 0x80;

/**
 * @param {number[]|Uint8Array|null|undefined} values
 * @param {Record<number, string>} map
 * @returns {string[]}
 */
function mapAlgos(values, map) {
  if (!values || !values.length) return [];
  return [...values].map((v) => algoName(map, v) || `algo ${v}`);
}

/**
 * @param {import("openpgp").Key | null | undefined} key
 * @param {Date} [date]
 * @returns {Promise<{
 *   symmetric: string[],
 *   aead: string[],
 *   hash: string[],
 *   compression: string[],
 *   noModify: boolean,
 *   hashAlgorithm: number|string|null,
 *   notations: import("./notations.js").NotationEntry[],
 * }>}
 */
export async function readKeyPreferences(key, date = new Date()) {
  const empty = {
    symmetric: [],
    aead: [],
    hash: [],
    compression: [],
    noModify: false,
    hashAlgorithm: null,
    notations: [],
  };
  if (!key) return empty;
  try {
    const selfSig = await key.getPrimarySelfSignature(date);
    if (!selfSig) return empty;
    const ksp = selfSig.keyServerPreferences;
    let noModify = false;
    if (ksp && ksp.length) {
      noModify = !!(ksp[0] & KEY_SERVER_NO_MODIFY);
    }
    return {
      symmetric: mapAlgos(selfSig.preferredSymmetricAlgorithms, SYMMETRIC),
      aead: mapAlgos(selfSig.preferredAEADAlgorithms, AEAD),
      hash: mapAlgos(selfSig.preferredHashAlgorithms, HASH),
      compression: mapAlgos(selfSig.preferredCompressionAlgorithms, COMPRESSION),
      noModify,
      hashAlgorithm: selfSig.hashAlgorithm ?? null,
      notations: notationsFromSignature(selfSig),
    };
  } catch (_) {
    return empty;
  }
}
