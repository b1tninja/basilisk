/**
 * Secure passphrase generation using the EFF Large Wordlist — the de facto
 * standard diceware list (default in the `diceware` tool, prefix-free,
 * designed for memorability by Joseph Bonneau / EFF, 2016).
 *
 * Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
 * SHA-256: addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e
 * The file ships verbatim (dice numbers included) so it can be verified
 * against EFF's published checksum.
 *
 * 7776 words = 6^5 → log2(7776) ≈ 12.925 bits per word, sampled with
 * crypto.getRandomValues + rejection sampling (no modulo bias).
 * EFF recommends a minimum of six words (~77.5 bits).
 *
 * Character mode: uniform random over a 69-char alphabet via rejection
 * sampling. ~6.1 bits per character.
 */

import effLargeWordlistRaw from "./eff-large-wordlist.txt?raw";

/**
 * EFF Large Wordlist — 7776 words parsed from the verbatim EFF file.
 * @type {string[]}
 */
export const WORDLIST = effLargeWordlistRaw
  .split("\n")
  .map((line) => line.trim().split("\t")[1])
  .filter(Boolean);

export const BITS_PER_WORD = Math.log2(7776); // ≈ 12.925

const CHAR_ALPHABET =
  "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_+=";
// 69 chars: excludes ambiguous l/I/1/O/0 to keep transcription-friendly.

/**
 * Uniform random integer in [0, max) via rejection sampling (no modulo bias).
 * @param {number} max exclusive upper bound, must be <= 65536
 * @returns {number}
 */
function randomIndex(max) {
  if (max <= 0 || max > 65536) throw new RangeError("max out of range");
  const limit = 65536 - (65536 % max);
  const buf = new Uint16Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

/**
 * Generate a diceware passphrase from the EFF Large Wordlist.
 * @param {number} [words=6] number of words (min 4, max 12); EFF recommends >= 6
 * @param {string} [separator="-"]
 * @returns {{ passphrase: string, bits: number, words: number }}
 */
export function generateWordPassphrase(words = 6, separator = "-") {
  const n = Math.max(4, Math.min(12, Math.floor(words)));
  const picked = [];
  for (let i = 0; i < n; i++) {
    picked.push(WORDLIST[randomIndex(WORDLIST.length)]);
  }
  return {
    passphrase: picked.join(separator),
    bits: Math.floor(n * BITS_PER_WORD),
    words: n,
  };
}

/**
 * Generate a random-character passphrase.
 * @param {number} [length=20] characters (min 12, max 64)
 * @returns {{ passphrase: string, bits: number, length: number }}
 */
export function generateCharPassphrase(length = 20) {
  const n = Math.max(12, Math.min(64, Math.floor(length)));
  const chars = [];
  for (let i = 0; i < n; i++) {
    chars.push(CHAR_ALPHABET[randomIndex(CHAR_ALPHABET.length)]);
  }
  const bitsPerChar = Math.log2(CHAR_ALPHABET.length);
  return {
    passphrase: chars.join(""),
    bits: Math.floor(n * bitsPerChar),
    length: n,
  };
}
