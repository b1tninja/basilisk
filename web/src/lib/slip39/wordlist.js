/**
 * Official SLIP-39 wordlist (1024 words).
 * Source: https://github.com/satoshilabs/slips/blob/master/slip-0039/wordlist.txt
 * SHA-256: bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3
 */

import raw from "./wordlist.txt?raw";

/** @type {string[]} */
export const WORDLIST = raw
  .split("\n")
  .map((l) => l.trim())
  .filter(Boolean);

if (WORDLIST.length !== 1024) {
  throw new Error(`SLIP-39 wordlist must have 1024 words, got ${WORDLIST.length}`);
}

/** @type {Map<string, number>} */
const INDEX = new Map(WORDLIST.map((w, i) => [w, i]));

/**
 * @param {string} word
 * @returns {number} index 0..1023
 */
export function wordIndex(word) {
  const i = INDEX.get(String(word || "").toLowerCase());
  if (i === undefined) throw new Error(`Unknown SLIP-39 word: ${word}`);
  return i;
}

/**
 * @param {number} index
 * @returns {string}
 */
export function wordAt(index) {
  if (index < 0 || index >= 1024) throw new RangeError("word index out of range");
  return WORDLIST[index];
}
