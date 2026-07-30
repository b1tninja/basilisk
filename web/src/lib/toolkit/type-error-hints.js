/**
 * Reading a wanted type out of a validator message (design v2 §33c).
 *
 * Split out of `CellTypeErrors.tsx` so it can be tested without a React
 * renderer — this is the part that can be *wrong* rather than merely ugly, and
 * it is worth pinning. The component only draws what this returns.
 */

/**
 * The type an error says was wanted, or null when the message does not name
 * one.
 *
 * Deliberately conservative: the validator emits prose, so this matches only
 * the registry's own established phrasings rather than parsing arbitrary
 * English. A miss costs a suggestion; a false positive would point the author
 * at an op that cannot help, which is worse than saying nothing.
 *
 * @param {string} message
 * @returns {string|null}
 */
export function expectedTypeFrom(message) {
  const text = String(message || "");
  // When the validator already prescribes the fix ("… — add export pkcs8"),
  // stay quiet. The generic suggestion is drawn from the producer list in
  // registry order, so for `bytes` it offers `aes-cbc` — technically a
  // producer, useless as advice, and directly contradicting the specific
  // instruction sitting next to it. A second, worse answer is not help.
  if (/\b(add|use|try)\s+[a-z]/i.test(text)) return null;
  const accepted = text.match(/accepted:\s*([a-z-]+)/i);
  if (accepted) return accepted[1].toLowerCase();
  const expects = text.match(/expects\s+(?:DER\s+)?([a-z-]+)/i);
  if (expects) return expects[1].toLowerCase();
  return null;
}
