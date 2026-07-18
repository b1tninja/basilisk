/**
 * Split concatenated OpenPGP armored MESSAGE blocks.
 * @param {string} text
 * @returns {string[]}
 */
export function splitArmoredMessages(text) {
  const src = String(text || "");
  const re = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g;
  /** @type {string[]} */
  const out = [];
  let m;
  while ((m = re.exec(src)) !== null) {
    out.push(m[0].trim());
  }
  return out;
}

/**
 * Text remaining after removing armored MESSAGE blocks (for hybrid pastes
 * that interleave ciphertext with already-decrypted mnemonics).
 * @param {string} text
 * @returns {string}
 */
export function stripArmoredMessages(text) {
  return String(text || "").replace(
    /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g,
    "\n"
  );
}
