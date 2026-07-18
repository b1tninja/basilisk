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
