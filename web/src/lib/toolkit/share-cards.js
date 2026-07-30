/**
 * Share cards — turning a split cell's artifacts into printable card models.
 *
 * A split emits a flat list of tiles: three share mnemonics, maybe three QR
 * SVGs, maybe an `envelope.asc`. What a person carrying a share out of the room
 * needs is none of those individually — it is one card per share, each saying
 * *which* share this is, *how many* of them reconstruct the secret, what
 * ceremony it belongs to, and when. This module is the join.
 *
 * Kept out of the widget so it can be unit-tested: the pairing rule (a QR tile
 * belongs to the share tile with the same `shareIndex`) and the threshold
 * inference are the parts that can be wrong in a way nobody notices until a
 * card has already been printed and the secret destroyed.
 *
 * The card model holds the mnemonic in cleartext, because a card that does not
 * is not a card. Producing one is therefore an explicit reveal, and the caller
 * is expected to gate it behind a deliberate action — see `ShareCards`.
 *
 * @module lib/toolkit/share-cards
 */

/**
 * @typedef {object} ShareCardArtifact
 * @property {string} [label]
 * @property {string} [filename]
 * @property {string} [content]
 * @property {string} [role]
 * @property {boolean} [sensitive]
 * @property {number} [shareIndex]
 * @property {string} [mime]
 * @property {{ shareOf?: number, threshold?: number }} [traits]
 */

/**
 * @typedef {object} ShareCard
 * @property {number} index      1-based share number
 * @property {number} total      how many shares exist
 * @property {number} threshold  how many are needed (0 when unknown)
 * @property {string} mnemonic
 * @property {string} qrSvg      inline SVG, or "" when the recipe emitted none
 * @property {string} label      ceremony label
 * @property {string} date       ISO date (YYYY-MM-DD)
 */

/**
 * Is this tile a share body (as opposed to its QR, or an envelope)?
 * @param {ShareCardArtifact} a
 */
function isShareBody(a) {
  if (!a) return false;
  if (a.role === "share") return true;
  // Pre-role tiles and `out @share` inside a foreach: a share index plus text
  // content is the honest signal. QR tiles carry an index too, hence the mime
  // guard rather than index alone.
  return !!a.shareIndex && a.role !== "qr" && !/svg/i.test(String(a.mime || ""));
}

/**
 * @param {ShareCardArtifact} a
 */
function isShareQr(a) {
  if (!a) return false;
  if (a.role === "qr") return true;
  return /svg/i.test(String(a.mime || "")) || /^\s*<svg/i.test(String(a.content || ""));
}

/**
 * Best available threshold for a set of share tiles.
 *
 * `traits.threshold` is what the engine stamps when it knows; a raw `foreach`
 * over a shares tip does not always. Zero means "not recorded", and the card
 * says so rather than inventing a number — a card claiming 2-of-3 for a 3-of-5
 * split is worse than a card that admits it does not know.
 *
 * @param {ShareCardArtifact[]} artifacts
 * @returns {number}
 */
export function inferThreshold(artifacts) {
  for (const a of artifacts || []) {
    const t = Number(a?.traits?.threshold);
    if (Number.isFinite(t) && t > 0) return t;
  }
  return 0;
}

/**
 * Build one card per share from a cell's artifacts.
 *
 * @param {ShareCardArtifact[]} artifacts
 * @param {{ label?: string, date?: string|Date, threshold?: number }} [opts]
 * @returns {ShareCard[]}
 */
export function collectShareCards(artifacts, opts = {}) {
  const list = Array.isArray(artifacts) ? artifacts : [];
  const bodies = list.filter(isShareBody);
  if (!bodies.length) return [];

  /** @type {Map<number, string>} */
  const qrByIndex = new Map();
  for (const a of list) {
    if (!isShareQr(a)) continue;
    const idx = Number(a.shareIndex);
    if (!idx) continue;
    qrByIndex.set(idx, String(a.content || ""));
  }

  const threshold =
    Number(opts.threshold) > 0 ? Number(opts.threshold) : inferThreshold(list);
  const date =
    opts.date instanceof Date
      ? opts.date.toISOString().slice(0, 10)
      : String(opts.date || new Date().toISOString().slice(0, 10));
  const label = String(opts.label || "").trim();

  const sorted = [...bodies].sort(
    (a, b) => (Number(a.shareIndex) || 0) - (Number(b.shareIndex) || 0)
  );
  const total = sorted.length;
  return sorted.map((a, i) => {
    const index = Number(a.shareIndex) || i + 1;
    return {
      index,
      total,
      threshold,
      mnemonic: String(a.content || "").trim(),
      qrSvg: qrByIndex.get(index) || "",
      label,
      date,
    };
  });
}

/**
 * The sentence printed on every card explaining the quorum.
 * @param {ShareCard} card
 * @returns {string}
 */
export function quorumLine(card) {
  if (!card) return "";
  if (card.threshold > 0) {
    return `Share ${card.index} of ${card.total} — any ${card.threshold} of these ${card.total} reconstruct the secret.`;
  }
  return `Share ${card.index} of ${card.total} — the recipe did not record how many are required.`;
}

/**
 * Words on the reveal gate. Kept here beside the model so the warning and the
 * thing being warned about cannot drift apart.
 * @param {number} count
 * @returns {string}
 */
export function revealWarning(count) {
  const n = Number(count) || 0;
  return (
    `Printing shows ${n === 1 ? "1 share" : `${n} shares`} in cleartext and sends ` +
    "them to a printer, which may spool them to disk or a print server. Do this " +
    "only on a printer you control, and hand each card to its holder directly."
  );
}
