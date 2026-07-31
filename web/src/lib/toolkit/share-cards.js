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
 * ## Verifiable splits change what a card has to say
 *
 * Since the ceremony started splitting with `vss.split`, a card belongs to a
 * split that has a public identity — the commitments, and the public key they
 * commit to. Two consequences the card has to carry, because paper is the only
 * thing that survives the room:
 *
 * - **The recovery line has to be right.** It used to be hard-coded to
 *   `sss.combine`, which is wrong for every card this ceremony now prints:
 *   `vss.combine` is the conjugate, and a custodian following the printed
 *   instruction would have been told to run an op that rejects their shares.
 *   `recoveryLine` derives it from whether the set is verifiable.
 * - **The card has to name its split**, so a custodian holding it years later
 *   can tell whether the commitments document in front of them is the right
 *   one. The id is a *label*: matching split ids is how you notice you have the
 *   wrong document, not how you verify a share. `checkLine` says what actually
 *   verifies it.
 *
 * @module lib/toolkit/share-cards
 */

import { publicKeyOf } from "../quorum/vss.js";
import { splitIdFor } from "./share-check.js";

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
 * @property {boolean} verifiable  the split published commitments
 * @property {string} splitId    short label for the split, "" when not verifiable
 */

/**
 * Find the published commitments among a cell's tiles.
 *
 * `vss.commitments | out @commitments` writes an ordinary non-sensitive text
 * tile, so it arrives in the same flat list as the shares. Matched by content
 * rather than only by name: a ceremony author may relabel the slot, and a
 * document that parses as a commitments object *is* one.
 *
 * @param {ShareCardArtifact[]} artifacts
 * @returns {string[]|null}
 */
export function findCommitments(artifacts) {
  for (const a of artifacts || []) {
    const text = String(a?.content || "").trim();
    if (!text.startsWith("{") && !text.startsWith("[")) continue;
    try {
      const parsed = JSON.parse(text);
      const list = Array.isArray(parsed) ? parsed : parsed?.commitments;
      if (Array.isArray(list) && list.length) return list.map(String);
    } catch {
      /* not a commitments document */
    }
  }
  return null;
}

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
 * @param {{ label?: string, date?: string|Date, threshold?: number, commitments?: string[]|string|null }} [opts]
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

  // Commitments may be handed in (the ceremony knows where its own tile is) or
  // discovered in the same cell. A split id is only stamped when the point
  // parses — a card must not carry an id derived from a document that could
  // not be read, because the id's whole job is to be compared against one.
  const explicit = opts.commitments;
  const commitments = Array.isArray(explicit)
    ? explicit
    : typeof explicit === "string" && explicit.trim()
      ? findCommitments([{ content: explicit }])
      : findCommitments(list);
  let splitId = "";
  if (commitments?.length) {
    try {
      splitId = splitIdFor(publicKeyOf(commitments));
    } catch {
      splitId = "";
    }
  }
  const verifiable = !!splitId;

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
      verifiable,
      splitId,
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
 * The recipe printed on the card for putting the secret back together.
 *
 * Was hard-coded to `sss.combine`, which became wrong the moment the ceremony
 * switched to `vss.split`: `vss.combine` is the conjugate, `sss.combine` is not
 * a synonym for it, and a custodian following a printed instruction has no way
 * to notice the card is telling them to run the wrong op. Derived now, so the
 * two cannot drift again.
 *
 * `vss.verify` is included in the verifiable form deliberately. Recovery is the
 * moment a bad share does its damage — combining an unverified set returns a
 * *different* secret rather than an error — and the card is the only place the
 * instruction to check first will still exist.
 *
 * @param {ShareCard} card
 * @returns {string}
 */
export function recoveryLine(card) {
  return card?.verifiable
    ? "shares | blip39.decode | vss.verify commitments=@commitments | vss.combine"
    : "shares | blip39.decode | sss.combine";
}

/**
 * The sentence telling a holder how to check *this* card on its own.
 *
 * Only meaningful for a verifiable split, and says nothing when the split is
 * not one — an `sss` card genuinely cannot be checked in isolation, and a
 * reassuring instruction that silently fails is worse than no instruction.
 *
 * @param {ShareCard} card
 * @returns {string}
 */
export function checkLine(card) {
  if (!card?.verifiable) {
    return "This share cannot be checked on its own — it carries no commitments.";
  }
  return `Check this card against the published commitments for split ${card.splitId}.`;
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
