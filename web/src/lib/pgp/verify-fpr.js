/**
 * Fingerprint comparison helpers for the /verify page.
 */

/**
 * Normalize a fingerprint or openpgp4fpr URI to hex uppercase chars.
 * Accepts v4 (40) and v6 (64) lengths.
 * @param {string} raw
 * @returns {string}
 */
export function normalizeFingerprintInput(raw) {
  let s = String(raw || "").trim();
  const m = s.match(/openpgp4fpr:([0-9a-fA-F]+)/i);
  if (m) s = m[1];
  s = s.replace(/^0x/i, "").replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  return s;
}

/**
 * Common OpenPGP hex identity lengths we normalize for search.
 * 8 = short key ID (allowed; UI shows collision warning); 16 = long key ID;
 * 32 = half v4 fingerprint; 40 = v4 fingerprint; 64 = v6 fingerprint.
 */
const SEARCH_HEX_LENGTHS = new Set([8, 16, 32, 40, 64]);

/* ───────────────── pulling ids out of pasted text ───────────────── */

/**
 * The separators that appear *inside* one printed fingerprint.
 *
 * Space and tab because `formatFingerprint` prints hex in four-character
 * blocks — every fingerprint this product shows a person is grouped, so a
 * grouped fingerprint is the normal thing to be handed back. Colon because
 * `openpgp4fpr:` URIs and QR payloads use one, hyphen because people type one.
 *
 * Newline and comma are deliberately absent: both separate one fingerprint
 * from the *next* in the forms this product emits — `hashForJoin` writes
 * `#j=a,b`, and a paste box gets one per line. Folding either in here would
 * join two grouped fingerprints across the break into a single 80-character
 * run and lose both of them.
 */
const FPR_SEPARATORS = /[ \t:-]+/;

/** One hex run, or several joined by those separators. */
const HEX_RUN = /[0-9a-fA-F]+(?:[ \t:-]+[0-9a-fA-F]+)*/g;

/**
 * @param {number} n
 * @returns {boolean} whether that many hex characters is a fingerprint —
 *   40 for v4, 64 for v6, and nothing else.
 */
function isFprLength(n) {
  return n === 40 || n === 64;
}

/**
 * Every hex value pasted text unambiguously contains.
 *
 * Extraction and normalisation used to sit at opposite ends of the codebase
 * with different alphabets — `parseInviteAudience` matched a *contiguous*
 * `[0-9a-fA-F]{40,64}` and only then handed the result to something that knew
 * about spaces and colons. A grouped fingerprint is ten runs of four, so it
 * matched nothing at all, and the product's own printed form was the one form
 * its paste box refused. This module is where both now live.
 *
 * A run is read in two passes because prose is noisy. A token that is *itself*
 * a whole fingerprint stands alone — that is `<fpr> <fpr>`, and the `f:` a
 * bare `openpgp4fpr:` prefix leaves in front of one. Everything else is read
 * as grouping, and only within a stretch of tokens that are all the same
 * width: a printed fingerprint is uniform blocks of four, so the stray `e` in
 * “here: AABB CCDD …” ends its own stretch instead of being absorbed into the
 * fingerprint behind it and taking the length to 41.
 *
 * What is left over is left over. Two fingerprints run together, or two
 * grouped ones with a single space between, are a length no split can justify
 * — and picking one anyway is how `{40,64}` came to match the first 64
 * characters of an 80-character pair and hand back an id belonging to nobody.
 *
 * @param {string} text
 * @returns {string[]} uppercase hex, in the order encountered, one entry per
 *   reading — including lengths that are not fingerprints, which is what lets
 *   `findShortKeyIds` see a key id this can never accept
 */
function hexReadings(text) {
  /** @type {string[]} */
  const out = [];
  for (const match of String(text || "").match(HEX_RUN) || []) {
    const tokens = match.split(FPR_SEPARATORS).filter(Boolean);
    /** @type {string[]} */
    let group = [];
    const flush = () => {
      if (group.length) out.push(group.join("").toUpperCase());
      group = [];
    };
    for (const token of tokens) {
      if (isFprLength(token.length)) {
        flush();
        out.push(token.toUpperCase());
        continue;
      }
      if (group.length && group[0].length !== token.length) flush();
      group.push(token);
    }
    flush();
  }
  return out;
}

/**
 * The fingerprints in a paste — the only place text is searched for one.
 *
 * The anti-drift guard is a round trip: everything `formatFingerprint` can
 * print, this recovers, v4 and v6, singly and in the lists this product emits.
 * That is the property that was violated, and it fails loudly if either end
 * changes.
 *
 * @param {string} text
 * @returns {string[]} uppercase, each one once, in the order encountered
 */
export function findFingerprints(text) {
  return [...new Set(hexReadings(text).filter((hex) => isFprLength(hex.length)))];
}

/**
 * Hex lengths that name a key without identifying one: 8, 16 and 32.
 *
 * Derived from `SEARCH_HEX_LENGTHS` rather than listed again, so search and
 * this cannot come to disagree about which lengths are the short ones.
 */
const SHORT_ID_HEX_LENGTHS = new Set(
  [...SEARCH_HEX_LENGTHS].filter((n) => !isFprLength(n))
);

/**
 * The short key ids in a paste — the ones search accepts and a room cannot use.
 *
 * A short id is a *suffix* of a fingerprint, so more than one key can answer to
 * it; the search page already carries that warning. It matters here because a
 * room is `SHA-256(hostname | sorted fingerprints)` — an id that names several
 * keys names no room, and without this the whole state reads as nothing having
 * happened.
 *
 * @param {string} text
 * @returns {string[]} uppercase, each one once, in the order encountered
 */
export function findShortKeyIds(text) {
  return [
    ...new Set(hexReadings(text).filter((hex) => SHORT_ID_HEX_LENGTHS.has(hex.length))),
  ];
}

/**
 * True when the query is only hex (optional 0x / spaces / colons) — not email/name.
 * @param {string} raw
 * @returns {boolean}
 */
export function looksLikeHexFingerprintQuery(raw) {
  const trimmed = String(raw || "").trim();
  if (!trimmed || trimmed.includes("@")) return false;
  let s = trimmed.replace(/^0x/i, "");
  s = s.replace(/[\s:]+/g, "");
  return s.length > 0 && /^[0-9a-fA-F]+$/.test(s);
}

/**
 * If the query looks like a fingerprint / key ID at a common hex length
 * (8 / 16 / 32 / 40 / 64), return contiguous hex. Otherwise return the trimmed
 * original (email / name / non-standard hex lengths).
 * @param {string} raw
 * @returns {string}
 */
export function normalizeSearchQuery(raw) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return "";
  if (trimmed.includes("@")) return trimmed;
  if (!looksLikeHexFingerprintQuery(trimmed)) return trimmed;
  const hex = normalizeFingerprintInput(trimmed);
  if (SEARCH_HEX_LENGTHS.has(hex.length)) return hex;
  return trimmed;
}

/**
 * @param {string} hex
 * @returns {boolean}
 */
function isValidFprLength(hex) {
  return isFprLength(hex.length);
}

/**
 * @param {string} expected
 * @param {string} scanned
 * @returns {{ ok: boolean, expected: string, scanned: string, reason: string }}
 */
export function compareFingerprints(expected, scanned) {
  const a = normalizeFingerprintInput(expected);
  const b = normalizeFingerprintInput(scanned);
  if (!a || !isValidFprLength(a)) {
    return {
      ok: false,
      expected: a,
      scanned: b,
      reason: "Expected fingerprint is missing or invalid.",
    };
  }
  if (!b || !isValidFprLength(b)) {
    return {
      ok: false,
      expected: a,
      scanned: b,
      reason: "Scanned fingerprint is missing or invalid.",
    };
  }
  if (a !== b) {
    return { ok: false, expected: a, scanned: b, reason: "Fingerprints do not match." };
  }
  return { ok: true, expected: a, scanned: b, reason: "Fingerprints match." };
}
