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
  return hex.length === 40 || hex.length === 64;
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
