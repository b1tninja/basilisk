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
 * If the query looks like a fingerprint / key ID (hex with optional spaces / 0x),
 * return contiguous hex; otherwise return the trimmed original (email / name).
 * @param {string} raw
 * @returns {string}
 */
export function normalizeSearchQuery(raw) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return "";
  if (trimmed.includes("@")) return trimmed;
  const hex = normalizeFingerprintInput(trimmed);
  if (
    hex.length === 8 ||
    hex.length === 16 ||
    hex.length === 40 ||
    hex.length === 64
  ) {
    return hex;
  }
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
