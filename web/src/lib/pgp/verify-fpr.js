/**
 * Fingerprint comparison helpers for the /verify page.
 */

/**
 * Normalize a fingerprint or openpgp4fpr URI to 40 hex uppercase chars.
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
 * @param {string} expected
 * @param {string} scanned
 * @returns {{ ok: boolean, expected: string, scanned: string, reason: string }}
 */
export function compareFingerprints(expected, scanned) {
  const a = normalizeFingerprintInput(expected);
  const b = normalizeFingerprintInput(scanned);
  if (!a || a.length !== 40) {
    return { ok: false, expected: a, scanned: b, reason: "Expected fingerprint is missing or invalid." };
  }
  if (!b || b.length !== 40) {
    return { ok: false, expected: a, scanned: b, reason: "Scanned fingerprint is missing or invalid." };
  }
  if (a !== b) {
    return { ok: false, expected: a, scanned: b, reason: "Fingerprints do not match." };
  }
  return { ok: true, expected: a, scanned: b, reason: "Fingerprints match." };
}
