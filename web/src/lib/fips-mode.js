/**
 * Basilisk FIPS-mode preference (POST/CAST verified-suites only).
 * Not a NIST FIPS 140 certificate — product posture only.
 */

export const FIPS_MODE_STORAGE_KEY = "basilisk.fipsMode";

/** @type {boolean|null} */
let _memory = null;

/**
 * @returns {boolean}
 */
export function getFipsMode() {
  if (_memory != null) return _memory;
  try {
    if (typeof localStorage === "undefined") return false;
    return localStorage.getItem(FIPS_MODE_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

/**
 * @param {boolean} on
 */
export function setFipsMode(on) {
  _memory = !!on;
  try {
    if (typeof localStorage === "undefined") return;
    if (on) localStorage.setItem(FIPS_MODE_STORAGE_KEY, "1");
    else localStorage.removeItem(FIPS_MODE_STORAGE_KEY);
  } catch {
    /* private mode / blocked storage — memory still holds the value */
  }
}

/** Operator-facing disclaimer (tooltips / docs). */
export const FIPS_MODE_DISCLAIMER =
  "Verified suites only (POST/CAST). Not a FIPS 140 certificate.";
