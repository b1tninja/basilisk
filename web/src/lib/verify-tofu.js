/**
 * Browser-local TOFU for /verify (first-verified timestamps).
 * @module lib/verify-tofu
 */

const STORAGE_KEY = "basilisk.verifyTofu.v1";

/**
 * @returns {Record<string, string>} fingerprint → ISO timestamp
 */
function readMap() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return Object.create(null);
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : Object.create(null);
  } catch (_) {
    return Object.create(null);
  }
}

/**
 * @param {Record<string, string>} map
 */
function writeMap(map) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch (_) {
    /* ignore quota / private mode */
  }
}

/**
 * @param {string} fingerprint
 * @returns {string} uppercase hex
 */
function cleanFpr(fingerprint) {
  return String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
}

/**
 * @param {string} fingerprint
 * @returns {string|null} ISO first-verified time, or null if never
 */
export function getFirstVerifiedAt(fingerprint) {
  const fpr = cleanFpr(fingerprint);
  if (!fpr) return null;
  const map = readMap();
  const v = map[fpr];
  return typeof v === "string" && v ? v : null;
}

/**
 * Record first verification if absent; return prior or new timestamp.
 * @param {string} fingerprint
 * @returns {{ firstSeen: string, isNew: boolean }}
 */
export function recordVerification(fingerprint) {
  const fpr = cleanFpr(fingerprint);
  const map = readMap();
  const prior = typeof map[fpr] === "string" && map[fpr] ? map[fpr] : null;
  if (prior) {
    return { firstSeen: prior, isNew: false };
  }
  const now = new Date().toISOString();
  map[fpr] = now;
  writeMap(map);
  return { firstSeen: now, isNew: true };
}
