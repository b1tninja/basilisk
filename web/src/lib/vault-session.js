/**
 * Short-lived in-memory cache of unlocked vault private keys (agent session).
 * Does not persist to IndexedDB. TTL matches Encrypt/Decrypt/Toolkit idle scrub.
 */

export const VAULT_SESSION_TTL_MS = 5 * 60 * 1000;

/**
 * @typedef {object} SessionEntry
 * @property {string} armored
 * @property {string} fingerprint
 * @property {number} expiresAt
 */

/** @type {Map<string, SessionEntry>} */
const cache = new Map();

/**
 * @param {string} fingerprint
 * @returns {string}
 */
export function normalizeVaultFingerprint(fingerprint) {
  return String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
}

/**
 * @param {string} fingerprint
 * @returns {string|null} armored private key if still valid
 */
export function sessionGet(fingerprint) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  if (!fpr) return null;
  const entry = cache.get(fpr);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    sessionEvict(fpr);
    return null;
  }
  return entry.armored;
}

/**
 * Store unlocked armor and refresh TTL.
 * @param {string} fingerprint
 * @param {string} armored
 */
export function sessionPut(fingerprint, armored) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  if (!fpr || !armored) return;
  cache.set(fpr, {
    fingerprint: fpr,
    armored: String(armored),
    expiresAt: Date.now() + VAULT_SESSION_TTL_MS,
  });
}

/**
 * Extend TTL for an existing entry (or no-op).
 * @param {string} fingerprint
 */
export function sessionTouch(fingerprint) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  const entry = cache.get(fpr);
  if (!entry) return;
  if (Date.now() > entry.expiresAt) {
    sessionEvict(fpr);
    return;
  }
  entry.expiresAt = Date.now() + VAULT_SESSION_TTL_MS;
}

/**
 * @param {string} fingerprint
 */
export function sessionEvict(fingerprint) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  const entry = cache.get(fpr);
  if (entry) {
    try {
      // Best-effort: strings are immutable; drop reference.
      entry.armored = "";
    } catch (_) {
      /* ignore */
    }
    cache.delete(fpr);
  }
}

/** Clear all session entries (idle / secure-destroy). */
export function sessionClear() {
  for (const fpr of [...cache.keys()]) {
    sessionEvict(fpr);
  }
}

/**
 * Metas only — never armor (safe for agent chrome / DOM).
 * @returns {{ fingerprint: string, expiresAt: number }[]}
 */
export function sessionList() {
  const now = Date.now();
  /** @type {{ fingerprint: string, expiresAt: number }[]} */
  const out = [];
  for (const [fpr, entry] of cache) {
    if (now > entry.expiresAt) {
      sessionEvict(fpr);
      continue;
    }
    out.push({ fingerprint: entry.fingerprint, expiresAt: entry.expiresAt });
  }
  return out.sort((a, b) => a.expiresAt - b.expiresAt);
}

/**
 * Soonest expiry among unlocked keys, or null.
 * @returns {number|null}
 */
export function sessionEarliestExpiry() {
  const list = sessionList();
  if (!list.length) return null;
  return list[0].expiresAt;
}
