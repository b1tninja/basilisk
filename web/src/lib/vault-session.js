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
 * @property {boolean|undefined} locked  see `sessionPut`
 */

/** @type {Map<string, SessionEntry>} */
const cache = new Map();

/**
 * Kind-shaped id pattern (§28a): ssh ids are `SHA256:` + 43 chars of
 * unpadded base64 over the RFC 4253 public blob; raw ids the same over the
 * SPKI DER, prefixed `spki:`. Case and `+/` are significant in base64, so
 * these must pass through untouched — the hex normalization below would
 * destroy them (`SHA256:Ur1h…` → `A256`, which then matches nothing).
 */
const KIND_SHAPED_ID = /^(spki:)?SHA256:[A-Za-z0-9+/]{43}$/;

/**
 * What kind of key an id of this shape belongs to.
 *
 * The shapes above are already load-bearing — they are why `normalizeVaultFingerprint`
 * passes some ids through untouched — so the kind is readable from the id
 * alone, and reading it here keeps that knowledge in the module that owns it.
 * The caller is the notebook's key list, which folds in session-only keys the
 * vault has no record of and therefore no `kind` for: without this they defaulted
 * to pgp and would be offered as candidates to sign a session invite.
 *
 * @param {string} fingerprint
 * @returns {"pgp"|"ssh"|"raw"}
 */
export function vaultKindFromId(fingerprint) {
  const raw = String(fingerprint || "").trim();
  if (raw.startsWith("spki:")) return "raw";
  if (raw.startsWith("SHA256:")) return "ssh";
  return "pgp";
}

/**
 * @param {string} fingerprint
 * @returns {string}
 */
export function normalizeVaultFingerprint(fingerprint) {
  const raw = String(fingerprint || "").trim();
  if (KIND_SHAPED_ID.test(raw)) return raw;
  return raw.toUpperCase().replace(/[^0-9A-F]/g, "");
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
 *
 * ## Why `locked` is carried, and why it is three-valued
 *
 * Opening the vault envelope is not the same as being able to sign, and the
 * chrome said it was. A `protection: "passphrase"` key is locked *twice* — the
 * vault's device-bound AES-GCM wrapper, and OpenPGP's own S2K inside it —
 * and `vault.unlockKey` only ever removes the outer one. So the armor cached
 * here may be a private key nothing can use yet, and "unlocked · 4:58 left"
 * beside it was a true statement about the envelope and a false one about the
 * key. The run found out later, deep inside `resolveGpgPrivateKey`, on
 * OpenPGP's own message.
 *
 * The caller establishes it because this module holds no key parser and should
 * not grow one: it is imported by the notebook chrome, its tests run in node in
 * milliseconds, and pulling OpenPGP in here to answer one boolean would cost
 * both. `vault-unlock.js` already has the armor in hand and is already async.
 *
 * `undefined` is a real third value: *nobody established it*. It is not
 * `false`, because defaulting to "ready to sign" is precisely the false claim
 * this exists to stop, and it is not `true`, because a spurious "needs a
 * passphrase" on a device key is a refusal naming a state the reader is not in.
 * Readers must treat it as "not known" and say nothing about it.
 *
 * @param {string} fingerprint
 * @param {string} armored
 * @param {{ locked?: boolean }} [opts]  `locked` — whether `armored` still
 *   carries OpenPGP S2K protection, i.e. whether a passphrase is still owed
 *   before this key can sign. Omit when it was not established.
 */
export function sessionPut(fingerprint, armored, opts = {}) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  if (!fpr || !armored) return;
  cache.set(fpr, {
    fingerprint: fpr,
    armored: String(armored),
    expiresAt: Date.now() + VAULT_SESSION_TTL_MS,
    locked: typeof opts.locked === "boolean" ? opts.locked : undefined,
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
 *
 * `locked` rides along for the reason it is stored: the chrome's whole job is
 * to say what a key can do, and the one fact separating "open" from "usable"
 * had no way to reach it. It is a boolean about the armor, not the armor.
 *
 * @returns {{ fingerprint: string, expiresAt: number, locked: boolean|undefined }[]}
 */
export function sessionList() {
  const now = Date.now();
  /** @type {{ fingerprint: string, expiresAt: number, locked: boolean|undefined }[]} */
  const out = [];
  for (const [fpr, entry] of cache) {
    if (now > entry.expiresAt) {
      sessionEvict(fpr);
      continue;
    }
    out.push({
      fingerprint: entry.fingerprint,
      expiresAt: entry.expiresAt,
      locked: entry.locked,
    });
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
