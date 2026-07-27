/**
 * Device-local OpenPGP public key cache (IndexedDB `pubkeys` in basilisk-vault).
 *
 * Public armor only — never private key material. Complements trust.js ownertrust
 * marks and the private-key vault store.
 */

import { VAULT_PUBKEYS_STORE, withVaultStore } from "./vault.js";

/** Soft TTL before background revalidation is preferred (ms). */
export const PUBKEY_CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Max cached public keys (LRU by lastUsedAt / fetchedAt). */
export const PUBKEY_CACHE_MAX = 500;

/** @typedef {"basilisk"|"upstream"|"import"} PubkeyOrigin */

/**
 * @typedef {object} PubkeyCacheRecord
 * @property {string} fingerprint
 * @property {string} armored
 * @property {string[]} uids
 * @property {string} [email]
 * @property {string} [name]
 * @property {PubkeyOrigin} origin
 * @property {string} [sourceKeyserver]
 * @property {string} [approvalState]
 * @property {boolean} [revoked]
 * @property {string} [keyId]
 * @property {string} [keyExpiration]
 * @property {string} [userLabel]
 * @property {string} fetchedAt
 * @property {string} [lastUsedAt]
 */

/**
 * @param {string} fingerprint
 * @returns {string}
 */
function cleanFpr(fingerprint) {
  return String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
}

/**
 * @param {PubkeyCacheRecord} rec
 * @returns {boolean}
 */
export function isPubkeyCacheStale(rec) {
  const at = Date.parse(String(rec?.fetchedAt || ""));
  if (!Number.isFinite(at)) return true;
  return Date.now() - at > PUBKEY_CACHE_TTL_MS;
}

/**
 * @param {string} fingerprint
 * @returns {Promise<PubkeyCacheRecord|null>}
 */
export async function cacheGet(fingerprint) {
  const fpr = cleanFpr(fingerprint);
  if (fpr.length < 16) return null;
  try {
    const row = await withVaultStore(VAULT_PUBKEYS_STORE, "readonly", (store) =>
      store.get(fpr)
    );
    if (!row || typeof row !== "object") return null;
    if (!String(row.armored || "").includes("BEGIN PGP")) return null;
    return /** @type {PubkeyCacheRecord} */ (row);
  } catch (_) {
    return null;
  }
}

/**
 * @returns {Promise<PubkeyCacheRecord[]>}
 */
export async function cacheList() {
  try {
    const rows = await withVaultStore(VAULT_PUBKEYS_STORE, "readonly", (store) =>
      store.getAll()
    );
    return (Array.isArray(rows) ? rows : []).filter(
      (r) => r && String(r.armored || "").includes("BEGIN PGP")
    );
  } catch (_) {
    return [];
  }
}

/**
 * @param {string} fingerprint
 * @returns {Promise<void>}
 */
export async function cacheTouch(fingerprint) {
  const fpr = cleanFpr(fingerprint);
  if (!fpr) return;
  try {
    await withVaultStore(VAULT_PUBKEYS_STORE, "readwrite", (store) => {
      return new Promise((resolve, reject) => {
        const getReq = store.get(fpr);
        getReq.onerror = () => reject(getReq.error);
        getReq.onsuccess = () => {
          const existing = getReq.result;
          if (!existing) {
            resolve(null);
            return;
          }
          existing.lastUsedAt = new Date().toISOString();
          const putReq = store.put(existing);
          putReq.onsuccess = () => resolve(existing);
          putReq.onerror = () => reject(putReq.error);
        };
      });
    });
  } catch (_) {
    /* ignore */
  }
}

/**
 * @param {Omit<PubkeyCacheRecord, "fetchedAt"|"lastUsedAt"> & {
 *   fetchedAt?: string,
 *   lastUsedAt?: string,
 * }} input
 * @returns {Promise<PubkeyCacheRecord|null>}
 */
export async function cachePut(input) {
  const fpr = cleanFpr(input?.fingerprint);
  const armored = String(input?.armored || "").trim();
  if (fpr.length < 40 || !armored.includes("BEGIN PGP")) return null;
  const origin = input.origin;
  if (origin !== "basilisk" && origin !== "upstream" && origin !== "import") {
    return null;
  }
  const now = new Date().toISOString();
  /** @type {PubkeyCacheRecord} */
  const rec = {
    fingerprint: fpr,
    armored,
    uids: Array.isArray(input.uids) ? input.uids.map(String) : [],
    email: String(input.email || "").trim(),
    name: String(input.name || "").trim(),
    origin,
    sourceKeyserver: input.sourceKeyserver
      ? String(input.sourceKeyserver).toLowerCase()
      : undefined,
    approvalState: input.approvalState ? String(input.approvalState) : undefined,
    revoked: !!input.revoked,
    keyId: input.keyId ? String(input.keyId).toUpperCase() : fpr.slice(-16),
    keyExpiration: input.keyExpiration ? String(input.keyExpiration) : undefined,
    userLabel: input.userLabel ? String(input.userLabel).trim() : undefined,
    fetchedAt: input.fetchedAt || now,
    lastUsedAt: input.lastUsedAt || now,
  };
  try {
    await withVaultStore(VAULT_PUBKEYS_STORE, "readwrite", (store) => store.put(rec));
    await enforceQuota();
    return rec;
  } catch (_) {
    return null;
  }
}

/**
 * @param {string} fingerprint
 * @returns {Promise<void>}
 */
export async function cacheDelete(fingerprint) {
  const fpr = cleanFpr(fingerprint);
  if (!fpr) return;
  try {
    await withVaultStore(VAULT_PUBKEYS_STORE, "readwrite", (store) => store.delete(fpr));
  } catch (_) {
    /* ignore */
  }
}

/**
 * @returns {Promise<void>}
 */
export async function cacheClear() {
  try {
    await withVaultStore(VAULT_PUBKEYS_STORE, "readwrite", (store) => store.clear());
  } catch (_) {
    /* ignore */
  }
}

/**
 * Drop oldest entries when over PUBKEY_CACHE_MAX.
 * @returns {Promise<void>}
 */
async function enforceQuota() {
  const all = await cacheList();
  if (all.length <= PUBKEY_CACHE_MAX) return;
  const ranked = [...all].sort((a, b) => {
    const ta = Date.parse(a.lastUsedAt || a.fetchedAt || "") || 0;
    const tb = Date.parse(b.lastUsedAt || b.fetchedAt || "") || 0;
    return ta - tb;
  });
  const drop = ranked.slice(0, all.length - PUBKEY_CACHE_MAX);
  for (const rec of drop) {
    await cacheDelete(rec.fingerprint);
  }
}

/**
 * Substring search over cached metas (email / name / uid / fpr / key id).
 * @param {string} query
 * @param {{ limit?: number }} [opts]
 * @returns {Promise<PubkeyCacheRecord[]>}
 */
export async function cacheSearch(query, opts = {}) {
  const q = String(query || "").trim().toLowerCase();
  if (q.length < 2) return [];
  const limit = Math.max(1, Number(opts.limit) || 50);
  const hex = q.replace(/[^0-9a-f]/g, "");
  const all = await cacheList();
  /** @type {PubkeyCacheRecord[]} */
  const hits = [];
  for (const rec of all) {
    const fpr = cleanFpr(rec.fingerprint).toLowerCase();
    const kid = String(rec.keyId || "").toLowerCase();
    const email = String(rec.email || "").toLowerCase();
    const name = String(rec.name || "").toLowerCase();
    const uids = (rec.uids || []).map((u) => String(u).toLowerCase()).join(" ");
    let ok = false;
    if (hex.length >= 8 && (fpr.includes(hex) || kid.includes(hex))) ok = true;
    else if (email.includes(q) || name.includes(q) || uids.includes(q)) ok = true;
    if (ok) hits.push(rec);
    if (hits.length >= limit) break;
  }
  return hits;
}

/**
 * Map a cache record to a portal-like search hit for the picker UI.
 * @param {PubkeyCacheRecord} rec
 * @returns {object}
 */
export function cacheRecordToSearchHit(rec) {
  const fpr = cleanFpr(rec.fingerprint);
  const uids = (rec.uids || []).map((raw) => {
    const s = String(raw);
    const m = s.match(/<([^>]+)>/);
    const email = m ? m[1] : s.includes("@") ? s : "";
    const name = m ? s.slice(0, m.index).trim() : "";
    return { raw: s, email, name };
  });
  return {
    fingerprint: fpr,
    key_id: rec.keyId || fpr.slice(-16),
    label: rec.userLabel || null,
    approval_state: rec.approvalState || (rec.origin === "basilisk" ? "approved" : ""),
    revoked: !!rec.revoked,
    key_expiration: rec.keyExpiration || null,
    approved_uids: uids,
    email: rec.email || "",
    origin: rec.origin,
    source_keyserver: rec.sourceKeyserver || "",
    cached: true,
  };
}
