/**
 * Basilisk browser key vault.
 *
 * Stores OpenPGP private keys in IndexedDB, envelope-encrypted with a
 * non-extractable device-bound AES-GCM key. Optional outer layers:
 *   - passphrase: OpenPGP S2K/Argon2 locks the armored key before wrapping
 *   - passkey (WebAuthn PRF): PRF→HKDF KEK wraps the device-encrypted blob
 *
 * localStorage is intentionally unused for secrets (string-only, XSS-readable).
 * Wipe ephemeral buffers with inlined fill(0) (see memory-safety.js — no
 * shared zeroBuffer chokepoint).
 */

import { readPrivateKey } from "openpgp";
import { parseAttestationObject } from "./webauthn/attestation.js";
import { normalizeVaultFingerprint } from "./vault-session.js";
import { lookupAaguidInMds } from "./webauthn/mds.js";
import { bytesToBase64Url } from "./toolkit/encode.js";

const DB_NAME = "basilisk-vault";
/** Schema v3 adds `pubkeys` (third-party public key cache; see pubkey-cache.js). */
const DB_VERSION = 3;
const STORE_KEYS = "keys";
const STORE_KEK = "kek";
const STORE_PUBKEYS = "pubkeys";
const DEVICE_KEK_ID = "device-aes-gcm";
/**
 * The pre-per-key PRF row: one credential id and one random salt for the whole
 * vault. Nothing writes it any more — see `putPrfEnrolment` — but it is still
 * read, because keys saved while it was the only shape have no row of their
 * own and it is the only description of how they were wrapped.
 */
const PRF_META_ID = "prf-meta";
/** `prf:<fingerprint>` — the enrolment that wraps exactly that key. */
const PRF_ROW_PREFIX = "prf:";
const PRF_INFO = new TextEncoder().encode("Basilisk Vault PRF KEK v1");

/** @typedef {"passphrase"|"passkey"|"device"} VaultProtection */
/** @typedef {"verified"|"unverified"|"unavailable"} MdsStatus */

/**
 * @typedef {object} VaultKeyMeta
 * @property {string} fingerprint
 * @property {string} uid
 * @property {string} email
 * @property {string} created  ISO timestamp
 * @property {string|null} expires  ISO timestamp or null
 * @property {VaultProtection} protection
 * @property {string} [name]
 * @property {string[]} [keyIds]  Primary + subkey key IDs (uppercase hex), for PKESK matching
 * @property {MdsStatus} [mdsStatus]  Soft FIDO MDS badge (passkey only); never blocks unlock
 * @property {string} [mdsDescription]
 * @property {string} [aaguid]
 * @property {string} [publicArmored]  Armored public key (no secrets)
 * @property {string|null} [lastUsedAt]  ISO timestamp of last successful unlock
 * @property {"pgp"|"ssh"|"raw"} [kind]  Absent means pgp (legacy records predate kinds, §28a)
 * @property {string} [publicLine]  ssh kind: the one-line OpenSSH public form (no secrets)
 * @property {string} [alg]  Non-pgp kinds: genkey-style algorithm tag (`ed25519`, `x25519`, …) so unlock can re-import
 */

/**
 * @typedef {VaultKeyMeta & {
 *   wrapped: ArrayBuffer,
 *   iv: ArrayBuffer,
 *   outerWrapped?: ArrayBuffer,
 *   outerIv?: ArrayBuffer,
 *   keyIds?: string[],
 * }} VaultKeyRecord
 */

/**
 * What the vault has to keep to ask an authenticator for the same PRF output
 * twice: which credential to address, and the salt it was evaluated over. The
 * salt is drawn fresh per enrolment and is not derivable from anything else,
 * so it is the half that cannot be reconstructed if it is lost.
 *
 * @typedef {object} PrfEnrolment
 * @property {ArrayBuffer} credentialId
 * @property {Uint8Array} firstSalt
 */

/**
 * @typedef {object} PasskeyPrfCreateResult
 * @property {Uint8Array} prfIkm
 * @property {import("./webauthn/mds.js").MdsLookupResult} mds
 * @property {PrfEnrolment} enrolment  Hand to `saveKey` as `prfEnrolment`
 */

/**
 * @returns {Promise<IDBDatabase>}
 */
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error || new Error("IndexedDB open failed"));
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_KEYS)) {
        db.createObjectStore(STORE_KEYS, { keyPath: "fingerprint" });
      }
      if (!db.objectStoreNames.contains(STORE_KEK)) {
        db.createObjectStore(STORE_KEK, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(STORE_PUBKEYS)) {
        db.createObjectStore(STORE_PUBKEYS, { keyPath: "fingerprint" });
      }
    };
    req.onsuccess = () => resolve(req.result);
  });
}

/**
 * Run a transaction against a vault IndexedDB object store.
 * Used by pubkey-cache.js for the `pubkeys` store (no secrets).
 *
 * @template T
 * @param {string} storeName
 * @param {IDBTransactionMode} mode
 * @param {(store: IDBObjectStore) => IDBRequest<T> | Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function withVaultStore(storeName, mode, fn) {
  return withStore(storeName, mode, fn);
}

export const VAULT_PUBKEYS_STORE = STORE_PUBKEYS;

/**
 * @template T
 * @param {string} storeName
 * @param {IDBTransactionMode} mode
 * @param {(store: IDBObjectStore) => IDBRequest<T> | Promise<T>} fn
 * @returns {Promise<T>}
 */
async function withStore(storeName, mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, mode);
      const store = tx.objectStore(storeName);
      let reqOrPromise;
      try {
        reqOrPromise = fn(store);
      } catch (err) {
        reject(err);
        return;
      }
      if (reqOrPromise && typeof reqOrPromise.then === "function") {
        /** @type {Promise<T>} */ (reqOrPromise).then(resolve, reject);
        tx.onerror = () => reject(tx.error);
        return;
      }
      const req = /** @type {IDBRequest<T>} */ (reqOrPromise);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

/**
 * Run one transaction spanning several object stores.
 *
 * `withStore` covers the single-store case, which is nearly all of them. This
 * exists for the one write that spans two: a key record and the PRF enrolment
 * that opens it are a single fact, and committing half of it produces either a
 * record nothing can unlock or an enrolment that outlives its key.
 *
 * @template T
 * @param {string[]} storeNames
 * @param {IDBTransactionMode} mode
 * @param {(tx: IDBTransaction) => Promise<T>} fn
 * @returns {Promise<T>}
 */
async function withStores(storeNames, mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(storeNames, mode);
      tx.onerror = () => reject(tx.error);
      let result;
      try {
        result = fn(tx);
      } catch (err) {
        reject(err);
        return;
      }
      Promise.resolve(result).then(resolve, reject);
    });
  } finally {
    db.close();
  }
}

/**
 * @returns {Promise<CryptoKey>}
 */
async function getOrCreateDeviceKek() {
  const existing = await withStore(STORE_KEK, "readonly", (s) => s.get(DEVICE_KEK_ID));
  if (existing?.key instanceof CryptoKey) {
    return existing.key;
  }
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  await withStore(STORE_KEK, "readwrite", (s) => s.put({ id: DEVICE_KEK_ID, key }));
  return key;
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} plaintext
 * @returns {Promise<{ iv: Uint8Array, ciphertext: ArrayBuffer }>}
 */
async function aesGcmEncrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );
  return { iv, ciphertext };
}

/**
 * @param {CryptoKey} key
 * @param {BufferSource} iv
 * @param {BufferSource} ciphertext
 * @returns {Promise<ArrayBuffer>}
 */
async function aesGcmDecrypt(key, iv, ciphertext) {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
}

/**
 * Derive a non-extractable AES-GCM KEK from WebAuthn PRF IKM via HKDF-SHA-256.
 * @param {ArrayBuffer|Uint8Array} ikm
 * @returns {Promise<CryptoKey>}
 */
export async function derivePrfKek(ikm) {
  const raw = ikm instanceof Uint8Array ? ikm : new Uint8Array(ikm);
  const baseKey = await crypto.subtle.importKey("raw", raw, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: PRF_INFO,
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Feature-detect WebAuthn PRF support (best-effort).
 * @returns {Promise<boolean>}
 */
export async function isPasskeyPrfAvailable() {
  try {
    if (typeof PublicKeyCredential === "undefined") return false;
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
      const uv = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (!uv) return false;
    }
    // PRF is an extension — assume available if WebAuthn platform auth exists;
    // actual create/get will fail clearly if unsupported.
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * @param {string} fingerprint
 * @returns {string}
 */
function prfRowId(fingerprint) {
  return `${PRF_ROW_PREFIX}${fingerprint}`;
}

/**
 * @param {*} row
 * @returns {PrfEnrolment|null}
 */
function rowToEnrolment(row) {
  if (!row?.credentialId || !row?.firstSalt) return null;
  return {
    credentialId: row.credentialId,
    firstSalt: new Uint8Array(row.firstSalt),
  };
}

/**
 * The enrolment that opens one key, or null.
 *
 * The row is keyed by the fingerprint it belongs to, so this answers about
 * *that* key rather than about whichever passkey was enrolled most recently —
 * which is the whole of the bug this shape replaced.
 *
 * @param {string} fingerprint
 * @returns {Promise<PrfEnrolment|null>}
 */
async function getPrfEnrolment(fingerprint) {
  const row = await withStore(STORE_KEK, "readonly", (s) => s.get(prfRowId(fingerprint)));
  return rowToEnrolment(row);
}

/**
 * The singleton enrolment written by versions before per-key rows.
 *
 * It is never rewritten and never deleted. A key saved back then carries no
 * row of its own, and this is the only record of how it was wrapped; copying
 * it onto those keys would assert an association nothing can check, and for a
 * key stranded by the overwrite that assertion would be false.
 *
 * @returns {Promise<PrfEnrolment|null>}
 */
async function getLegacyPrfEnrolment() {
  const row = await withStore(STORE_KEK, "readonly", (s) => s.get(PRF_META_ID));
  return rowToEnrolment(row);
}

/**
 * Every enrolment this vault holds — one per passkey-protected key, plus the
 * legacy singleton if this vault predates them.
 *
 * @returns {Promise<PrfEnrolment[]>}
 */
async function listPrfEnrolments() {
  const rows = await withStore(STORE_KEK, "readonly", (s) => s.getAll());
  /** @type {PrfEnrolment[]} */
  const out = [];
  const seen = new Set();
  for (const row of rows || []) {
    const id = String(row?.id || "");
    if (id !== PRF_META_ID && !id.startsWith(PRF_ROW_PREFIX)) continue;
    const enrolment = rowToEnrolment(row);
    if (!enrolment) continue;
    // One passkey may wrap several keys, each with its own salt. Addressing it
    // once is enough for a ceremony that only needs *a* credential to answer.
    const credential = bytesToBase64Url(new Uint8Array(enrolment.credentialId));
    if (seen.has(credential)) continue;
    seen.add(credential);
    out.push(enrolment);
  }
  return out;
}

/**
 * The enrolment row for a record, written inside the record's own transaction.
 *
 * Passing `null` deletes the row, which is the correct answer whenever the
 * record being written is not wrapped by a stored enrolment: a row describing a
 * wrapping that no longer exists is worse than no row, because unlock would
 * present a credential and get bytes that decrypt nothing.
 *
 * @param {IDBTransaction} tx
 * @param {string} fingerprint
 * @param {PrfEnrolment|null} enrolment
 * @returns {IDBRequest}
 */
function putPrfEnrolment(tx, fingerprint, enrolment) {
  const store = tx.objectStore(STORE_KEK);
  if (!enrolment) return store.delete(prfRowId(fingerprint));
  const salt = enrolment.firstSalt;
  return store.put({
    id: prfRowId(fingerprint),
    fingerprint,
    credentialId: enrolment.credentialId,
    firstSalt: salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength),
  });
}

/**
 * Named by `getPasskeyPrf` when a passkey-protected key has no enrolment to
 * present — neither its own row nor the legacy one. It names the key because
 * the vault may hold other passkey keys that unlock perfectly well, and "your
 * passkey is not registered" would read as a claim about all of them.
 *
 * @param {string} fingerprint
 * @returns {string}
 */
export function prfEnrolmentMissingMessage(fingerprint) {
  return `This key is passkey-protected, but this vault holds no passkey enrolment for ${fingerprint} — neither the credential to ask nor the salt to ask it about. Neither can be re-derived, so restore this key from an exported or paper backup.`;
}

/**
 * Named when a record that does not say which enrolment wrapped it fails to
 * unwrap. That is nearly always a key saved before per-key rows existed, but
 * it is also any key wrapped under PRF IKM the vault never enrolled, so the
 * first sentence states the observation and the overwrite appears as the
 * explanation it probably is rather than as a finding.
 *
 * This is the data-loss message, and it says so. A vault that kept one PRF row
 * replaced that row on the next enrolment, taking the 32 random bytes of salt
 * with it, and a PRF cannot be re-evaluated over a salt nobody kept. There is
 * no remedy inside the product to offer, so it offers the only one there is.
 *
 * @returns {string}
 */
export function prfLegacyEnrolmentLostMessage() {
  return "This key's record does not say which passkey wrapped it, and the one passkey enrolment this vault still holds did not open it. Versions before per-key enrolments kept a single enrolment for the whole vault, so enrolling a second passkey overwrote the first — including the 32-byte random salt the earlier key's wrapping was derived from. If that is what happened here, this key cannot be unlocked again on this or any other device: the salt is gone, and no authenticator can reproduce a PRF output without it. Restore this key from an exported or paper backup.";
}

/**
 * Named when the enrolment recorded for a key answers and its PRF output still
 * does not open the record. The two are written in one transaction, so this
 * states the disjunction rather than picking a cause it cannot observe.
 *
 * @param {string} fingerprint
 * @returns {string}
 */
export function prfEnrolmentMismatchMessage(fingerprint) {
  return `The passkey enrolled for ${fingerprint} answered, but its PRF output did not decrypt this key — either the stored wrapping or the enrolment has changed since the key was saved. Restore this key from an exported or paper backup.`;
}

/**
 * Create a passkey with PRF (platform or roaming / YubiKey).
 * Requests direct attestation for soft MDS lookup; never blocks on MDS failure.
 *
 * This performs the ceremony and persists nothing. The enrolment it returns is
 * only meaningful beside the key it wraps, and the ceremony does not know which
 * key that is — `saveKey` does, and writes the two together. That is also why
 * enrolling a second passkey is no longer destructive: there is no vault-wide
 * row left for it to land on, so nothing needs a confirmation gate in front of
 * it. A cancelled or failed save now leaves no orphan enrolment either.
 *
 * @param {string} userEmail
 * @returns {Promise<PasskeyPrfCreateResult>}
 */
export async function createPasskeyPrf(userEmail) {
  const firstSalt = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const cred = /** @type {PublicKeyCredential} */ (
    await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "Basilisk", id: location.hostname },
        user: {
          id: userId,
          name: userEmail || "basilisk-vault",
          displayName: "Basilisk vault",
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          // Allow platform passkeys and roaming security keys (YubiKey).
          userVerification: "required",
          residentKey: "preferred",
        },
        // Capture attestation for MDS label/badge; enroll is not gated on verify.
        attestation: "direct",
        timeout: 120_000,
        extensions: {
          prf: { eval: { first: firstSalt } },
        },
      },
    })
  );
  if (!cred) throw new Error("Passkey creation cancelled or failed");
  const ext = cred.getClientExtensionResults?.() || {};
  const prfResults = ext.prf?.results?.first;
  if (!prfResults) {
    throw new Error(
      "This authenticator does not support the WebAuthn PRF extension. Choose passphrase or device-only protection."
    );
  }

  /** @type {import("./webauthn/mds.js").MdsLookupResult} */
  let mds = {
    status: "unverified",
    aaguid: "",
    detail: "No attestation object on credential",
  };
  try {
    const attResp = /** @type {AuthenticatorAttestationResponse} */ (cred.response);
    const parsed = attResp?.attestationObject
      ? parseAttestationObject(attResp.attestationObject)
      : null;
    mds = await lookupAaguidInMds(parsed?.aaguid);
  } catch (err) {
    mds = {
      status: "unavailable",
      aaguid: "",
      detail: err?.message || "MDS lookup failed",
    };
  }

  return {
    prfIkm: new Uint8Array(prfResults),
    mds,
    enrolment: { credentialId: cred.rawId, firstSalt },
  };
}

/**
 * Get PRF output from an existing passkey (unlock gesture).
 *
 * With a fingerprint this addresses that key's own enrolment: one credential,
 * one salt, both read from the row written when the key was saved. Unlock is
 * never asking "which passkey is current" — it is asking the passkey this key
 * was wrapped under.
 *
 * Without one (the `webauthn.prf` toolkit step, which has no key in hand) it
 * offers every enrolment this vault holds and lets the authenticator answer for
 * whichever credential is present. A single candidate keeps the plain `eval`
 * form that every PRF implementation supports; `evalByCredential` appears only
 * where there is genuinely more than one salt to choose between, so nothing
 * that works today starts depending on it.
 *
 * @param {string} [fingerprint]  The key being unlocked, when there is one
 * @returns {Promise<Uint8Array>}
 */
export async function getPasskeyPrf(fingerprint) {
  const fpr = fingerprint ? normalizeVaultFingerprint(fingerprint) : "";
  /** @type {PrfEnrolment[]} */
  let candidates;
  if (fpr) {
    const own = (await getPrfEnrolment(fpr)) || (await getLegacyPrfEnrolment());
    if (!own) throw new Error(prfEnrolmentMissingMessage(fpr));
    candidates = [own];
  } else {
    candidates = await listPrfEnrolments();
    if (!candidates.length) {
      throw new Error(
        "No passkey registered for this vault. Generate a key with passkey protection first."
      );
    }
  }

  const prf =
    candidates.length === 1
      ? { eval: { first: candidates[0].firstSalt } }
      : {
          evalByCredential: Object.fromEntries(
            candidates.map((e) => [
              bytesToBase64Url(new Uint8Array(e.credentialId)),
              { first: e.firstSalt },
            ])
          ),
        };

  const cred = /** @type {PublicKeyCredential} */ (
    await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: candidates.map((e) => ({
          type: /** @type {const} */ ("public-key"),
          id: e.credentialId,
        })),
        userVerification: "required",
        timeout: 120_000,
        extensions: { prf },
      },
    })
  );
  if (!cred) throw new Error("Passkey assertion cancelled or failed");
  const ext = cred.getClientExtensionResults?.() || {};
  const prfResults = ext.prf?.results?.first;
  if (!prfResults) {
    throw new Error("PRF extension returned no results");
  }
  return new Uint8Array(prfResults);
}

/**
 * Collect uppercase hex key IDs (primary + all subkeys) from an armored private key.
 * Works without unlocking — key IDs live in the public half of the packets.
 * @param {string} armoredPrivate
 * @returns {Promise<string[]>}
 */
export async function collectKeyIds(armoredPrivate) {
  const key = await readPrivateKey({ armoredKey: armoredPrivate });
  /** @type {string[]} */
  const ids = [];
  const pushId = (kid) => {
    try {
      const hex = String(kid?.toHex?.() || "")
        .toUpperCase()
        .replace(/[^0-9A-F]/g, "");
      if (hex && !ids.includes(hex)) ids.push(hex);
    } catch (_) {
      /* ignore */
    }
  };
  pushId(key.getKeyID?.());
  try {
    for (const sub of key.getSubkeys?.() || []) {
      pushId(sub.getKeyID?.());
    }
  } catch (_) {
    /* ignore */
  }
  // Also accept getKeys() if present (primary + subs).
  try {
    for (const k of key.getKeys?.() || []) {
      pushId(k.getKeyID?.());
    }
  } catch (_) {
    /* ignore */
  }
  return ids;
}

/**
 * Whether a vault key matches any of the message's recipient key IDs.
 * Matches full key ID, fingerprint, or fingerprint suffix (v4 key ID).
 * @param {VaultKeyMeta} meta
 * @param {string[]} recipientKeyIDs
 * @returns {boolean}
 */
export function vaultKeyMatchesRecipients(meta, recipientKeyIDs) {
  const recipients = (recipientKeyIDs || [])
    .map((id) =>
      String(id || "")
        .toUpperCase()
        .replace(/[^0-9A-F]/g, "")
    )
    .filter((id) => id && !/^0+$/.test(id));
  if (!recipients.length) return false;

  const fpr = String(meta.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  /** @type {string[]} */
  const candidates = [...(meta.keyIds || [])];
  if (fpr) {
    candidates.push(fpr);
    if (fpr.length >= 16) candidates.push(fpr.slice(-16));
  }
  const norms = candidates
    .map((id) =>
      String(id || "")
        .toUpperCase()
        .replace(/[^0-9A-F]/g, "")
    )
    .filter(Boolean);

  return recipients.some((r) =>
    norms.some((c) => c === r || c.endsWith(r) || r.endsWith(c))
  );
}

/**
 * List vault key metadata (no private material).
 * @returns {Promise<VaultKeyMeta[]>}
 */
export async function listKeys() {
  await purgeExpired();
  const rows = await withStore(STORE_KEYS, "readonly", (s) => s.getAll());
  return (rows || []).map((r) => {
    const fpr = r.fingerprint || "";
    /** @type {string[]} */
    let keyIds = Array.isArray(r.keyIds) ? [...r.keyIds] : [];
    // Legacy records: fall back to primary key ID = last 16 of fingerprint.
    if (!keyIds.length && fpr.length >= 16) {
      keyIds = [fpr.slice(-16).toUpperCase()];
    }
    return {
      fingerprint: fpr,
      uid: r.uid || "",
      email: r.email || "",
      name: r.name || "",
      created: r.created,
      expires: r.expires ?? null,
      protection: r.protection,
      keyIds,
      mdsStatus: r.mdsStatus,
      mdsDescription: r.mdsDescription || "",
      aaguid: r.aaguid || "",
      publicArmored: r.publicArmored || "",
      lastUsedAt: r.lastUsedAt || null,
      // Multi-kind metadata (§28a); absent on legacy records means pgp.
      ...(r.kind ? { kind: r.kind } : {}),
      ...(r.publicLine ? { publicLine: r.publicLine } : {}),
      ...(r.alg ? { alg: r.alg } : {}),
    };
  });
}

/**
 * Sort vault metas by lastUsedAt (newest first), then created.
 * @param {VaultKeyMeta[]} keys
 * @returns {VaultKeyMeta[]}
 */
export function sortKeysByLastUsed(keys) {
  return [...(keys || [])].sort((a, b) => {
    const ta = Date.parse(a.lastUsedAt || "") || 0;
    const tb = Date.parse(b.lastUsedAt || "") || 0;
    if (tb !== ta) return tb - ta;
    const ca = Date.parse(a.created || "") || 0;
    const cb = Date.parse(b.created || "") || 0;
    return cb - ca;
  });
}

/**
 * Record a successful unlock timestamp.
 * @param {string} fingerprint
 */
export async function touchKeyUsed(fingerprint) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  if (!fpr) return;
  const record = await withStore(STORE_KEYS, "readonly", (s) => s.get(fpr));
  if (!record) return;
  await withStore(STORE_KEYS, "readwrite", (s) =>
    s.put({ ...record, lastUsedAt: new Date().toISOString() })
  );
}

/**
 * Persist publicArmored (and optional keyIds) without changing wrapped private blob.
 * @param {string} fingerprint
 * @param {{ publicArmored?: string, keyIds?: string[] }} patch
 */
export async function patchKeyMeta(fingerprint, patch) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  const record = await withStore(STORE_KEYS, "readonly", (s) => s.get(fpr));
  if (!record) return;
  /** @type {VaultKeyRecord} */
  const next = { ...record };
  if (patch.publicArmored != null) next.publicArmored = patch.publicArmored;
  if (Array.isArray(patch.keyIds) && patch.keyIds.length) next.keyIds = [...patch.keyIds];
  await withStore(STORE_KEYS, "readwrite", (s) => s.put(next));
}

/**
 * Protection strength, weakest first. The vault's whole claim is that a key
 * saved behind an authenticator stays behind one, so the ordering is the
 * thing we enforce on re-save (§34d).
 * @type {Record<string, number>}
 */
const PROTECTION_RANK = { device: 0, passphrase: 1, passkey: 2 };

/**
 * @param {string} protection
 * @returns {number}
 */
function protectionRank(protection) {
  const rank = PROTECTION_RANK[String(protection || "").toLowerCase()];
  return typeof rank === "number" ? rank : 0;
}

/**
 * What a stored record's protection actually *is*, which is not always what
 * its label says: the security property is the outer PRF wrap, so a record
 * carrying one requires the authenticator whatever the label reads. Trusting
 * the label alone would let a corrupted or hand-edited record argue that
 * dropping the wrap is harmless.
 *
 * @param {VaultKeyRecord} record
 * @returns {string}
 */
function effectiveProtection(record) {
  if (record?.outerWrapped?.byteLength) return "passkey";
  return String(record?.protection || "device").toLowerCase();
}

/**
 * §34d, verbatim — asserted by tests; the wording is the feature. It names
 * both protections because "already saved" alone does not tell you what you
 * were about to lose, and it names a remedy because a refusal with no way
 * forward just gets clicked again.
 *
 * @param {string} existing
 * @param {string} next
 * @returns {string}
 */
export function protectionDowngradeMessage(existing, next) {
  return `This key is already in the vault with ${existing} protection, and saving it with ${next} protection would weaken it — delete it from My Keys first, or save it again with ${existing} protection.`;
}

/**
 * Write a record and its PRF enrolment, refusing a protection downgrade unless
 * the caller has explicitly asked to replace.
 *
 * The read and the write share one readwrite transaction rather than the
 * obvious check-then-call in the caller: two tabs are one vault, and the
 * window between a UI's "is it already there?" query and its save is exactly
 * the window in which the other tab enrols the passkey this guard exists to
 * protect. IndexedDB gives us the atomicity for free as long as the `put` is
 * issued from the `get`'s success callback, so it is issued from there.
 *
 * The enrolment row rides in the same transaction, and is written from the
 * record's own success callback for the same reason. The row must describe the
 * wrapping the record actually carries or not exist at all — a refused write
 * that had already replaced the row would leave the *previous* wrapping
 * undescribed, which is the failure mode this whole change is about.
 *
 * @param {VaultKeyRecord} record
 * @param {"refuse"|"replace"} onConflict
 * @param {PrfEnrolment|null} enrolment
 * @returns {Promise<void>}
 */
function putGuardingProtection(record, onConflict, enrolment) {
  return withStores(
    [STORE_KEYS, STORE_KEK],
    "readwrite",
    (tx) =>
      new Promise((resolve, reject) => {
        const store = tx.objectStore(STORE_KEYS);
        const read = store.get(record.fingerprint);
        read.onerror = () => reject(read.error);
        read.onsuccess = () => {
          const prior = read.result;
          if (prior && onConflict !== "replace") {
            const from = effectiveProtection(prior);
            const to = String(record.protection || "").toLowerCase();
            if (protectionRank(to) < protectionRank(from)) {
              reject(new Error(protectionDowngradeMessage(from, to)));
              return;
            }
          }
          const write = store.put(record);
          write.onerror = () => reject(write.error);
          write.onsuccess = () => {
            const row = putPrfEnrolment(tx, record.fingerprint, enrolment);
            row.onerror = () => reject(row.error);
            row.onsuccess = () => resolve(undefined);
          };
        };
      })
  );
}

/**
 * Save a private key into the vault.
 *
 * The store's keyPath is the fingerprint, so this is an upsert. Re-saving at
 * the same or a stronger protection is routine — it is how publicArmored and
 * key-id backfill land — but re-saving at a weaker one silently threw away a
 * passkey binding until `onConflict` existed. The default is therefore the
 * refusal: a caller that means to weaken a key has to say so.
 *
 * @param {object} opts
 * @param {string} opts.fingerprint
 * @param {string} opts.armoredPrivate  May already be passphrase-locked
 * @param {string} opts.uid
 * @param {string} opts.email
 * @param {string} [opts.name]
 * @param {string|null} [opts.expires]  ISO
 * @param {VaultProtection} opts.protection
 * @param {Uint8Array} [opts.prfIkm]  Required when protection === "passkey"
 * @param {PrfEnrolment} [opts.prfEnrolment]  From `createPasskeyPrf`; what lets a later unlock ask the authenticator again
 * @param {import("./webauthn/mds.js").MdsLookupResult} [opts.mds]  Soft MDS result from PRF create
 * @param {string[]} [opts.keyIds]  Optional; extracted from armoredPrivate when omitted
 * @param {string} [opts.publicArmored]  Optional armored public; derived from private when omitted
 * @param {"pgp"|"ssh"|"raw"} [opts.kind]  Defaults pgp; non-pgp payloads are opaque text (§28a)
 * @param {string} [opts.publicLine]  ssh kind: OpenSSH public line
 * @param {string} [opts.alg]  Non-pgp kinds: algorithm tag for re-import on unlock
 * @param {"refuse"|"replace"} [opts.onConflict]  Default "refuse": reject a weakening re-save
 * @returns {Promise<VaultKeyMeta>}
 */
export async function saveKey(opts) {
  const kind = opts.kind || "pgp";
  const onConflict = opts.onConflict || "refuse";
  if (onConflict !== "refuse" && onConflict !== "replace") {
    // A typo would otherwise fall through to the safe branch and look like it
    // worked, which is how a caller ends up believing it asked for replace.
    throw new Error(`saveKey onConflict must be "refuse" or "replace"`);
  }
  // The id is kind-shaped (§28a): hex OpenPGP fingerprint, or `SHA256:` /
  // `spki:SHA256:` base64 where hex normalization would destroy it.
  const fpr =
    kind === "pgp"
      ? String(opts.fingerprint || "")
          .toUpperCase()
          .replace(/[^0-9A-F]/g, "")
      : String(opts.fingerprint || "").trim();
  if (kind === "pgp" && fpr.length < 40) throw new Error("Invalid fingerprint");
  if (kind !== "pgp" && !/^(spki:)?SHA256:[A-Za-z0-9+/]{43}$/.test(fpr)) {
    throw new Error(`Invalid ${kind} key id — expected SHA256:… fingerprint, got "${fpr}"`);
  }

  // Read before write, for `created` / `lastUsedAt` only — the downgrade
  // refusal is *not* made here.
  //
  // Two fixes for this bug landed independently, one on each side of a merge:
  // a pre-check in this position, and the transactional guard in `putRecord`.
  // Keeping both would have been worse than either. This read and a later
  // `put` are separate transactions, so the window between them is exactly
  // when the other tab enrols the passkey the guard exists to protect — the
  // race `putRecord` was written to close by issuing its write from its own
  // read's success callback. A pre-check here would refuse the common case
  // slightly earlier and leave the racing case to the real guard, which reads
  // as defence in depth and is really one correct check beside one that
  // cannot see the state it is judging.
  //
  // It also judged `prior.protection`, the label, where `effectiveProtection`
  // asks whether an outer PRF wrap is actually present — a record whose label
  // was edited would have passed here and been caught there.
  const prior = await withStore(STORE_KEYS, "readonly", (s) => s.get(fpr));

  /** @type {string[]} */
  let keyIds = Array.isArray(opts.keyIds) ? [...opts.keyIds] : [];
  if (kind === "pgp" && !keyIds.length && opts.armoredPrivate) {
    try {
      keyIds = await collectKeyIds(opts.armoredPrivate);
    } catch (_) {
      keyIds = fpr.length >= 16 ? [fpr.slice(-16)] : [];
    }
  }

  let publicArmored = String(opts.publicArmored || "").trim();
  if (kind === "pgp" && !publicArmored && opts.armoredPrivate) {
    try {
      publicArmored = await derivePublicArmored(opts.armoredPrivate);
    } catch (_) {
      publicArmored = "";
    }
  }

  const encoder = new TextEncoder();
  const payload = encoder.encode(opts.armoredPrivate);
  const deviceKek = await getOrCreateDeviceKek();
  const { iv, ciphertext } = await aesGcmEncrypt(deviceKek, payload);
  try {
    payload.fill(0);
  } catch (_) {
    /* wipe */
  }

  /** @type {VaultKeyRecord} */
  const record = {
    fingerprint: fpr,
    uid: opts.uid || "",
    email: opts.email || "",
    name: opts.name || "",
    created: prior?.created || new Date().toISOString(),
    expires: opts.expires || null,
    protection: opts.protection,
    keyIds,
    publicArmored,
    lastUsedAt: prior?.lastUsedAt || null,
    wrapped: ciphertext,
    iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
  };

  // The wrap layer above never cared what it wrapped (§28a) — kind is
  // metadata for listing, id shaping and unlock re-import, not for crypto.
  if (kind !== "pgp") {
    record.kind = kind;
    if (opts.publicLine) record.publicLine = String(opts.publicLine);
    if (opts.alg) record.alg = String(opts.alg);
  }

  if (opts.mds?.status) {
    record.mdsStatus = opts.mds.status;
    record.mdsDescription = opts.mds.description || "";
    record.aaguid = opts.mds.aaguid || "";
  }

  if (opts.protection === "passkey") {
    if (!opts.prfIkm) throw new Error("PRF IKM required for passkey protection");
    const prfKek = await derivePrfKek(opts.prfIkm);
    const outerPlain = new Uint8Array(ciphertext);
    const outer = await aesGcmEncrypt(prfKek, outerPlain);
    try {
      outerPlain.fill(0);
    } catch (_) {
      /* wipe */
    }
    record.outerWrapped = outer.ciphertext;
    record.outerIv = outer.iv.buffer.slice(
      outer.iv.byteOffset,
      outer.iv.byteOffset + outer.iv.byteLength
    );
    // Clear the device-only ciphertext from the record so unlock requires PRF.
    // Keep a zeroed placeholder length for schema clarity — we use outer* fields.
    record.wrapped = new ArrayBuffer(0);
  }

  // Only a passkey save that came with an enrolment leaves a row behind. A
  // caller holding PRF IKM from somewhere the vault never enrolled — the
  // toolkit pipeline, a test — still gets its key wrapped, but the vault does
  // not claim to know how to ask for those bytes again, because it does not.
  // Every other protection deletes the row: the record no longer carries a PRF
  // wrap, so an enrolment for it would describe nothing.
  const enrolment =
    opts.protection === "passkey" && opts.prfEnrolment ? opts.prfEnrolment : null;
  await putGuardingProtection(record, onConflict, enrolment);
  return {
    fingerprint: fpr,
    uid: record.uid,
    email: record.email,
    name: record.name,
    created: record.created,
    expires: record.expires,
    protection: record.protection,
    keyIds: record.keyIds || [],
    mdsStatus: record.mdsStatus,
    mdsDescription: record.mdsDescription,
    aaguid: record.aaguid,
    publicArmored: record.publicArmored || "",
    lastUsedAt: record.lastUsedAt || null,
  };
}

/**
 * Unlock and return the armored private key.
 *
 * @param {string} fingerprint
 * @param {{ passphrase?: string, prfIkm?: Uint8Array }} [opts]
 * @returns {Promise<string>} armored private key (may still be OpenPGP passphrase-locked)
 */
export async function unlockKey(fingerprint, opts = {}) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  const record = await withStore(STORE_KEYS, "readonly", (s) => s.get(fpr));
  if (!record) throw new Error("Key not found in vault");

  let deviceCipher;
  if (record.protection === "passkey") {
    if (!opts.prfIkm) throw new Error("Passkey unlock required");
    const prfKek = await derivePrfKek(opts.prfIkm);
    try {
      deviceCipher = await aesGcmDecrypt(prfKek, record.outerIv, record.outerWrapped);
    } catch (err) {
      // Re-raised, not retried and not swallowed: AES-GCM has already refused
      // and there is no second thing to try. What is added is which state the
      // reader is in, since a bare OperationError reads as "something went
      // wrong" for a key that may be permanently gone. The read happens only
      // here, on the failure path, because the answer is only needed here.
      const own = await getPrfEnrolment(fpr);
      throw new Error(
        own ? prfEnrolmentMismatchMessage(fpr) : prfLegacyEnrolmentLostMessage(),
        { cause: err }
      );
    }
  } else {
    deviceCipher = record.wrapped;
  }

  const deviceKek = await getOrCreateDeviceKek();
  const plainBuf = await aesGcmDecrypt(deviceKek, record.iv, deviceCipher);
  const armored = new TextDecoder().decode(plainBuf);
  try {
    (plainBuf instanceof Uint8Array ? plainBuf : new Uint8Array(plainBuf)).fill(0);
  } catch (_) {
    /* wipe */
  }
  if (deviceCipher instanceof ArrayBuffer && record.protection === "passkey") {
    try {
      new Uint8Array(deviceCipher).fill(0);
    } catch (_) {
      /* wipe */
    }
  }

  // Backfill key IDs / publicArmored for legacy vault entries.
  /** @type {Partial<VaultKeyRecord>} */
  const patch = {};
  if (!Array.isArray(record.keyIds) || !record.keyIds.length) {
    try {
      const keyIds = await collectKeyIds(armored);
      if (keyIds.length) patch.keyIds = keyIds;
    } catch (_) {
      /* ignore */
    }
  }
  if (!record.publicArmored) {
    try {
      const pub = await derivePublicArmored(armored);
      if (pub) patch.publicArmored = pub;
    } catch (_) {
      /* ignore */
    }
  }
  if (Object.keys(patch).length) {
    try {
      await withStore(STORE_KEYS, "readwrite", (s) =>
        s.put({ ...record, ...patch })
      );
    } catch (_) {
      /* ignore — unlock still succeeds */
    }
  }

  return armored;
}

/**
 * @param {string} armoredPrivate
 * @returns {Promise<string>}
 */
async function derivePublicArmored(armoredPrivate) {
  const key = await readPrivateKey({ armoredKey: armoredPrivate });
  const pub = key.toPublic();
  return pub.armor();
}

/**
 * Delete a vault entry, overwriting wrapped blobs with zeros first.
 *
 * The key's PRF enrolment goes with it. Keyed by fingerprint, the row has an
 * obvious lifetime — exactly the record's — where a vault-wide row had no
 * correct moment to be deleted at all. The salt is not wiped on the way out:
 * it is a public PRF input, and pretending otherwise would put a scrubbing
 * comment next to something that never needed scrubbing.
 *
 * @param {string} fingerprint
 */
export async function deleteKey(fingerprint) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  const record = await withStore(STORE_KEYS, "readonly", (s) => s.get(fpr));
  if (record) {
    for (const buf of [
      record.wrapped,
      record.iv,
      record.outerWrapped,
      record.outerIv,
    ]) {
      try {
        if (buf) new Uint8Array(buf).fill(0);
      } catch (_) {
        /* wipe */
      }
    }
    // Write zeros back then delete
    await withStore(STORE_KEYS, "readwrite", (s) =>
      s.put({
        ...record,
        wrapped: new ArrayBuffer(0),
        iv: new ArrayBuffer(0),
        outerWrapped: new ArrayBuffer(0),
        outerIv: new ArrayBuffer(0),
      })
    );
  }
  await withStore(STORE_KEYS, "readwrite", (s) => s.delete(fpr));
  await withStore(STORE_KEK, "readwrite", (s) => s.delete(prfRowId(fpr)));
}

/**
 * Remove vault entries whose OpenPGP expiration has passed.
 * @returns {Promise<number>} count removed
 */
export async function purgeExpired() {
  const now = Date.now();
  const rows = await withStore(STORE_KEYS, "readonly", (s) => s.getAll());
  let n = 0;
  for (const r of rows || []) {
    if (!r.expires) continue;
    const t = Date.parse(r.expires);
    if (!Number.isNaN(t) && t < now) {
      await deleteKey(r.fingerprint);
      n += 1;
    }
  }
  return n;
}

/**
 * Expiration presets → seconds from now (OpenPGP.js keyExpirationTime).
 * @type {Record<string, number|null>}
 */
export const EXPIRY_PRESETS = {
  "1d": 86400,
  "1w": 7 * 86400,
  "1m": 30 * 86400,
  "1y": 365 * 86400,
  none: null,
};

/**
 * @param {string} preset
 * @returns {string|null} ISO expiry or null
 */
export function expiryIsoFromPreset(preset) {
  const sec = EXPIRY_PRESETS[preset];
  if (sec == null) return null;
  return new Date(Date.now() + sec * 1000).toISOString();
}
