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
import { lookupAaguidInMds } from "./webauthn/mds.js";

const DB_NAME = "basilisk-vault";
/** Schema v3 adds `pubkeys` (third-party public key cache; see pubkey-cache.js). */
const DB_VERSION = 3;
const STORE_KEYS = "keys";
const STORE_KEK = "kek";
const STORE_PUBKEYS = "pubkeys";
const DEVICE_KEK_ID = "device-aes-gcm";
const PRF_META_ID = "prf-meta";
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
 * @typedef {object} PasskeyPrfCreateResult
 * @property {Uint8Array} prfIkm
 * @property {import("./webauthn/mds.js").MdsLookupResult} mds
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
 * @returns {Promise<{ credentialId: ArrayBuffer, firstSalt: Uint8Array, mds?: object } | null>}
 */
async function getPrfMeta() {
  const row = await withStore(STORE_KEK, "readonly", (s) => s.get(PRF_META_ID));
  if (!row?.credentialId || !row?.firstSalt) return null;
  return {
    credentialId: row.credentialId,
    firstSalt: new Uint8Array(row.firstSalt),
    mds: row.mds || null,
  };
}

/**
 * @param {ArrayBuffer} credentialId
 * @param {Uint8Array} firstSalt
 * @param {import("./webauthn/mds.js").MdsLookupResult} [mds]
 */
async function savePrfMeta(credentialId, firstSalt, mds) {
  await withStore(STORE_KEK, "readwrite", (s) =>
    s.put({
      id: PRF_META_ID,
      credentialId,
      firstSalt: firstSalt.buffer.slice(
        firstSalt.byteOffset,
        firstSalt.byteOffset + firstSalt.byteLength
      ),
      mds: mds
        ? {
            status: mds.status,
            aaguid: mds.aaguid,
            description: mds.description || "",
            detail: mds.detail || "",
          }
        : undefined,
    })
  );
}

/**
 * Create a passkey with PRF (platform or roaming / YubiKey).
 * Requests direct attestation for soft MDS lookup; never blocks on MDS failure.
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

  await savePrfMeta(cred.rawId, firstSalt, mds);
  return { prfIkm: new Uint8Array(prfResults), mds };
}

/**
 * Get PRF output from an existing passkey (unlock gesture).
 * @returns {Promise<Uint8Array>}
 */
export async function getPasskeyPrf() {
  const meta = await getPrfMeta();
  if (!meta) {
    throw new Error("No passkey registered for this vault. Generate a key with passkey protection first.");
  }
  const cred = /** @type {PublicKeyCredential} */ (
    await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [
          { type: "public-key", id: meta.credentialId },
        ],
        userVerification: "required",
        timeout: 120_000,
        extensions: {
          prf: { eval: { first: meta.firstSalt } },
        },
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
  const fpr = String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
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
  const fpr = String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  const record = await withStore(STORE_KEYS, "readonly", (s) => s.get(fpr));
  if (!record) return;
  /** @type {VaultKeyRecord} */
  const next = { ...record };
  if (patch.publicArmored != null) next.publicArmored = patch.publicArmored;
  if (Array.isArray(patch.keyIds) && patch.keyIds.length) next.keyIds = [...patch.keyIds];
  await withStore(STORE_KEYS, "readwrite", (s) => s.put(next));
}

/**
 * Save a private key into the vault.
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
 * @param {import("./webauthn/mds.js").MdsLookupResult} [opts.mds]  Soft MDS result from PRF create
 * @param {string[]} [opts.keyIds]  Optional; extracted from armoredPrivate when omitted
 * @param {string} [opts.publicArmored]  Optional armored public; derived from private when omitted
 * @returns {Promise<VaultKeyMeta>}
 */
export async function saveKey(opts) {
  const fpr = String(opts.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (fpr.length < 40) throw new Error("Invalid fingerprint");

  /** @type {string[]} */
  let keyIds = Array.isArray(opts.keyIds) ? [...opts.keyIds] : [];
  if (!keyIds.length && opts.armoredPrivate) {
    try {
      keyIds = await collectKeyIds(opts.armoredPrivate);
    } catch (_) {
      keyIds = fpr.length >= 16 ? [fpr.slice(-16)] : [];
    }
  }

  let publicArmored = String(opts.publicArmored || "").trim();
  if (!publicArmored && opts.armoredPrivate) {
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
    created: new Date().toISOString(),
    expires: opts.expires || null,
    protection: opts.protection,
    keyIds,
    publicArmored,
    lastUsedAt: null,
    wrapped: ciphertext,
    iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
  };

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

  await withStore(STORE_KEYS, "readwrite", (s) => s.put(record));
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
  const fpr = String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  const record = await withStore(STORE_KEYS, "readonly", (s) => s.get(fpr));
  if (!record) throw new Error("Key not found in vault");

  let deviceCipher;
  if (record.protection === "passkey") {
    if (!opts.prfIkm) throw new Error("Passkey unlock required");
    const prfKek = await derivePrfKek(opts.prfIkm);
    deviceCipher = await aesGcmDecrypt(prfKek, record.outerIv, record.outerWrapped);
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
 * @param {string} fingerprint
 */
export async function deleteKey(fingerprint) {
  const fpr = String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
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
