/**
 * Basilisk browser key vault.
 *
 * Stores OpenPGP private keys in IndexedDB, envelope-encrypted with a
 * non-extractable device-bound AES-GCM key. Optional outer layers:
 *   - passphrase: OpenPGP S2K/Argon2 locks the armored key before wrapping
 *   - passkey (WebAuthn PRF): PRF→HKDF KEK wraps the device-encrypted blob
 *
 * localStorage is intentionally unused for secrets (string-only, XSS-readable).
 */

const DB_NAME = "basilisk-vault";
const DB_VERSION = 1;
const STORE_KEYS = "keys";
const STORE_KEK = "kek";
const DEVICE_KEK_ID = "device-aes-gcm";
const PRF_META_ID = "prf-meta";
const PRF_INFO = new TextEncoder().encode("Basilisk Vault PRF KEK v1");

/** @typedef {"passphrase"|"passkey"|"device"} VaultProtection */

/**
 * @typedef {object} VaultKeyMeta
 * @property {string} fingerprint
 * @property {string} uid
 * @property {string} email
 * @property {string} created  ISO timestamp
 * @property {string|null} expires  ISO timestamp or null
 * @property {VaultProtection} protection
 * @property {string} [name]
 */

/**
 * @typedef {VaultKeyMeta & {
 *   wrapped: ArrayBuffer,
 *   iv: ArrayBuffer,
 *   outerWrapped?: ArrayBuffer,
 *   outerIv?: ArrayBuffer,
 * }} VaultKeyRecord
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
    };
    req.onsuccess = () => resolve(req.result);
  });
}

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
 * @returns {Promise<{ credentialId: ArrayBuffer, firstSalt: Uint8Array } | null>}
 */
async function getPrfMeta() {
  const row = await withStore(STORE_KEK, "readonly", (s) => s.get(PRF_META_ID));
  if (!row?.credentialId || !row?.firstSalt) return null;
  return {
    credentialId: row.credentialId,
    firstSalt: new Uint8Array(row.firstSalt),
  };
}

/**
 * @param {ArrayBuffer} credentialId
 * @param {Uint8Array} firstSalt
 */
async function savePrfMeta(credentialId, firstSalt) {
  await withStore(STORE_KEK, "readwrite", (s) =>
    s.put({
      id: PRF_META_ID,
      credentialId,
      firstSalt: firstSalt.buffer.slice(
        firstSalt.byteOffset,
        firstSalt.byteOffset + firstSalt.byteLength
      ),
    })
  );
}

/**
 * Create a platform passkey with PRF enabled (first time).
 * @param {string} userEmail
 * @returns {Promise<Uint8Array>} PRF output (32 bytes)
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
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "preferred",
        },
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
  await savePrfMeta(cred.rawId, firstSalt);
  return new Uint8Array(prfResults);
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
 * Zero a buffer best-effort.
 * @param {ArrayBuffer|Uint8Array|null|undefined} buf
 */
function zeroBuffer(buf) {
  if (!buf) return;
  try {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    u8.fill(0);
  } catch (_) {
    /* ignore */
  }
}

/**
 * List vault key metadata (no private material).
 * @returns {Promise<VaultKeyMeta[]>}
 */
export async function listKeys() {
  await purgeExpired();
  const rows = await withStore(STORE_KEYS, "readonly", (s) => s.getAll());
  return (rows || []).map((r) => ({
    fingerprint: r.fingerprint,
    uid: r.uid || "",
    email: r.email || "",
    name: r.name || "",
    created: r.created,
    expires: r.expires ?? null,
    protection: r.protection,
  }));
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
 * @returns {Promise<VaultKeyMeta>}
 */
export async function saveKey(opts) {
  const fpr = String(opts.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (fpr.length < 40) throw new Error("Invalid fingerprint");

  const encoder = new TextEncoder();
  const payload = encoder.encode(opts.armoredPrivate);
  const deviceKek = await getOrCreateDeviceKek();
  const { iv, ciphertext } = await aesGcmEncrypt(deviceKek, payload);
  zeroBuffer(payload);

  /** @type {VaultKeyRecord} */
  const record = {
    fingerprint: fpr,
    uid: opts.uid || "",
    email: opts.email || "",
    name: opts.name || "",
    created: new Date().toISOString(),
    expires: opts.expires || null,
    protection: opts.protection,
    wrapped: ciphertext,
    iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
  };

  if (opts.protection === "passkey") {
    if (!opts.prfIkm) throw new Error("PRF IKM required for passkey protection");
    const prfKek = await derivePrfKek(opts.prfIkm);
    const outerPlain = new Uint8Array(ciphertext);
    const outer = await aesGcmEncrypt(prfKek, outerPlain);
    zeroBuffer(outerPlain);
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
  zeroBuffer(plainBuf);
  if (deviceCipher instanceof ArrayBuffer && record.protection === "passkey") {
    zeroBuffer(deviceCipher);
  }
  return armored;
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
    zeroBuffer(record.wrapped);
    zeroBuffer(record.iv);
    zeroBuffer(record.outerWrapped);
    zeroBuffer(record.outerIv);
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
