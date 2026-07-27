/**
 * Shared My Keys unlock path for Encrypt / Decrypt / Toolkit / agent.unlock.
 */

import {
  getPasskeyPrf,
  listKeys,
  touchKeyUsed,
  unlockKey,
} from "./vault.js";
import {
  normalizeVaultFingerprint,
  sessionGet,
  sessionPut,
  sessionTouch,
} from "./vault-session.js";

/**
 * @typedef {object} VaultUnlockResult
 * @property {string} armored
 * @property {string} openPgpPassphrase  OpenPGP S2K passphrase (may be empty)
 * @property {string} fingerprint
 * @property {import("./vault.js").VaultProtection} protection
 */

/**
 * Unlock a vault private key (session-cached). Passkey ceremony when needed.
 *
 * @param {string} fingerprint
 * @param {{
 *   openPgpPassphrase?: string,
 *   prfIkm?: Uint8Array,
 *   meta?: import("./vault.js").VaultKeyMeta,
 *   skipSession?: boolean,
 * }} [opts]
 * @returns {Promise<VaultUnlockResult>}
 */
export async function unlockVaultForUse(fingerprint, opts = {}) {
  const fpr = normalizeVaultFingerprint(fingerprint);
  if (fpr.length < 40) throw new Error("Invalid vault fingerprint");

  const openPgpPassphrase = String(opts.openPgpPassphrase || "");
  /** @type {import("./vault.js").VaultKeyMeta|undefined} */
  let meta = opts.meta;
  if (!meta) {
    const all = await listKeys();
    meta = all.find((k) => k.fingerprint === fpr);
  }
  if (!meta) throw new Error("Key not found in vault");

  if (!opts.skipSession) {
    const cached = sessionGet(fpr);
    if (cached) {
      sessionTouch(fpr);
      try {
        await touchKeyUsed(fpr);
      } catch (_) {
        /* ignore */
      }
      return {
        armored: cached,
        openPgpPassphrase,
        fingerprint: fpr,
        protection: meta.protection,
      };
    }
  }

  /** @type {{ passphrase?: string, prfIkm?: Uint8Array }} */
  const unlockOpts = {};
  let ownedPrf = false;
  try {
    if (meta.protection === "passkey") {
      if (opts.prfIkm) {
        unlockOpts.prfIkm = opts.prfIkm;
      } else {
        unlockOpts.prfIkm = await getPasskeyPrf();
        ownedPrf = true;
      }
    }
    const armored = await unlockKey(fpr, unlockOpts);
    if (!opts.skipSession) sessionPut(fpr, armored);
    try {
      await touchKeyUsed(fpr);
    } catch (_) {
      /* ignore */
    }
    return {
      armored,
      openPgpPassphrase,
      fingerprint: fpr,
      protection: meta.protection,
    };
  } finally {
    if (ownedPrf) {
      try {
        unlockOpts.prfIkm?.fill?.(0);
      } catch (_) {
        /* wipe */
      }
    }
  }
}
