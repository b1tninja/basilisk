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
 * @property {"pgp"|"ssh"|"raw"} kind  What `armored` holds: PGP armor, openssh-key-v1 text, or a JWK (§28d)
 */

/**
 * Whether this armor still carries OpenPGP S2K protection.
 *
 * The vault's outer envelope and OpenPGP's own passphrase are two different
 * locks, and `unlockKey` opens only the first — its own return type says so
 * ("may still be OpenPGP passphrase-locked"). Nothing read that sentence, so
 * the chrome called every opened envelope "unlocked" and the run discovered
 * the second lock several steps later. See `sessionPut` for what the answer is
 * used for.
 *
 * `protection === "passphrase"` is the *intent* and this is the *observation*;
 * they normally agree, and where they do not the armor wins, because the armor
 * is what `decryptKey` will be handed. Observing costs one parse on a path that
 * has just run Argon2.
 *
 * Only PGP armor has an S2K to inspect. An ssh or raw record holds
 * openssh-key-v1 text or a bare JWK, which `readPrivateKey` cannot read at all,
 * so those answer `false` — nothing further is owed for them, which is the
 * honest reading of "no passphrase is outstanding".
 *
 * A parse failure answers `undefined` rather than guessing. An unreadable key
 * is a problem, but it is not *this* problem, and claiming either state would
 * put a sentence on screen about something never established.
 *
 * @param {string} armored
 * @param {"pgp"|"ssh"|"raw"|undefined} kind
 * @returns {Promise<boolean|undefined>}
 */
async function stillOwesAPassphrase(armored, kind) {
  if (kind && kind !== "pgp") return false;
  try {
    // Lazily, matching `agent-ops.js` and `keyring-service.js`: OpenPGP is a
    // large dependency and this module is imported by chrome that may never
    // unlock anything.
    const { isArmoredKeyLocked } = await import("./key-export.js");
    return await isArmoredKeyLocked(armored);
  } catch (_) {
    return undefined;
  }
}

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
  // Kind-shaped ids (SHA256:…) pass normalize verbatim; only the hex form
  // has a minimum length to enforce (§28a).
  if (!fpr.startsWith("SHA256:") && !fpr.startsWith("spki:") && fpr.length < 40) {
    throw new Error("Invalid vault fingerprint");
  }

  const openPgpPassphrase = String(opts.openPgpPassphrase || "");
  /** @type {import("./vault.js").VaultKeyMeta|undefined} */
  let meta = opts.meta;
  if (!meta) {
    try {
      const all = await listKeys();
      meta = all.find((k) => k.fingerprint === fpr);
    } catch (_) {
      // No vault in this context (or it failed to open) — a session-only key
      // can still resolve below.
    }
  }

  // Session cache first — and a session hit does not *require* vault
  // membership: a session-only key (minted in memory, never persisted) is
  // still a key the user holds. Only when neither the session nor the vault
  // knows the fingerprint is it genuinely not found.
  if (!opts.skipSession) {
    const cached = sessionGet(fpr);
    if (cached) {
      sessionTouch(fpr);
      if (meta) {
        try {
          await touchKeyUsed(fpr);
        } catch (_) {
          /* ignore */
        }
      }
      return {
        armored: cached,
        openPgpPassphrase,
        fingerprint: fpr,
        protection: meta?.protection || "session",
        kind: meta?.kind || "pgp",
      };
    }
  }
  if (!meta) throw new Error("Key not found in vault");

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
    if (!opts.skipSession) {
      sessionPut(fpr, armored, { locked: await stillOwesAPassphrase(armored, meta.kind) });
    }
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
      kind: meta.kind || "pgp",
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
