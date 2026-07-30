/**
 * Session default (Preferences) + per-step OpenPGP crypto-profile resolution.
 * Shared by the notebook engine (actual encrypt calls) and the Toolkit UI
 * (CryptoProfileControl, consequence banners) so both compute the same
 * effective profile for a `gpg.encrypt` / `gpg.symencrypt` step.
 * @module lib/pgp/profile-from-step
 */
import { PROFILE_AUTO, PROFILE_COMPATIBLE, PROFILE_MODERN } from "./encrypt.js";

/** @typedef {import("./types.js").EncryptProfile} EncryptProfile */

/**
 * Session-wide default mode (Preferences → Cryptographic parameters) → EncryptProfile.
 * @param {"auto"|"modern"|"compatible"} mode
 * @returns {EncryptProfile}
 */
export function profileForMode(mode) {
  if (mode === "modern") return { ...PROFILE_MODERN };
  if (mode === "compatible") return { ...PROFILE_COMPATIBLE };
  return { ...PROFILE_AUTO };
}

/**
 * A step's `profile=custom` sub-params → concrete EncryptProfile.
 * `aead="off"` maps to `null` (legacy SEIPD v1); `compression="off"` maps to
 * `"uncompressed"` — matching the enum values `encrypt.js`/`algos.js` expect.
 * @param {Record<string, unknown>} [params]
 * @returns {EncryptProfile}
 */
export function customProfileFromParams(params) {
  const aead = String(params?.aead ?? "ocb");
  const compression = String(params?.compression ?? "off");
  return {
    cipher: String(params?.cipher ?? "aes256"),
    aead: aead === "off" ? null : aead,
    compression: compression === "off" ? "uncompressed" : compression,
    s2k: String(params?.s2k ?? "argon2"),
  };
}

/**
 * Whether a step's own `profile` param overrides the session default.
 * @param {{ params?: Record<string, unknown> }} [step]
 * @returns {boolean}
 */
export function stepOverridesProfile(step) {
  const mode = String(step?.params?.profile || "auto").toLowerCase();
  return mode === "modern" || mode === "compatible" || mode === "custom";
}

/**
 * Effective EncryptProfile for a `gpg.encrypt` / `gpg.symencrypt` step: the
 * step's own `profile` param when it overrides, else the session default.
 * @param {{ params?: Record<string, unknown> }} [step]
 * @param {EncryptProfile} [sessionProfile]
 * @returns {EncryptProfile}
 */
export function resolveStepProfile(step, sessionProfile) {
  const mode = String(step?.params?.profile || "auto").toLowerCase();
  if (mode === "modern") return { ...PROFILE_MODERN };
  if (mode === "compatible") return { ...PROFILE_COMPATIBLE };
  if (mode === "custom") return customProfileFromParams(step?.params);
  return sessionProfile ? { ...sessionProfile } : { ...PROFILE_AUTO };
}
