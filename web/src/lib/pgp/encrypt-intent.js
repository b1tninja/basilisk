/**
 * Pre-encrypt intent summaries derived from the active profile + recipient caps.
 * Does not re-parse ciphertext — that is summarizeEncryption()'s job after encrypt.
 * @module lib/pgp/encrypt-intent
 */

import {
  PROFILE_AUTO,
  PROFILE_COMPATIBLE,
  PROFILE_MODERN,
} from "./encrypt.js";

const CIPHER_LABEL = {
  aes128: "AES-128",
  aes192: "AES-192",
  aes256: "AES-256",
};

const AEAD_LABEL = {
  ocb: "OCB",
  gcm: "GCM",
  eax: "EAX",
};

const COMPRESSION_LABEL = {
  uncompressed: null,
  zip: "ZIP",
  zlib: "ZLIB",
};

/**
 * @param {import("./types.js").EncryptProfile} profile
 * @returns {string}
 */
export function formatProfileSpec(profile) {
  const cipher = CIPHER_LABEL[profile.cipher] || profile.cipher;
  if (profile.aead) {
    const aead = AEAD_LABEL[profile.aead] || String(profile.aead).toUpperCase();
    const s2k = profile.s2k === "argon2" ? "Argon2" : "iterated S2K";
    return `${cipher} · ${aead} · SEIPD v2 · ${s2k}`;
  }
  const s2k = profile.s2k === "argon2" ? "Argon2" : "iterated S2K";
  return `${cipher} · SEIPD v1 (CFB+MDC) · ${s2k}`;
}

/**
 * Whether AEAD / SEIPD v2 will actually apply given recipient capabilities.
 * OpenPGP.js only emits SEIPD v2 for public-key encryption when every recipient
 * advertises seipdv2; passphrase-only encryption follows aeadProtect directly.
 *
 * @param {import("./types.js").EncryptProfile} profile
 * @param {{ hasKeys?: boolean, hasPassphrase?: boolean, allModern?: boolean, legacyCount?: number, totalKeys?: number }} opts
 * @returns {{
 *   summary: string,
 *   parts: string[],
 *   useAead: boolean,
 *   degraded: boolean,
 *   note: string,
 * }}
 */
export function describeEncryptIntent(profile, opts = {}) {
  const hasKeys = !!opts.hasKeys;
  const hasPassphrase = !!opts.hasPassphrase;
  const allModern = opts.allModern !== false;
  const legacyCount = opts.legacyCount || 0;
  const totalKeys = opts.totalKeys || 0;

  const wantsAead = !!profile.aead;
  const aeadBlocked = wantsAead && hasKeys && !allModern;
  const useAead = wantsAead && !aeadBlocked;

  /** @type {string[]} */
  const parts = [CIPHER_LABEL[profile.cipher] || profile.cipher];
  if (useAead) {
    parts.push(AEAD_LABEL[profile.aead] || String(profile.aead).toUpperCase());
    parts.push("SEIPD v2");
  } else {
    parts.push("SEIPD v1 (CFB+MDC)");
  }
  if (hasPassphrase) {
    parts.push(profile.s2k === "argon2" ? "Argon2" : "iterated S2K");
  }
  const comp = COMPRESSION_LABEL[profile.compression];
  if (comp) parts.push(comp);

  let note = "";
  if (aeadBlocked) {
    note = `${legacyCount} of ${totalKeys} recipient${totalKeys === 1 ? "" : "s"} lack SEIPDv2 — using the compatible format.`;
  } else if (wantsAead && hasKeys && allModern && totalKeys > 0) {
    note = `All ${totalKeys} recipient${totalKeys === 1 ? "" : "s"} support modern (SEIPDv2) encryption.`;
  } else if (wantsAead && !hasKeys && hasPassphrase) {
    note = "Passphrase-only: AEAD applies from the selected profile.";
  } else if (!wantsAead) {
    note = "Compatible profile: SEIPD v1 for broad client support.";
  }

  return {
    summary: parts.join(" · "),
    parts,
    useAead,
    degraded: aeadBlocked,
    note,
  };
}

/**
 * Compare a profile to named presets; return custom divergence details.
 * @param {import("./types.js").EncryptProfile} profile
 * @returns {{
 *   preset: "compatible"|"modern"|"auto"|"custom",
 *   changes: string[],
 *   explanation: string,
 * }}
 */
export function describeProfileDivergence(profile) {
  if (profilesEqual(profile, PROFILE_COMPATIBLE)) {
    return { preset: "compatible", changes: [], explanation: "" };
  }
  if (profilesEqual(profile, PROFILE_MODERN) || profilesEqual(profile, PROFILE_AUTO)) {
    return { preset: "modern", changes: [], explanation: "" };
  }

  /** Prefer explaining against Modern when AEAD is on, else Compatible. */
  const baseline = profile.aead ? PROFILE_MODERN : PROFILE_COMPATIBLE;
  const baselineName = profile.aead ? "Modern" : "Compatible";
  /** @type {string[]} */
  const changes = [];

  if (profile.cipher !== baseline.cipher) {
    changes.push(
      `${CIPHER_LABEL[profile.cipher] || profile.cipher} instead of ${CIPHER_LABEL[baseline.cipher]}`
    );
  }
  if (profile.aead !== baseline.aead) {
    const have = profile.aead
      ? AEAD_LABEL[profile.aead] || profile.aead
      : "SEIPD v1 (no AEAD)";
    const want = baseline.aead
      ? AEAD_LABEL[baseline.aead] || baseline.aead
      : "SEIPD v1 (no AEAD)";
    changes.push(`${have} instead of ${want}`);
  }
  if (profile.compression !== baseline.compression) {
    changes.push(
      `${profile.compression === "uncompressed" ? "no compression" : profile.compression} instead of ${baseline.compression === "uncompressed" ? "no compression" : baseline.compression}`
    );
  }
  if (profile.s2k !== baseline.s2k) {
    changes.push(
      `${profile.s2k === "argon2" ? "Argon2" : "iterated S2K"} instead of ${baseline.s2k === "argon2" ? "Argon2" : "iterated S2K"}`
    );
  }

  const explanation = changes.length
    ? `Diverges from ${baselineName}: ${changes.join("; ")}.`
    : "Custom options do not match a named preset.";

  return { preset: "custom", changes, explanation };
}

/**
 * @param {import("./types.js").EncryptProfile} a
 * @param {import("./types.js").EncryptProfile} b
 */
function profilesEqual(a, b) {
  return (
    a.cipher === b.cipher &&
    a.aead === b.aead &&
    a.compression === b.compression &&
    a.s2k === b.s2k
  );
}
