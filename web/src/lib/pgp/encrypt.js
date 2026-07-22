/**
 * Encrypt service: profile → OpenPGP.js config + multi-payload encrypt loop.
 * @module lib/pgp/encrypt
 */

import { createMessage, encrypt, enums, readMessage } from "openpgp";
import {
  dearmorToBytes,
  enrichSpansWithPackets,
  mapPacketSpans,
} from "../packet-map.js";
import { AEAD, COMPRESSION, SYMMETRIC, algoName, s2kTypeName } from "./algos.js";

/** @type {import("./types.js").EncryptProfile} */
export const PROFILE_COMPATIBLE = {
  cipher: "aes256",
  aead: null,
  compression: "uncompressed",
  s2k: "iterated",
};

/** @type {import("./types.js").EncryptProfile} */
export const PROFILE_MODERN = {
  cipher: "aes256",
  aead: "ocb",
  compression: "uncompressed",
  s2k: "argon2",
};

/**
 * Auto preset: request Modern; OpenPGP.js degrades to SEIPD v1 when any
 * recipient key lacks the seipdv2 feature flag. Safe default for novices.
 * @type {import("./types.js").EncryptProfile}
 */
export const PROFILE_AUTO = { ...PROFILE_MODERN };

const CIPHER_ENUM = {
  aes128: enums.symmetric.aes128,
  aes192: enums.symmetric.aes192,
  aes256: enums.symmetric.aes256,
};

const AEAD_ENUM = {
  gcm: enums.aead.gcm,
  ocb: enums.aead.ocb,
  eax: enums.aead.eax,
};

const COMPRESSION_ENUM = {
  uncompressed: enums.compression.uncompressed,
  zip: enums.compression.zip,
  zlib: enums.compression.zlib,
};

const S2K_ENUM = {
  argon2: enums.s2k.argon2,
  iterated: enums.s2k.iterated,
};

/**
 * Map an {@link EncryptProfile} to an OpenPGP.js per-call config override.
 * @param {import("./types.js").EncryptProfile} profile
 * @returns {Partial<import("openpgp").Config>}
 */
export function profileToConfig(profile) {
  const cipher = CIPHER_ENUM[profile.cipher] ?? enums.symmetric.aes256;
  const compression =
    COMPRESSION_ENUM[profile.compression] ?? enums.compression.uncompressed;
  const s2k = S2K_ENUM[profile.s2k] ?? enums.s2k.iterated;

  /** @type {Partial<import("openpgp").Config>} */
  const config = {
    preferredSymmetricAlgorithm: cipher,
    preferredCompressionAlgorithm: compression,
    s2kType: s2k,
  };

  if (profile.aead) {
    config.aeadProtect = true;
    config.preferredAEADAlgorithm = AEAD_ENUM[profile.aead] ?? enums.aead.ocb;
  } else {
    config.aeadProtect = false;
  }

  return config;
}

/**
 * Encrypt one or more payloads per {@link EncryptRequest}.
 * @param {import("./types.js").EncryptRequest} request
 * @returns {Promise<import("./types.js").EncryptArtifact[]>}
 */
export async function encryptArtifacts(request) {
  const {
    recipients = [],
    passwords = [],
    payloads = [],
    profile,
    hideRecipients = false,
    signingKeys = [],
  } = request;
  if (!payloads.length) return [];
  if (!recipients.length && !passwords.length) {
    throw new Error("At least one recipient or passphrase is required.");
  }

  const config = profileToConfig(profile || PROFILE_COMPATIBLE);
  const encryptOpts = {
    format: /** @type {const} */ ("armored"),
    config,
    wildcard: !!hideRecipients,
    ...(recipients.length ? { encryptionKeys: recipients } : {}),
    ...(passwords.length ? { passwords } : {}),
    ...(signingKeys.length ? { signingKeys } : {}),
  };

  /** @type {import("./types.js").EncryptArtifact[]} */
  const out = [];
  for (const payload of payloads) {
    if (payload.kind === "text") {
      const text = String(payload.text || "");
      const msg = await createMessage({ text });
      const armored = await encrypt({ message: msg, ...encryptOpts });
      out.push({
        label: "Message",
        filename: "encrypted-message.asc",
        armored: String(armored),
      });
    } else if (payload.kind === "file") {
      const bytes = payload.bytes;
      if (!(bytes instanceof Uint8Array)) {
        throw new Error("File payload requires bytes.");
      }
      const filename = payload.filename || "file";
      const msg = await createMessage({ binary: bytes, filename });
      const armored = await encrypt({ message: msg, ...encryptOpts });
      // Best-effort wipe of plaintext buffer after encrypt (inlined — see memory-safety.js).
      try {
        bytes.fill(0);
      } catch (_) {
        /* wipe */
      }
      out.push({
        label: filename,
        filename: `${filename}.asc`,
        armored: String(armored),
      });
    } else {
      throw new Error(`Unknown payload kind: ${payload.kind}`);
    }
  }
  return out;
}

/**
 * Padding packets (RFC 9580 tag 21): OpenPGP.js 6.x defines `PaddingPacket` for
 * parse/write, but the high-level `encrypt()` path does not expose a config flag
 * to emit padding. Enabling would require forking message construction.
 * Investigation result (2026-07): skip — no trivial opt-in.
 */

/**
 * Honest summary of what was actually written into an armored ciphertext,
 * derived by re-parsing packets (not echoing the intended profile).
 * @param {string} armored
 * @returns {Promise<string>}
 */
export async function summarizeEncryption(armored) {
  const parts = [];
  try {
    const binary = dearmorToBytes(armored);
    const spans = mapPacketSpans(binary);
    const message = await readMessage({ armoredMessage: armored });
    const enriched = enrichSpansWithPackets(spans, message.packets);

    let cipher = null;
    let aead = null;
    let seipdV1 = false;
    let compression = null;
    let s2k = null;

    for (const span of enriched) {
      const pkt = span.packet;
      if (!pkt) continue;
      if (span.tag === 18) {
        const ver = pkt.version ?? 1;
        if (ver >= 2) {
          cipher = algoName(SYMMETRIC, pkt.cipherAlgorithm) || cipher;
          aead = algoName(AEAD, pkt.aeadAlgorithm) || aead;
        } else {
          seipdV1 = true;
        }
      } else if (span.tag === 8) {
        compression = algoName(COMPRESSION, pkt.algorithm) || compression;
      } else if (span.tag === 3) {
        const t = s2kTypeName(pkt.s2k);
        if (t) s2k = t;
      }
    }

    if (cipher && aead) {
      parts.push(`${cipher}-${aead}`);
    } else if (seipdV1) {
      parts.push(cipher ? `${cipher} (SEIPD v1)` : "SEIPD v1 (CFB+MDC)");
    } else if (cipher) {
      parts.push(cipher);
    }

    if (compression && compression !== "Uncompressed") {
      parts.push(compression);
    }
    if (s2k) {
      parts.push(s2k === "argon2" ? "Argon2" : s2k);
    }
  } catch (_) {
    /* best-effort */
  }
  return parts.length ? parts.join(" · ") : "encrypted";
}
