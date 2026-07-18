/**
 * Quorum room / channel identity from audience fingerprints + site scope.
 * Scope defaults to the WebAuthn relying-party id (`location.hostname`) so
 * the same audience on different deployments gets different room ids —
 * no separate Quorum config required.
 * @module lib/quorum/room
 */

import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Canonical audience: sorted, deduped, uppercase fingerprints (40 or 64 hex).
 * @param {string[]} fingerprints
 * @returns {string[]}
 */
export function canonicalAudience(fingerprints) {
  /** @type {Set<string>} */
  const set = new Set();
  for (const raw of fingerprints || []) {
    const fpr = normalizeFingerprintInput(raw);
    if (fpr.length === 40 || fpr.length === 64) set.add(fpr);
  }
  return [...set].sort();
}

/**
 * Relying-party / deployment scope for Quorum derivation.
 * Matches vault WebAuthn RP id: `location.hostname` (no scheme/port).
 * @param {string} [override] explicit hostname for tests or advanced callers
 * @returns {string} lowercase hostname
 */
export function quorumRelyingPartyId(override) {
  if (override != null && String(override).trim()) {
    return String(override).trim().toLowerCase();
  }
  try {
    if (typeof location !== "undefined" && location.hostname) {
      return String(location.hostname).toLowerCase();
    }
  } catch (_) {
    /* ignore */
  }
  return "localhost";
}

/**
 * RFC 4648 Base32 (no padding), uppercase.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase32(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/**
 * @param {string[]} fingerprints
 * @param {{ relyingPartyId?: string }} [opts]
 * @returns {Promise<string>} 16-char base32 room id
 */
export async function deriveRoomId(fingerprints, opts = {}) {
  const audience = canonicalAudience(fingerprints);
  if (audience.length < 2) {
    throw new Error("Quorum room requires at least two audience fingerprints");
  }
  const rpId = quorumRelyingPartyId(opts.relyingPartyId);
  const material = `${rpId}|${audience.join("|")}`;
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(material)
  );
  return bytesToBase32(new Uint8Array(digest)).slice(0, 16);
}

/**
 * Derive a labeled sub-id (topic / channel) from a room id via HKDF-SHA-256.
 * @param {string} roomId
 * @param {string} label
 * @param {{ relyingPartyId?: string }} [opts]
 * @returns {Promise<string>}
 */
export async function deriveChannelId(roomId, label, opts = {}) {
  const rpId = quorumRelyingPartyId(opts.relyingPartyId);
  const ikm = new TextEncoder().encode(String(roomId || ""));
  const info = new TextEncoder().encode(
    `basilisk-quorum-channel|${rpId}|${label || ""}`
  );
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info },
    key,
    128
  );
  return bytesToBase32(new Uint8Array(bits)).slice(0, 16);
}

/**
 * @param {string} roomId
 * @returns {boolean}
 */
export function isValidRoomId(roomId) {
  return /^[A-Z2-7]{8,32}$/.test(String(roomId || "").trim().toUpperCase());
}
