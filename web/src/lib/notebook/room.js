/**
 * Notebook room / channel identity from audience fingerprints + site scope.
 * Scope defaults to the WebAuthn relying-party id (`location.hostname`) so
 * the same audience on different deployments gets different room ids —
 * no separate notebook config required.
 * @module lib/notebook/room
 */

import { bytesToBase32 } from "../toolkit/encode.js";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";

export { bytesToBase32 };

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
 * Relying-party / deployment scope for room derivation.
 * Matches vault WebAuthn RP id: `location.hostname` (no scheme/port).
 * @param {string} [override] explicit hostname for tests or advanced callers
 * @returns {string} lowercase hostname
 */
export function notebookRelyingPartyId(override) {
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

/** Length of the public room id — the part that may be spoken aloud. */
export const ROOM_ID_LEN = 16;

/** Full base32 of a SHA-256 digest: ceil(256/5) characters, unpadded. */
export const ROOM_KEY_LEN = 52;

/**
 * Room material: the whole digest, and the prefix of it that is the room id.
 *
 * `roomId` is what a person reads out and what the server rate-limits on. It is
 * 80 bits of the digest and nothing more. `roomKey` is all 256 bits, and the
 * only way to hold it is to have computed it — which takes the relying party
 * and the full audience, i.e. *being told who is meeting*, not just being told
 * the code.
 *
 * That gap is the admission boundary the negotiate endpoint enforces: an id
 * alone buys a token for the room's lobby, and only the key buys a token for
 * the group where signalling is broadcast. Truncation is what makes the two
 * derivable from one computation and non-invertible in the other direction —
 * the server can check `roomKey.startsWith(roomId)` without ever learning the
 * audience, which is why the audience never goes over the wire.
 *
 * **Epoch.** Epoch 0 mixes nothing, so every room id that has ever been derived
 * is unchanged. A later epoch appends a counter, so a rotation lands on an
 * unrelated group whose name no earlier token carries a role for.
 *
 * **Secret.** The epoch alone would only move the room somewhere the party
 * being removed can also compute — they know the audience and they can count.
 * A rotation therefore also mixes a secret minted at the moment of rotation
 * and delivered sealed to the members who stay, so the new name is not a
 * function of anything the removed party holds. Rotation without a secret is
 * still meaningful — it strands the token they already have — but it is not
 * exclusion, and the two should not be confused.
 *
 * @param {string[]} fingerprints
 * @param {{ relyingPartyId?: string, epoch?: number, secret?: string }} [opts]
 * @returns {Promise<{ roomId: string, roomKey: string, epoch: number }>}
 */
export async function deriveRoomMaterial(fingerprints, opts = {}) {
  const audience = canonicalAudience(fingerprints);
  if (audience.length < 2) {
    throw new Error("Notebook room requires at least two audience fingerprints");
  }
  const epoch = Math.max(0, Math.trunc(Number(opts.epoch) || 0));
  const secret = String(opts.secret || "");
  const rpId = notebookRelyingPartyId(opts.relyingPartyId);
  const material =
    `${rpId}|${audience.join("|")}` +
    (epoch > 0 ? `|epoch:${epoch}` : "") +
    (secret ? `|rot:${secret}` : "");
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(material)
  );
  const roomKey = bytesToBase32(new Uint8Array(digest)).slice(0, ROOM_KEY_LEN);
  return { roomId: roomKey.slice(0, ROOM_ID_LEN), roomKey, epoch };
}

/**
 * @param {string[]} fingerprints
 * @param {{ relyingPartyId?: string, epoch?: number }} [opts]
 * @returns {Promise<string>} 16-char base32 room id
 */
export async function deriveRoomId(fingerprints, opts = {}) {
  return (await deriveRoomMaterial(fingerprints, opts)).roomId;
}

/**
 * @param {string} roomKey
 * @returns {boolean}
 */
export function isValidRoomKey(roomKey) {
  return new RegExp(`^[A-Z2-7]{${ROOM_KEY_LEN}}$`).test(
    String(roomKey || "").trim().toUpperCase()
  );
}

/**
 * Derive a labeled sub-id (topic / channel) from a room id via HKDF-SHA-256.
 * @param {string} roomId
 * @param {string} label
 * @param {{ relyingPartyId?: string }} [opts]
 * @returns {Promise<string>}
 */
export async function deriveChannelId(roomId, label, opts = {}) {
  const rpId = notebookRelyingPartyId(opts.relyingPartyId);
  const ikm = new TextEncoder().encode(String(roomId || ""));
  // `basilisk-quorum-channel` keeps its old spelling deliberately: it is HKDF
  // `info`, so every channel id ever derived is a function of these exact
  // bytes. Renaming it with the layer would move every channel at once, and
  // two peers on different spellings would derive different ids for the same
  // label and quietly talk past each other.
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
