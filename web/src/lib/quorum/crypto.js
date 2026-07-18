/**
 * Quorum authenticated key exchange: PGP-signed/encrypted signaling +
 * pairwise P-256 ECDH → HKDF-SHA-256 → AES-GCM-256.
 * @module lib/quorum/crypto
 */

import {
  createMessage,
  decrypt,
  encrypt,
  readKey,
  readMessage,
  readPrivateKey,
} from "openpgp";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";

/**
 * @typedef {object} QuorumEnvelopePayload
 * @property {1} v
 * @property {"hello"|"offer"|"answer"|"ice"} type
 * @property {string} from
 * @property {string|null} [to]
 * @property {string} roomId
 * @property {string} [sdp]
 * @property {RTCIceCandidateInit|null} [candidate]
 * @property {string} [dtlsFingerprint]
 * @property {JsonWebKey} [ecdhPublicJwk]
 * @property {number} ts
 */

/**
 * Generate an ephemeral P-256 ECDH keypair (WebCrypto).
 * @returns {Promise<CryptoKeyPair>}
 */
export async function generateEcdhKeyPair() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
}

/**
 * @param {CryptoKey} publicKey
 * @returns {Promise<JsonWebKey>}
 */
export async function exportEcdhPublicJwk(publicKey) {
  return crypto.subtle.exportKey("jwk", publicKey);
}

/**
 * @param {JsonWebKey} jwk
 * @returns {Promise<CryptoKey>}
 */
export async function importEcdhPublicJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

/**
 * Pairwise session key: ECDH → HKDF-SHA-256 (info = roomId + both fprs sorted).
 * Deterministic in both directions.
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} peerPublicKey
 * @param {string} roomId
 * @param {string} myFpr
 * @param {string} peerFpr
 * @returns {Promise<CryptoKey>} AES-GCM-256 key
 */
export async function derivePairwiseSessionKey(
  privateKey,
  peerPublicKey,
  roomId,
  myFpr,
  peerFpr
) {
  const a = normalizeFingerprintInput(myFpr);
  const b = normalizeFingerprintInput(peerFpr);
  const [lo, hi] = a < b ? [a, b] : [b, a];
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    256
  );
  const ikm = await crypto.subtle.importKey("raw", bits, "HKDF", false, [
    "deriveKey",
  ]);
  const info = new TextEncoder().encode(
    `basilisk-quorum-session|${roomId}|${lo}|${hi}`
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info,
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * @param {CryptoKey} aesKey
 * @param {string} plaintext
 * @returns {Promise<string>} base64(iv||ciphertext)
 */
export async function encryptSessionPayload(aesKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(plaintext)
  );
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.length);
  return bytesToBase64(out);
}

/**
 * @param {CryptoKey} aesKey
 * @param {string} blob
 * @returns {Promise<string>}
 */
export async function decryptSessionPayload(aesKey, blob) {
  const raw = base64ToBytes(blob);
  if (raw.length < 13) throw new Error("Session ciphertext too short");
  const iv = raw.slice(0, 12);
  const ct = raw.slice(12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
  return new TextDecoder().decode(pt);
}

/**
 * Extract DTLS fingerprint lines from SDP.
 * @param {string} sdp
 * @returns {string}
 */
export function extractDtlsFingerprint(sdp) {
  const lines = String(sdp || "").split(/\r?\n/);
  const fps = [];
  for (const line of lines) {
    const m = line.match(/^a=fingerprint:(\S+)\s+(\S+)/i);
    if (m) fps.push(`${m[1].toLowerCase()} ${m[2].toUpperCase()}`);
  }
  return fps.join("|");
}

/**
 * Sign + encrypt a signaling envelope to all audience public keys.
 * @param {object} opts
 * @param {QuorumEnvelopePayload} opts.payload
 * @param {import("openpgp").PrivateKey} opts.signingKey
 * @param {import("openpgp").Key[]} opts.audienceKeys
 * @returns {Promise<string>} armored PGP message
 */
export async function sealSignalingEnvelope({ payload, signingKey, audienceKeys }) {
  if (!audienceKeys?.length) {
    throw new Error("No audience encryption keys");
  }
  const text = JSON.stringify(payload);
  return encrypt({
    message: await createMessage({ text }),
    encryptionKeys: audienceKeys,
    signingKeys: signingKey,
    format: "armored",
  });
}

/**
 * Decrypt + verify a signaling envelope; reject if signer not in audience.
 * @param {object} opts
 * @param {string} opts.armored
 * @param {import("openpgp").PrivateKey} opts.decryptionKey
 * @param {Map<string, import("openpgp").Key>} opts.audienceKeyByFpr
 * @param {string[]} opts.audienceFprs
 * @param {string} opts.expectedRoomId
 * @returns {Promise<{ payload: QuorumEnvelopePayload, signerFpr: string }>}
 */
export async function openSignalingEnvelope({
  armored,
  decryptionKey,
  audienceKeyByFpr,
  audienceFprs,
  expectedRoomId,
}) {
  const allowed = new Set(
    (audienceFprs || []).map((f) => normalizeFingerprintInput(f))
  );
  const verificationKeys = [...audienceKeyByFpr.values()];
  const { data, signatures } = await decrypt({
    message: await readMessage({ armoredMessage: armored }),
    decryptionKeys: decryptionKey,
    verificationKeys,
  });
  if (!signatures?.length) {
    throw new Error("Signaling envelope missing signature");
  }
  await signatures[0].verified;
  const kidHex = String(signatures[0].keyID?.toHex?.() || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  let signerFpr = "";
  for (const [fpr, key] of audienceKeyByFpr) {
    if (!allowed.has(fpr)) continue;
    const primary = normalizeFingerprintInput(key.getFingerprint?.() || fpr);
    if (kidHex && primary.endsWith(kidHex)) {
      signerFpr = primary;
      break;
    }
    try {
      const keyID = signatures[0].keyID;
      for (const id of key.getKeyIDs?.() || []) {
        if (keyID && id.equals?.(keyID)) {
          signerFpr = primary;
          break;
        }
      }
    } catch (_) {
      /* ignore */
    }
    if (signerFpr) break;
  }
  if (!signerFpr || !allowed.has(signerFpr)) {
    throw new Error("Signaling signer is not in the room audience");
  }
  /** @type {QuorumEnvelopePayload} */
  let payload;
  try {
    payload = JSON.parse(String(data));
  } catch {
    throw new Error("Signaling payload is not JSON");
  }
  if (payload.v !== 1) throw new Error("Unsupported signaling version");
  if (payload.roomId !== expectedRoomId) {
    throw new Error("Signaling room id mismatch");
  }
  const from = normalizeFingerprintInput(payload.from);
  if (from !== signerFpr) {
    throw new Error("Signaling from fingerprint does not match signer");
  }
  payload.from = from;
  if (payload.to) payload.to = normalizeFingerprintInput(payload.to);
  return { payload, signerFpr };
}

/**
 * Load OpenPGP public keys for audience fingerprints from the keyserver.
 * @param {string[]} fingerprints
 * @returns {Promise<Map<string, import("openpgp").Key>>}
 */
export async function fetchAudienceKeys(fingerprints) {
  /** @type {Map<string, import("openpgp").Key>} */
  const map = new Map();
  for (const raw of fingerprints) {
    const fpr = normalizeFingerprintInput(raw);
    if (!(fpr.length === 40 || fpr.length === 64)) continue;
    const r = await fetch(
      `/pks/lookup?op=get&search=${encodeURIComponent(`0x${fpr}`)}`
    );
    if (!r.ok) {
      throw new Error(`Failed to fetch key ${fpr.slice(0, 8)}… (${r.status})`);
    }
    const armored = await r.text();
    if (!armored.includes("BEGIN PGP")) {
      throw new Error(`No public key for ${fpr.slice(0, 8)}…`);
    }
    const key = await readKey({ armoredKey: armored });
    map.set(normalizeFingerprintInput(key.getFingerprint()), key);
  }
  return map;
}

/**
 * @param {string} armoredPrivate
 * @param {string} [passphrase]
 * @returns {Promise<import("openpgp").PrivateKey>}
 */
export async function unlockPrivateKey(armoredPrivate, passphrase = "") {
  let key = await readPrivateKey({ armoredKey: armoredPrivate });
  if (!key.isDecrypted()) {
    const { decryptKey } = await import("openpgp");
    key = await decryptKey({ privateKey: key, passphrase });
  }
  return key;
}

/** @param {Uint8Array} bytes */
function bytesToBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/** @param {string} b64 */
function base64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
