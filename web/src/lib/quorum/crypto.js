/**
 * Quorum authenticated key exchange: PGP-signed/encrypted signaling +
 * pairwise P-256 ECDH → HKDF-SHA-256 → AES-GCM-256 (transcript-bound v2).
 *
 * Signaling (mailbox) is encrypted to long-term audience keys and is not PFS.
 * Data-channel session keys use ephemeral ECDH and are discarded on leave.
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
import { canonicalAudience, deriveRoomId } from "./room.js";

/** Max age for a signed invite (ms). */
export const INVITE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * @typedef {object} QuorumEnvelopePayload
 * @property {1} v
 * @property {"invite"|"hello"|"offer"|"answer"|"ice"} type
 * @property {string} from
 * @property {string|null} [to]
 * @property {string} roomId
 * @property {string} [sdp]
 * @property {RTCIceCandidateInit|null} [candidate]
 * @property {string} [dtlsFingerprint]
 * @property {JsonWebKey} [ecdhPublicJwk]
 * @property {string[]} [audience]
 * @property {string} [initiator]
 * @property {string} [nonce]
 * @property {string} [helloNonce]
 * @property {string} [note]
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
 * @param {number} [byteLength]
 * @returns {string} lowercase hex
 */
export function randomNonceHex(byteLength = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Stable thumbprint of a P-256 ECDH JWK (SHA-256 hex of canonical JSON).
 * @param {JsonWebKey} jwk
 * @returns {Promise<string>}
 */
export async function jwkThumbprint(jwk) {
  const canon = JSON.stringify({
    crv: jwk.crv || "",
    kty: jwk.kty || "",
    x: jwk.x || "",
    y: jwk.y || "",
  });
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canon)
  );
  return bytesToHex(new Uint8Array(digest));
}

/**
 * @param {object} opts
 * @param {string} opts.roomId
 * @param {string[]} opts.audience
 * @param {string} opts.initiator
 * @param {JsonWebKey} opts.ecdhPublicJwk
 * @param {string} [opts.nonce]
 * @param {string} [opts.note]
 * @returns {QuorumEnvelopePayload}
 */
export function buildInvitePayload({
  roomId,
  audience,
  initiator,
  ecdhPublicJwk,
  nonce,
  note,
}) {
  const from = normalizeFingerprintInput(initiator);
  const aud = canonicalAudience(audience);
  return {
    v: 1,
    type: "invite",
    from,
    to: null,
    roomId: String(roomId || "")
      .trim()
      .toUpperCase(),
    audience: aud,
    initiator: from,
    nonce: nonce || randomNonceHex(32),
    ecdhPublicJwk,
    note: note ? String(note) : undefined,
    ts: Date.now(),
  };
}

/**
 * Validate a decrypted invite payload (after signature verification).
 * @param {QuorumEnvelopePayload} payload
 * @param {object} opts
 * @param {string} opts.signerFpr
 * @param {string} opts.expectedRoomId
 * @param {string[]} opts.expectedAudience
 * @param {number} [opts.now]
 * @param {number} [opts.maxAgeMs]
 * @returns {Promise<{ inviteNonce: string, initiator: string }>}
 */
export async function assertInvite(
  payload,
  {
    signerFpr,
    expectedRoomId,
    expectedAudience,
    now = Date.now(),
    maxAgeMs = INVITE_MAX_AGE_MS,
  }
) {
  if (payload.v !== 1) throw new Error("Unsupported invite version");
  if (payload.type !== "invite") throw new Error("Not an invite envelope");
  const signer = normalizeFingerprintInput(signerFpr);
  const from = normalizeFingerprintInput(payload.from);
  const initiator = normalizeFingerprintInput(payload.initiator || "");
  if (!from || from !== signer) {
    throw new Error("Invite from fingerprint does not match signer");
  }
  if (!initiator || initiator !== from) {
    throw new Error("Invite initiator must match signer");
  }
  const expected = canonicalAudience(expectedAudience);
  const claimed = canonicalAudience(payload.audience || []);
  if (expected.length < 2) {
    throw new Error("Expected audience too small");
  }
  if (
    claimed.length !== expected.length ||
    claimed.some((f, i) => f !== expected[i])
  ) {
    throw new Error("Invite audience does not match pinned audience");
  }
  if (!claimed.includes(initiator)) {
    throw new Error("Invite initiator is not in the audience");
  }
  const roomId = String(payload.roomId || "")
    .trim()
    .toUpperCase();
  const expectedRoom = String(expectedRoomId || "")
    .trim()
    .toUpperCase();
  if (roomId !== expectedRoom) {
    throw new Error("Invite room id mismatch");
  }
  const derived = await deriveRoomId(claimed);
  if (derived !== roomId) {
    throw new Error("Invite room id does not match audience derivation");
  }
  const ts = Number(payload.ts) || 0;
  if (!ts || Math.abs(now - ts) > maxAgeMs) {
    throw new Error("Invite timestamp out of range");
  }
  const inviteNonce = String(payload.nonce || "").toLowerCase();
  if (!/^[0-9a-f]{32,128}$/.test(inviteNonce)) {
    throw new Error("Invite nonce missing or invalid");
  }
  if (!payload.ecdhPublicJwk?.kty) {
    throw new Error("Invite missing ECDH public key");
  }
  return { inviteNonce, initiator };
}

/**
 * Ensure the local fingerprint is in the canonical audience.
 * @param {string} myFpr
 * @param {string[]} audienceFprs
 * @returns {string[]} canonical audience including myFpr
 */
export function requireSelfInAudience(myFpr, audienceFprs) {
  const me = normalizeFingerprintInput(myFpr);
  const audience = canonicalAudience([...audienceFprs, me]);
  if (!me || !(me.length === 40 || me.length === 64)) {
    throw new Error("Invalid local fingerprint");
  }
  if (!audience.includes(me)) {
    throw new Error("Local key must be in the room audience");
  }
  if (audience.length < 2) {
    throw new Error("Quorum room requires at least two audience fingerprints");
  }
  return audience;
}

/**
 * Pairwise session key (v2): ECDH → HKDF-SHA-256 with transcript-bound salt/info.
 * @param {object} opts
 * @param {CryptoKey} opts.privateKey local ECDH private
 * @param {CryptoKey} opts.peerPublicKey peer ECDH public
 * @param {string} opts.roomId
 * @param {string} opts.myFpr
 * @param {string} opts.peerFpr
 * @param {string[]} opts.audienceFprs
 * @param {JsonWebKey} opts.myEcdhJwk
 * @param {JsonWebKey} opts.peerEcdhJwk
 * @param {string} opts.inviteNonce
 * @param {string} opts.myHelloNonce
 * @param {string} opts.peerHelloNonce
 * @param {string} [opts.dtlsFingerprint]
 * @returns {Promise<{ aesKey: CryptoKey, transcriptHash: string }>}
 */
export async function derivePairwiseSessionKey({
  privateKey,
  peerPublicKey,
  roomId,
  myFpr,
  peerFpr,
  audienceFprs,
  myEcdhJwk,
  peerEcdhJwk,
  inviteNonce,
  myHelloNonce,
  peerHelloNonce,
  dtlsFingerprint = "",
}) {
  const a = normalizeFingerprintInput(myFpr);
  const b = normalizeFingerprintInput(peerFpr);
  const [lo, hi] = a < b ? [a, b] : [b, a];
  const audience = canonicalAudience(audienceFprs);
  const myThumb = await jwkThumbprint(myEcdhJwk);
  const peerThumb = await jwkThumbprint(peerEcdhJwk);
  const [loThumb, hiThumb] = a < b ? [myThumb, peerThumb] : [peerThumb, myThumb];
  const [loHello, hiHello] =
    a < b
      ? [String(myHelloNonce || ""), String(peerHelloNonce || "")]
      : [String(peerHelloNonce || ""), String(myHelloNonce || "")];

  const saltMaterial = `salt|${roomId}|${lo}|${hi}|${String(inviteNonce || "").toLowerCase()}|${loHello}|${hiHello}`;
  const saltDigest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(saltMaterial)
  );

  const infoStr = [
    "basilisk-quorum-session-v2",
    roomId,
    audience.join(","),
    lo,
    hi,
    loThumb,
    hiThumb,
    String(dtlsFingerprint || ""),
  ].join("|");
  const transcriptHash = bytesToHex(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(infoStr + "|" + saltMaterial)
      )
    )
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    256
  );
  const ikm = await crypto.subtle.importKey("raw", bits, "HKDF", false, [
    "deriveKey",
  ]);
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(saltDigest),
      info: new TextEncoder().encode(infoStr),
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  return { aesKey, transcriptHash };
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
 * Canonical pairwise DTLS binding (sorted sides).
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
export function combineDtlsFingerprints(a, b) {
  const x = String(a || "");
  const y = String(b || "");
  if (!x) return y;
  if (!y) return x;
  return x < y ? `${x}|${y}` : `${y}|${x}`;
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
  if (payload.initiator) {
    payload.initiator = normalizeFingerprintInput(payload.initiator);
  }
  if (payload.audience) {
    payload.audience = canonicalAudience(payload.audience);
  }
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

/** @param {Uint8Array} bytes */
function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
