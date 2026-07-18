/**
 * Intended Recipient Fingerprint (RFC 9580 §5.2.3.36 / §13.12).
 * @module lib/pgp/intended-recipient
 */

import { fingerprintHex } from "./identity.js";

/** Subpacket type 35 */
export const SUBPACKET_INTENDED_RECIPIENT = 35;

/**
 * Extract intended-recipient fingerprints from a SignaturePacket.
 * @param {import("openpgp").SignaturePacket | null | undefined} pkt
 * @returns {string[]} uppercase hex fingerprints
 */
export function intendedRecipientsFromSigPacket(pkt) {
  if (!pkt) return [];
  /** @type {string[]} */
  const out = [];
  const lists = [
    ...(pkt.unknownSubpackets || []),
    ...(pkt.unhashedSubpackets || []),
  ];
  for (const sp of lists) {
    if (sp?.type !== SUBPACKET_INTENDED_RECIPIENT) continue;
    const body = sp.body;
    if (!(body instanceof Uint8Array) || body.length < 21) continue;
    const fpr = fingerprintHex(body.subarray(1));
    if (fpr) out.push(fpr);
  }
  // Some builds may expose a first-class field
  const direct = pkt.intendedRecipientFingerprint || pkt.intendedRecipients;
  if (direct instanceof Uint8Array) {
    const fpr = fingerprintHex(direct.length > 20 ? direct.subarray(1) : direct);
    if (fpr) out.push(fpr);
  } else if (Array.isArray(direct)) {
    for (const item of direct) {
      if (item instanceof Uint8Array) {
        const fpr = fingerprintHex(item.length > 20 ? item.subarray(1) : item);
        if (fpr) out.push(fpr);
      } else if (typeof item === "string") {
        const fpr = item.toUpperCase().replace(/[^0-9A-F]/g, "");
        if (fpr.length >= 40) out.push(fpr);
      }
    }
  }
  return [...new Set(out)];
}

/**
 * Collect intended recipients from decrypt() signature results.
 * @param {Array<{ signature?: Promise<import("openpgp").Signature> | import("openpgp").Signature }>} signatures
 * @returns {Promise<string[]>}
 */
export async function intendedRecipientsFromDecryptSignatures(signatures) {
  /** @type {string[]} */
  const all = [];
  for (const s of signatures || []) {
    try {
      const sigObj = await s.signature;
      const packets = sigObj?.packets ? [...sigObj.packets] : [];
      for (const pkt of packets) {
        all.push(...intendedRecipientsFromSigPacket(pkt));
      }
    } catch (_) {
      /* ignore */
    }
  }
  return [...new Set(all)];
}

/**
 * Compare IRF list to the decryption key fingerprint.
 * @param {string[]} intended
 * @param {string} decryptFpr
 * @returns {{ status: "ok"|"mismatch"|"absent", message: string }}
 */
export function checkIntendedRecipient(intended, decryptFpr) {
  const fpr = String(decryptFpr || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (!intended.length) {
    return {
      status: "absent",
      message:
        "Signed message has no Intended Recipient Fingerprint subpacket — cannot detect surreptitious forwarding (RFC 9580 §13.12).",
    };
  }
  const match = intended.some(
    (i) => i === fpr || (fpr && (i.endsWith(fpr) || fpr.endsWith(i)))
  );
  if (match) {
    return {
      status: "ok",
      message: "Intended Recipient Fingerprint matches this decryption key.",
    };
  }
  return {
    status: "mismatch",
    message:
      "Intended Recipient Fingerprint does not match this decryption key — possible surreptitious forwarding (RFC 9580 §13.12).",
  };
}
