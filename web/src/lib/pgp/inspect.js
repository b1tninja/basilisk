/**
 * Inspect armored OpenPGP messages without decrypting.
 * @module lib/pgp/inspect
 */

import {
  enums,
  readCleartextMessage,
  readMessage,
  readSignature,
} from "openpgp";
import { fingerprintHex, keyIdHex } from "./identity.js";

/**
 * @param {Iterable} packets
 * @returns {import("./types.js").SigDetail[]}
 */
export function sigDetailsFromPackets(packets) {
  const list = Array.isArray(packets) ? packets : [...(packets || [])];
  return list.map((pkt) => {
    const keyId = keyIdHex(pkt.issuerKeyID);
    const fingerprint = fingerprintHex(pkt.issuerFingerprint);
    const created =
      pkt.created instanceof Date && !Number.isNaN(pkt.created.getTime())
        ? pkt.created
        : null;
    return { keyId, fingerprint, created };
  });
}

/**
 * Parse armored input into a {@link MessageAnalysis} without decrypting.
 * @param {string} armored
 * @returns {Promise<import("./types.js").MessageAnalysis>}
 */
export async function analyzeArmored(armored) {
  const text = String(armored || "").trim();
  if (!text) {
    return {
      type: "empty",
      recipientKeyIDs: [],
      sigDetails: [],
      cleartext: "",
      message: null,
      hasSkesk: false,
      hasPkesk: false,
      armored: "",
    };
  }

  // Encrypted or binary signed message
  try {
    const message = await readMessage({ armoredMessage: text });
    const recipientKeyIDs = (message.getEncryptionKeyIDs?.() || []).map(keyIdHex);
    let hasSkesk = false;
    let hasPkesk = false;
    try {
      for (const p of message.packets || []) {
        const tag = p.constructor?.tag;
        if (tag === 3) hasSkesk = true;
        if (tag === 1) hasPkesk = true;
      }
    } catch (_) {
      /* ignore */
    }
    let sigDetails = [];
    try {
      const sigPkts = message.packets?.filterByTag?.(enums.packet.signature) || [];
      sigDetails = sigDetailsFromPackets(sigPkts);
    } catch (_) {
      /* ignore */
    }
    if (!sigDetails.length && typeof message.getSigningKeyIDs === "function") {
      sigDetails = (message.getSigningKeyIDs() || []).map((id) => ({
        keyId: keyIdHex(id),
        fingerprint: "",
        created: null,
      }));
    }
    const encrypted = recipientKeyIDs.length > 0 || hasSkesk || hasPkesk;
    return {
      type: encrypted ? "encrypted" : "message",
      recipientKeyIDs,
      sigDetails,
      cleartext: "",
      message,
      hasSkesk,
      hasPkesk,
      armored: text,
    };
  } catch (_) {
    /* try cleartext / signature */
  }

  // Clearsigned message
  try {
    const clearMsg = await readCleartextMessage({ cleartextMessage: text });
    let sigDetails = [];
    try {
      const sigPkts = clearMsg.signature?.packets || [];
      sigDetails = sigDetailsFromPackets(sigPkts);
    } catch (_) {
      /* ignore */
    }
    if (!sigDetails.length && typeof clearMsg.getSigningKeyIDs === "function") {
      sigDetails = (clearMsg.getSigningKeyIDs() || []).map((id) => ({
        keyId: keyIdHex(id),
        fingerprint: "",
        created: null,
      }));
    }
    return {
      type: "cleartext",
      recipientKeyIDs: [],
      sigDetails,
      cleartext: clearMsg.getText?.() ?? String(clearMsg.text || ""),
      message: clearMsg,
      hasSkesk: false,
      hasPkesk: false,
      armored: text,
    };
  } catch (_) {
    /* try detached signature */
  }

  // Detached signature
  try {
    const signature = await readSignature({ armoredSignature: text });
    const sigDetails = sigDetailsFromPackets(signature.packets || []);
    return {
      type: "detached",
      recipientKeyIDs: [],
      sigDetails,
      cleartext: "",
      message: signature,
      hasSkesk: false,
      hasPkesk: false,
      armored: text,
    };
  } catch (err) {
    throw new Error(err?.message || "Could not parse as a PGP message or signature.");
  }
}
