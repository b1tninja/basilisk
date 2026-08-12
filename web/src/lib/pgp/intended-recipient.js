/**
 * Intended Recipient Fingerprint (RFC 9580 §5.2.3.36 / §13.12).
 *
 * ## `checkIntendedRecipient` has no caller, and wiring it here would be a lie
 *
 * The subpacket names who a signer meant a message for. Comparing it against
 * the key that decrypted the message is what detects **surreptitious
 * forwarding**: Mallory takes Alice's message signed to Bob, re-encrypts it to
 * Carol, and Carol reads a good signature from Alice as though Alice wrote to
 * her.
 *
 * The comparison below is correct and tested, and nothing calls it — because
 * **this build has no live path that decrypts a signed message and shows a
 * signature verdict**:
 *
 * - `crypto-worker.js` does verify, and extracts these fingerprints onto each
 *   signature status. Nothing posts `{ type: "decrypt" }` to it. Nothing posts
 *   `encrypt` or `toolkit-run` either; `generate` is the only reachable arm.
 * - The toolkit's live decrypt (`decryptGpgSource` in `engine.js`) passes no
 *   `verificationKeys` at all — it recovers share mnemonics, and has no
 *   signature to attach a verdict to.
 * - `openSignalingEnvelope` verifies, but that is peer signalling sealed to a
 *   pinned audience by construction; the subpacket is not part of it.
 * - `gpg.verify` verifies *cleartext-signed* documents, which are not
 *   encrypted, so there is no re-encryption step to catch.
 *
 * So the check is not missing a call site: the call site does not exist. Adding
 * one inside the unreachable worker arm would make the defence look present
 * while changing nothing a person can reach — which is the exact defect the
 * check itself was found by.
 *
 * ## What must exist first, and what to do then
 *
 * A path that decrypts *and* verifies for a person: the worker's `decrypt` arm
 * gaining a caller, or `gpg.decrypt` gaining `verificationKeys`. The boundary
 * is not the problem — the worker already holds the decrypted private key in
 * the same scope as the extraction, so the comparison belongs right beside it,
 * and its verdict rides on the signature status the UI renders.
 *
 * The three outcomes, decided in advance so the wiring is not blocked on them:
 *
 * - **`absent` — say nothing.** Most messages carry no subpacket. Treating its
 *   absence as a warning would fire on the common case and teach people to
 *   ignore the one that matters. Absence is *no claim made*, not a failed one.
 * - **`match` — say nothing loud.** The expected case; do not badge the normal.
 * - **`mismatch` — change what the signature verdict says.** Do not refuse the
 *   decrypt: the plaintext is already recoverable and refusing would hide the
 *   evidence from the person who needs it. What must not happen is the verdict
 *   reading "Alice signed this to you", because she did not. The signature is
 *   cryptographically good; what is wrong is who it was addressed to, and those
 *   are different sentences that a reader acts on differently.
 *
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
