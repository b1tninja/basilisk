/**
 * Recipient key capability detection (RFC 9580 SEIPDv2 feature bit).
 * Matches OpenPGP.js getPreferredCipherSuite logic: every recipient must
 * advertise seipdv2 for public-key AEAD encryption to apply.
 */

import { enums } from "openpgp";

/**
 * Whether a public key advertises SEIPD v2 / AEAD support in its primary
 * self-signature features bitfield.
 * @param {import("openpgp").Key | null | undefined} key
 * @param {Date} [date]
 * @returns {Promise<boolean>}
 */
export async function supportsSeipdV2(key, date = new Date()) {
  if (!key) return false;
  try {
    const selfSig = await key.getPrimarySelfSignature(date);
    const features = selfSig?.features;
    if (!features || !features.length) return false;
    return !!(features[0] & enums.features.seipdv2);
  } catch (_) {
    return false;
  }
}

/**
 * Summarize how many valid recipients support modern (SEIPDv2) encryption.
 * @param {Array<{ pgpKey?: import("openpgp").Key | null, valid?: boolean }>} recipients
 * @returns {Promise<{ total: number, modern: number, legacy: number }>}
 */
export async function summarizeRecipientCapabilities(recipients) {
  const list = (recipients || []).filter((r) => r?.valid && r.pgpKey);
  let modern = 0;
  for (const r of list) {
    if (await supportsSeipdV2(r.pgpKey)) modern += 1;
  }
  const total = list.length;
  return { total, modern, legacy: total - modern };
}
