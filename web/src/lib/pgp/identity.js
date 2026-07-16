/**
 * Key identity helpers: key IDs, fingerprints, and keyserver search links.
 */

import { escapeHtml, formatFingerprint, searchUrl } from "../utils.js";

/**
 * @param {import("openpgp").KeyID | { toHex?: () => string, bytes?: Uint8Array } | null | undefined} keyID
 * @returns {string}
 */
export function keyIdHex(keyID) {
  if (!keyID) return "";
  try {
    if (typeof keyID.toHex === "function") return String(keyID.toHex()).toUpperCase();
  } catch (_) {
    /* fall through */
  }
  if (keyID.bytes instanceof Uint8Array) {
    return Array.from(keyID.bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
  }
  return String(keyID).toUpperCase().replace(/[^0-9A-F]/g, "");
}

/**
 * @param {Uint8Array | null | undefined} fp
 * @returns {string}
 */
export function fingerprintHex(fp) {
  if (!(fp instanceof Uint8Array) || !fp.length) return "";
  return Array.from(fp)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/**
 * @param {string} hex
 * @returns {boolean}
 */
export function isAnonymousKeyId(hex) {
  return !hex || /^0+$/.test(hex);
}

/**
 * HTML link to search the keyserver for a key ID / fingerprint.
 * @param {string} hex
 * @param {string} [label]
 * @returns {string}
 */
export function keySearchLink(hex, label) {
  if (isAnonymousKeyId(hex)) {
    return `<span class="muted">${escapeHtml(label || "anonymous")}</span>`;
  }
  const q = `0x${hex}`;
  const display = label || formatFingerprint(hex);
  return `<a class="text-link fpr" href="${escapeHtml(searchUrl(q))}" title="Search keyserver">${escapeHtml(display)}</a>`;
}
