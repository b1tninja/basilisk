/**
 * Encoding helpers for the toolkit pipeline.
 * Single place for PEM / Base64 / Base64url / hex — kills openssl|tr chains.
 */

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/**
 * URL-safe Base64 without padding.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * @param {string} b64
 * @returns {Uint8Array}
 */
export function base64ToBytes(b64) {
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Wrap DER bytes as PEM.
 * @param {Uint8Array} der
 * @param {string} label  e.g. "PRIVATE KEY"
 * @returns {string}
 */
export function toPem(der, label = "PRIVATE KEY") {
  const b64 = bytesToBase64(der);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/**
 * Infer PEM label from export format.
 * @param {string} format  pkcs8|spki|…
 * @param {string} which  private|public
 * @returns {string}
 */
export function pemLabelFor(format, which = "private") {
  if (format === "spki" || which === "public") return "PUBLIC KEY";
  return "PRIVATE KEY";
}

/**
 * Best-effort zero a buffer.
 * @param {ArrayBuffer|Uint8Array|null|undefined} buf
 */
export function zeroBuffer(buf) {
  if (!buf) return;
  try {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    u8.fill(0);
  } catch (_) {
    /* ignore */
  }
}

/**
 * UTF-8 encode a string to bytes.
 * @param {string} text
 * @returns {Uint8Array}
 */
export function textToBytes(text) {
  return new TextEncoder().encode(String(text || ""));
}

/**
 * UTF-8 decode bytes to string.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToText(bytes) {
  return new TextDecoder().decode(bytes);
}
