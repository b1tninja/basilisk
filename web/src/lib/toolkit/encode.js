/**
 * Encoding helpers for the toolkit pipeline.
 * Single place for PEM / Base64 / Base64url / Base32 / hex — kills openssl|tr chains.
 */

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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
 * Decode RFC 4648 Base32 (padding optional; case-insensitive).
 * @param {string} text
 * @returns {Uint8Array}
 */
export function base32ToBytes(text) {
  const clean = String(text || "")
    .replace(/\s+/g, "")
    .replace(/=+$/g, "")
    .toUpperCase();
  if (!clean.length) return new Uint8Array(0);
  if (/[^A-Z2-7]/.test(clean)) throw new Error("Invalid Base32");
  /** @type {number[]} */
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("Invalid Base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/**
 * Decode hex (optionally whitespace-separated) to bytes.
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  const clean = String(hex || "").replace(/\s+/g, "").toLowerCase();
  if (!clean.length) return new Uint8Array(0);
  if (clean.length % 2 !== 0 || /[^0-9a-f]/.test(clean)) {
    throw new Error("Invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * @typedef {{ der: Uint8Array, label: string, which: "public"|"private", format: "spki"|"pkcs8"|"opaque" }} PemBlock
 */

/**
 * Map a PEM BEGIN label to WebCrypto import format + half.
 * @param {string} label
 * @returns {{ which: "public"|"private", format: "spki"|"pkcs8"|"opaque" }}
 */
export function pemMetaFromLabel(label) {
  const L = String(label || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, " ");
  if (
    L === "PUBLIC KEY" ||
    L === "RSA PUBLIC KEY" ||
    L === "EC PUBLIC KEY" ||
    L.endsWith(" PUBLIC KEY")
  ) {
    return { which: "public", format: "spki" };
  }
  if (
    L === "PRIVATE KEY" ||
    L === "RSA PRIVATE KEY" ||
    L === "EC PRIVATE KEY" ||
    L === "ENCRYPTED PRIVATE KEY" ||
    L.endsWith(" PRIVATE KEY")
  ) {
    return { which: "private", format: "pkcs8" };
  }
  return { which: "private", format: "opaque" };
}

/**
 * Parse the first PEM block: DER + label metadata.
 * @param {string} pem
 * @returns {PemBlock}
 */
export function parsePem(pem) {
  const text = String(pem || "");
  const m = text.match(
    /-----BEGIN ([^-]+)-----([\s\S]*?)-----END [^-]+-----/
  );
  if (!m) throw new Error("No PEM block found");
  const label = String(m[1] || "").trim();
  const b64 = m[2].replace(/\s+/g, "");
  const der = base64ToBytes(b64);
  const meta = pemMetaFromLabel(label);
  return { der, label, which: meta.which, format: meta.format };
}

/**
 * Strip PEM armor and return DER bytes.
 * @param {string} pem
 * @returns {Uint8Array}
 */
export function fromPem(pem) {
  return parsePem(pem).der;
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
 * Best-effort buffer wipe: inline `try { u8.fill(0); } catch (_) {}` at the
 * call site — do not re-export a shared zeroBuffer (see memory-safety.js).
 */

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

/**
 * Decode a JWK base64url field to bytes.
 * @param {string} b64url
 * @returns {Uint8Array}
 */
export function jwkFieldToBytes(b64url) {
  return base64ToBytes(String(b64url || ""));
}

/** Named curve OIDs for EC PKCS#8 construction. */
const EC_CURVE_OID = {
  "P-256": [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
  "P-384": [0x2b, 0x81, 0x04, 0x00, 0x22],
  "P-521": [0x2b, 0x81, 0x04, 0x00, 0x23],
};

/**
 * @param {Uint8Array[]} parts
 * @returns {Uint8Array}
 */
function concatBytes(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/**
 * @param {number} tag
 * @param {Uint8Array|number[]} content
 * @returns {Uint8Array}
 */
function derTlv(tag, content) {
  const body = content instanceof Uint8Array ? content : new Uint8Array(content);
  /** @type {number[]} */
  const len = [];
  if (body.length < 0x80) {
    len.push(body.length);
  } else if (body.length < 0x100) {
    len.push(0x81, body.length);
  } else {
    len.push(0x82, (body.length >> 8) & 0xff, body.length & 0xff);
  }
  const out = new Uint8Array(1 + len.length + body.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(body, 1 + len.length);
  return out;
}

/**
 * Build a PKCS#8 PrivateKeyInfo for an EC private scalar (no public key field).
 * WebCrypto derives the public point on import.
 * @param {Uint8Array} scalar
 * @param {"P-256"|"P-384"|"P-521"} curve
 * @returns {Uint8Array}
 */
export function pkcs8FromEcScalar(scalar, curve) {
  const oid = EC_CURVE_OID[curve];
  if (!oid) throw new Error(`Unsupported EC curve for scalar PKCS#8: ${curve}`);
  if (!(scalar instanceof Uint8Array) || !scalar.length) {
    throw new Error("EC scalar must be non-empty bytes");
  }
  // ECPrivateKey ::= SEQUENCE { version INTEGER 1, privateKey OCTET STRING }
  const ecPrivateKey = derTlv(
    0x30,
    concatBytes([derTlv(0x02, [0x01]), derTlv(0x04, scalar)])
  );
  // AlgorithmIdentifier ::= SEQUENCE { ecPublicKey OID, namedCurve OID }
  const algId = derTlv(
    0x30,
    concatBytes([
      derTlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
      derTlv(0x06, oid),
    ])
  );
  // PrivateKeyInfo ::= SEQUENCE { version, algId, privateKey OCTET STRING }
  return derTlv(
    0x30,
    concatBytes([derTlv(0x02, [0x00]), algId, derTlv(0x04, ecPrivateKey)])
  );
}
