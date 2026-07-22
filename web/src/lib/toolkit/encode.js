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
 * Strip PEM armor and return DER bytes.
 * @param {string} pem
 * @returns {Uint8Array}
 */
export function fromPem(pem) {
  const text = String(pem || "");
  const m = text.match(
    /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/
  );
  if (!m) throw new Error("No PEM block found");
  const b64 = m[1].replace(/\s+/g, "");
  return base64ToBytes(b64);
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
