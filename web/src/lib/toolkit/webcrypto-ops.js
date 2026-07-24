/**
 * WebCrypto helpers for toolkit ops (digest, sign, verify, aesgcm, hkdf, pbkdf2, ecdh, wrap).
 */

import { textToBytes } from "./encode.js";

/**
 * @param {import("./engine.js").PipelineValue|null|undefined} value
 * @returns {Uint8Array}
 */
export function valueToBytes(value) {
  if (!value) throw new Error("Expected pipeline bytes or text");
  if (value.type === "bytes") return value.data;
  if (value.type === "text") return textToBytes(String(value.data));
  throw new Error(`Expected bytes or text, got ${value.type}`);
}

/**
 * @typedef {object} BoundWebCryptoKey
 * @property {CryptoKey} [privateKey]
 * @property {CryptoKey} [publicKey]
 * @property {CryptoKey} [secretKey]
 * @property {string} [alg]
 */

/**
 * @param {object} bindings
 * @param {"private"|"public"|"secret"|"either"} need
 * @returns {Promise<CryptoKey>}
 */
export async function resolveBoundKey(bindings, need) {
  const raw = bindings?.inputs?.key;
  if (!raw) {
    throw new Error(
      "No WebCrypto key bound — paste a JWK (or run genkey and paste the exported JWK) in the key panel."
    );
  }

  /** @type {BoundWebCryptoKey} */
  let bound = raw;
  if (raw.jwk || typeof raw.jwkText === "string") {
    bound = await importBoundJwk(raw);
  }

  if (need === "private") {
    if (bound.privateKey) return bound.privateKey;
    throw new Error("Bound key has no private key (need private JWK for sign / decrypt / unwrap)");
  }
  if (need === "public") {
    if (bound.publicKey) return bound.publicKey;
    throw new Error("Bound key has no public key (need public JWK for verify / encrypt / ECDH peer)");
  }
  if (need === "secret") {
    if (bound.secretKey) return bound.secretKey;
    throw new Error("Bound key has no secret key (need oct JWK for AES-GCM / HMAC / wrap)");
  }
  // either
  if (bound.secretKey) return bound.secretKey;
  if (bound.privateKey) return bound.privateKey;
  if (bound.publicKey) return bound.publicKey;
  throw new Error("Bound key is empty");
}

/**
 * @param {{ jwk?: JsonWebKey, jwkText?: string, alg?: string }} raw
 * @returns {Promise<BoundWebCryptoKey>}
 */
export async function importBoundJwk(raw) {
  /** @type {JsonWebKey} */
  let jwk;
  if (raw.jwk && typeof raw.jwk === "object") {
    jwk = raw.jwk;
  } else {
    const text = String(raw.jwkText || "").trim();
    if (!text) throw new Error("Empty JWK");
    jwk = JSON.parse(text);
  }
  const kty = String(jwk.kty || "");
  /** @type {BoundWebCryptoKey} */
  const out = { alg: raw.alg };

  if (kty === "oct") {
    const alg = inferOctAlg(jwk, raw.alg);
    const usages = octUsages(alg);
    const clean = { ...jwk };
    delete clean.key_ops;
    delete clean.alg;
    out.secretKey = await crypto.subtle.importKey("jwk", clean, alg, true, usages);
    out.alg = typeof alg === "string" ? alg : alg.name;
    return out;
  }

  if (kty === "OKP" && jwk.crv === "Ed25519") {
    const hasD = !!jwk.d;
    if (hasD) {
      out.privateKey = await crypto.subtle.importKey("jwk", jwk, "Ed25519", true, [
        "sign",
      ]);
      const pub = { ...jwk };
      delete pub.d;
      out.publicKey = await crypto.subtle.importKey("jwk", pub, "Ed25519", true, [
        "verify",
      ]);
    } else {
      out.publicKey = await crypto.subtle.importKey("jwk", jwk, "Ed25519", true, [
        "verify",
      ]);
    }
    out.alg = "ed25519";
    return out;
  }

  if (kty === "OKP" && jwk.crv === "X25519") {
    const hasD = !!jwk.d;
    if (hasD) {
      out.privateKey = await crypto.subtle.importKey("jwk", jwk, "X25519", true, [
        "deriveBits",
        "deriveKey",
      ]);
      const pub = { ...jwk };
      delete pub.d;
      out.publicKey = await crypto.subtle.importKey("jwk", pub, "X25519", true, []);
    } else {
      out.publicKey = await crypto.subtle.importKey("jwk", jwk, "X25519", true, []);
    }
    out.alg = "x25519";
    return out;
  }

  if (kty === "EC") {
    const curve = jwk.crv || "P-256";
    const isEcdh = raw.alg === "ecdh" || String(jwk.key_ops || "").includes("deriveBits");
    const algo = {
      name: isEcdh ? "ECDH" : "ECDSA",
      namedCurve: curve,
    };
    const hasD = !!jwk.d;
    if (hasD) {
      out.privateKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        algo,
        true,
        isEcdh ? ["deriveBits", "deriveKey"] : ["sign"]
      );
      const pub = { ...jwk };
      delete pub.d;
      out.publicKey = await crypto.subtle.importKey(
        "jwk",
        pub,
        algo,
        true,
        isEcdh ? [] : ["verify"]
      );
    } else {
      out.publicKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        algo,
        true,
        isEcdh ? [] : ["verify"]
      );
    }
    out.alg = `ec/${curve.replace("P-", "p").toLowerCase()}`;
    return out;
  }

  if (kty === "RSA") {
    const isOaep = raw.alg === "rsa-oaep" || (jwk.alg || "").includes("OAEP");
    const algo = {
      name: isOaep ? "RSA-OAEP" : "RSA-PSS",
      hash: "SHA-256",
    };
    const hasD = !!jwk.d;
    if (hasD) {
      out.privateKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        algo,
        true,
        isOaep ? ["decrypt"] : ["sign"]
      );
      const pub = {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: jwk.alg,
        ext: true,
        key_ops: isOaep ? ["encrypt"] : ["verify"],
      };
      out.publicKey = await crypto.subtle.importKey(
        "jwk",
        pub,
        algo,
        true,
        isOaep ? ["encrypt"] : ["verify"]
      );
    } else {
      out.publicKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        algo,
        true,
        isOaep ? ["encrypt"] : ["verify"]
      );
    }
    out.alg = isOaep ? "rsa-oaep" : "rsa-pss";
    return out;
  }

  throw new Error(`Unsupported JWK kty=${kty}`);
}

/**
 * @param {JsonWebKey} jwk
 * @param {string} [hint]
 */
function inferOctAlg(jwk, hint) {
  if (hint === "hmac/sha512" || jwk.alg === "HS512") {
    return { name: "HMAC", hash: "SHA-512" };
  }
  if (hint === "hmac/sha256" || jwk.alg === "HS256") {
    return { name: "HMAC", hash: "SHA-256" };
  }
  if (hint === "aes/128" || hint === "aes/256" || jwk.alg === "A256GCM" || jwk.alg === "A128GCM") {
    return { name: "AES-GCM", length: hint === "aes/128" || jwk.alg === "A128GCM" ? 128 : 256 };
  }
  if (hint === "aes-kw" || jwk.alg === "A256KW" || jwk.alg === "A128KW") {
    return { name: "AES-KW", length: jwk.alg === "A128KW" ? 128 : 256 };
  }
  // Default: AES-GCM 256 when k length suggests 32 bytes
  const kLen = jwk.k ? Math.floor((String(jwk.k).length * 3) / 4) : 32;
  if (kLen <= 16) return { name: "AES-GCM", length: 128 };
  return { name: "AES-GCM", length: 256 };
}

/** @param {AlgorithmIdentifier|AesKeyAlgorithm|HmacImportParams} alg */
function octUsages(alg) {
  const name = typeof alg === "string" ? alg : alg.name;
  if (name === "HMAC") return /** @type {KeyUsage[]} */ (["sign", "verify"]);
  if (name === "AES-KW") return /** @type {KeyUsage[]} */ (["wrapKey", "unwrapKey"]);
  return /** @type {KeyUsage[]} */ (["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function subtleSign(key, data) {
  const algo = signAlgorithmForKey(key);
  const sig = await crypto.subtle.sign(algo, key, data);
  return new Uint8Array(sig);
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} signature
 * @param {Uint8Array} data
 */
export async function subtleVerify(key, signature, data) {
  const algo = signAlgorithmForKey(key);
  return crypto.subtle.verify(algo, key, signature, data);
}

/** @param {CryptoKey} key */
function signAlgorithmForKey(key) {
  const name = key.algorithm.name;
  if (name === "ECDSA") {
    const curve = /** @type {EcKeyAlgorithm} */ (key.algorithm).namedCurve;
    const hash =
      curve === "P-384" ? "SHA-384" : curve === "P-521" ? "SHA-512" : "SHA-256";
    return { name: "ECDSA", hash };
  }
  if (name === "RSA-PSS") {
    return { name: "RSA-PSS", saltLength: 32 };
  }
  if (name === "Ed25519" || name === "HMAC") return name;
  throw new Error(`sign/verify does not support algorithm ${name}`);
}

/**
 * AES-GCM encrypt; returns IV(12) || ciphertext||tag
 * @param {CryptoKey} key
 * @param {Uint8Array} plain
 * @param {Uint8Array} [aad]
 */
export async function aesGcmEncrypt(key, plain, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      plain
    )
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} packed  IV(12) || ciphertext||tag
 * @param {Uint8Array} [aad]
 */
export async function aesGcmDecrypt(key, packed, aad) {
  if (packed.length < 13) throw new Error("aesgcm ciphertext too short");
  const iv = packed.subarray(0, 12);
  const ct = packed.subarray(12);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      ct
    )
  );
}

/**
 * @param {Uint8Array} ikm
 * @param {{ salt?: Uint8Array, info?: Uint8Array, length: number, hash?: string }} opts
 */
export async function hkdfDerive(ikm, opts) {
  const hash = opts.hash || "SHA-256";
  const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash,
      salt: opts.salt || new Uint8Array(),
      info: opts.info || new Uint8Array(),
    },
    baseKey,
    opts.length * 8
  );
  return new Uint8Array(bits);
}

/**
 * @param {Uint8Array} password
 * @param {{ salt: Uint8Array, iterations: number, length: number, hash?: string }} opts
 */
export async function pbkdf2Derive(password, opts) {
  const hash = opts.hash || "SHA-256";
  const baseKey = await crypto.subtle.importKey("raw", password, "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash,
      salt: opts.salt,
      iterations: opts.iterations,
    },
    baseKey,
    opts.length * 8
  );
  return new Uint8Array(bits);
}

/**
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} publicKey
 * @param {number} [bitLength]
 */
export async function ecdhSharedBits(privateKey, publicKey, bitLength = 256) {
  const bits = await crypto.subtle.deriveBits(
    { name: privateKey.algorithm.name, public: publicKey },
    privateKey,
    bitLength
  );
  return new Uint8Array(bits);
}

/**
 * Wrap a raw key with AES-KW (RFC 3394). Returns wrapped bytes.
 * @param {CryptoKey} wrappingKey  AES-KW
 * @param {CryptoKey} keyToWrap
 */
export async function aesKwWrap(wrappingKey, keyToWrap) {
  const wrapped = await crypto.subtle.wrapKey("raw", keyToWrap, wrappingKey, "AES-KW");
  return new Uint8Array(wrapped);
}

/**
 * @param {CryptoKey} wrappingKey
 * @param {Uint8Array} wrapped
 * @param {AlgorithmIdentifier|AesKeyAlgorithm|HmacImportParams} importAlg
 * @param {KeyUsage[]} usages
 */
export async function aesKwUnwrap(wrappingKey, wrapped, importAlg, usages) {
  return crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    wrappingKey,
    "AES-KW",
    importAlg,
    true,
    usages
  );
}
