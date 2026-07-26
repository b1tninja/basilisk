/**
 * WebCrypto helpers for toolkit ops (digest, sign, verify, aes-gcm, hkdf, pbkdf2, ecdh, wrap).
 */

import { textToBytes } from "./encode.js";

/**
 * Normalize recipe hash token → SubtleCrypto hash name.
 * @param {string|undefined|null} h
 * @returns {"SHA-1"|"SHA-256"|"SHA-384"|"SHA-512"}
 */
export function normalizeHashName(h) {
  const s = String(h || "sha-256")
    .toLowerCase()
    .replace(/_/g, "-");
  if (s === "sha-1" || s === "sha1") return "SHA-1";
  if (s === "sha-384" || s === "sha384") return "SHA-384";
  if (s === "sha-512" || s === "sha512") return "SHA-512";
  return "SHA-256";
}

/**
 * @param {string} alg  aes/128 | aes/192 | aes/256
 * @returns {128|192|256}
 */
export function aesLengthFromAlg(alg) {
  const a = String(alg || "").toLowerCase();
  if (a === "aes/128") return 128;
  if (a === "aes/192") return 192;
  return 256;
}

/**
 * @param {string} alg  hmac/sha256 | hmac/sha384 | hmac/sha512
 * @returns {"SHA-256"|"SHA-384"|"SHA-512"}
 */
export function hmacHashFromAlg(alg) {
  const a = String(alg || "").toLowerCase();
  if (a === "hmac/sha512") return "SHA-512";
  if (a === "hmac/sha384") return "SHA-384";
  return "SHA-256";
}

/** @param {"SHA-256"|"SHA-384"|"SHA-512"} hash */
export function hmacLengthBits(hash) {
  if (hash === "SHA-512") return 512;
  if (hash === "SHA-384") return 384;
  return 256;
}

/**
 * @param {unknown} n
 * @returns {96|104|112|120|128}
 */
export function parseGcmTagLength(n) {
  const t = Number(n);
  if (!t || t === 128) return 128;
  if (t === 96 || t === 104 || t === 112 || t === 120) return /** @type {96|104|112|120} */ (t);
  throw new Error(`aes-gcm tagLength must be 96|104|112|120|128, got ${n}`);
}

/**
 * @param {unknown} n
 * @returns {number}
 */
export function parseCtrLength(n) {
  const t = Number(n);
  if (!t) return 64;
  if (!Number.isInteger(t) || t < 1 || t > 128) {
    throw new Error(`aes-ctr length must be an integer 1–128, got ${n}`);
  }
  return t;
}

/**
 * Optional OAEP label → bytes (undefined when empty).
 * @param {unknown} label
 * @returns {Uint8Array|undefined}
 */
export function oaepLabelBytes(label) {
  const s = String(label ?? "");
  if (!s) return undefined;
  return textToBytes(s);
}

/**
 * @param {unknown} label
 * @returns {RsaOaepParams}
 */
export function rsaOaepParams(label) {
  /** @type {RsaOaepParams} */
  const params = { name: "RSA-OAEP" };
  const lab = oaepLabelBytes(label);
  if (lab) params.label = lab;
  return params;
}

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

  return pickBoundCryptoKey(bound, need);
}

/**
 * @param {BoundWebCryptoKey} bound
 * @param {"private"|"public"|"secret"|"either"} need
 * @returns {CryptoKey}
 */
function pickBoundCryptoKey(bound, need) {
  if (need === "private") {
    if (bound.privateKey) return bound.privateKey;
    throw new Error("Bound key has no private key (need private JWK for sign / decrypt / unwrap)");
  }
  if (need === "public") {
    if (bound.publicKey) return bound.publicKey;
    // HMAC verifies with the same oct key (stored as secretKey or privateKey).
    if (bound.secretKey?.algorithm?.name === "HMAC") return bound.secretKey;
    if (bound.privateKey?.algorithm?.name === "HMAC") return bound.privateKey;
    throw new Error("Bound key has no public key (need public JWK for verify / encrypt / ECDH peer)");
  }
  if (need === "secret") {
    if (bound.secretKey) return bound.secretKey;
    // Symmetric AES often lives on privateKey after genkey aes/*
    if (bound.privateKey) {
      const n = bound.privateKey.algorithm?.name || "";
      if (n.startsWith("AES") || n === "HMAC") return bound.privateKey;
    }
    throw new Error("Bound key has no secret key (need oct JWK for AES-GCM / HMAC / wrap)");
  }
  if (bound.secretKey) return bound.secretKey;
  if (bound.privateKey) return bound.privateKey;
  if (bound.publicKey) return bound.publicKey;
  throw new Error("Bound key is empty");
}

/**
 * Turn a live pipeline slot value into a CryptoKey.
 * @param {import("./engine.js").PipelineValue} value
 * @param {"private"|"public"|"secret"|"either"} need
 * @param {string} [algHint]
 * @returns {Promise<CryptoKey>}
 */
export async function pipelineValueToCryptoKey(value, need, algHint) {
  if (!value) throw new Error("Empty slot value");
  if (value.type === "keypair") {
    /** @type {BoundWebCryptoKey} */
    const bound = {
      privateKey: value.data?.privateKey,
      publicKey: value.data?.publicKey,
      secretKey: value.data?.secretKey,
      alg: value.meta?.alg || algHint,
    };
    return pickBoundCryptoKey(bound, need);
  }
  if (value.type === "text") {
    const bound = await importBoundJwk({
      jwkText: String(value.data),
      alg: algHint || value.meta?.alg,
    });
    return pickBoundCryptoKey(bound, need);
  }
  if (value.type === "bytes") {
    const raw = value.data;
    if (!(raw instanceof Uint8Array)) {
      throw new Error("Slot bytes are not a Uint8Array");
    }
    const bits = raw.length * 8;
    if (need === "secret" || need === "either") {
      if (bits === 128 || bits === 256) {
        return crypto.subtle.importKey(
          "raw",
          raw,
          { name: "AES-GCM", length: bits },
          true,
          ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        );
      }
      if (bits === 256 || bits === 512) {
        // Prefer AES when 256; HMAC-SHA256 also 256 — use alg hint
        const hint = String(algHint || value.meta?.alg || "");
        if (hint.startsWith("hmac")) {
          return crypto.subtle.importKey(
            "raw",
            raw,
            {
              name: "HMAC",
              hash: hint.includes("512") ? "SHA-512" : "SHA-256",
            },
            true,
            ["sign", "verify"]
          );
        }
        if (bits === 256) {
          return crypto.subtle.importKey(
            "raw",
            raw,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
          );
        }
      }
    }
    throw new Error(
      `Cannot import ${raw.length}B slot as ${need} CryptoKey — export jwk or use a keypair slot`
    );
  }
  throw new Error(`Slot type ${value.type} cannot supply a CryptoKey`);
}

/**
 * Resolve `key=@slot` (etc.) via bindings.resolveSlot, or null if unset.
 * @param {object} bindings
 * @param {string|undefined|null} ref
 * @param {"private"|"public"|"secret"|"either"} need
 * @param {string} [algHint]
 * @returns {Promise<CryptoKey|null>}
 */
export async function resolveSlotKey(bindings, ref, need, algHint) {
  const r = String(ref || "").trim();
  if (!r) return null;
  const resolve = bindings?.resolveSlot;
  if (typeof resolve !== "function") {
    throw new Error(`Slot ${r}: runtime slot resolver missing`);
  }
  const value = resolve(r);
  return pipelineValueToCryptoKey(value, need, algHint);
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
      const privJwk = { ...jwk };
      delete privJwk.key_ops;
      out.privateKey = await crypto.subtle.importKey(
        "jwk",
        privJwk,
        "Ed25519",
        true,
        ["sign"]
      );
      const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, ext: true };
      out.publicKey = await crypto.subtle.importKey("jwk", pub, "Ed25519", true, [
        "verify",
      ]);
    } else {
      const pubJwk = { ...jwk };
      delete pubJwk.key_ops;
      out.publicKey = await crypto.subtle.importKey(
        "jwk",
        pubJwk,
        "Ed25519",
        true,
        ["verify"]
      );
    }
    out.alg = "ed25519";
    return out;
  }

  if (kty === "OKP" && jwk.crv === "X25519") {
    const hasD = !!jwk.d;
    if (hasD) {
      const privJwk = { ...jwk };
      delete privJwk.key_ops;
      out.privateKey = await crypto.subtle.importKey(
        "jwk",
        privJwk,
        "X25519",
        true,
        ["deriveBits", "deriveKey"]
      );
      const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, ext: true };
      out.publicKey = await crypto.subtle.importKey("jwk", pub, "X25519", true, []);
    } else {
      const pubJwk = { ...jwk };
      delete pubJwk.key_ops;
      out.publicKey = await crypto.subtle.importKey("jwk", pubJwk, "X25519", true, []);
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
    const jwkAlg = String(jwk.alg || "");
    const isOaep =
      raw.alg === "rsa-oaep" ||
      jwkAlg.includes("OAEP") ||
      String(raw.padding || "").toLowerCase() === "oaep";
    const isPkcs1 =
      !isOaep &&
      (raw.alg === "rsassa-pkcs1" ||
        String(raw.padding || "").toLowerCase() === "pkcs1" ||
        /^RS(256|384|512)$/i.test(jwkAlg));
    const hash =
      /512/i.test(jwkAlg) ? "SHA-512" : /384/i.test(jwkAlg) ? "SHA-384" : "SHA-256";
    const algo = {
      name: isOaep
        ? "RSA-OAEP"
        : isPkcs1
          ? "RSASSA-PKCS1-v1_5"
          : "RSA-PSS",
      hash,
    };
    const hasD = !!jwk.d;
    if (hasD) {
      out.privateKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        algo,
        true,
        isOaep ? ["decrypt", "unwrapKey"] : ["sign"]
      );
      const pub = {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: jwk.alg,
        ext: true,
        key_ops: isOaep ? ["encrypt", "wrapKey"] : ["verify"],
      };
      out.publicKey = await crypto.subtle.importKey(
        "jwk",
        pub,
        algo,
        true,
        isOaep ? ["encrypt", "wrapKey"] : ["verify"]
      );
    } else {
      out.publicKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        algo,
        true,
        isOaep ? ["encrypt", "wrapKey"] : ["verify"]
      );
    }
    out.alg = isOaep ? "rsa-oaep" : isPkcs1 ? "rsassa-pkcs1-v1_5" : "rsa-pss";
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
  if (hint === "hmac/sha384" || jwk.alg === "HS384") {
    return { name: "HMAC", hash: "SHA-384" };
  }
  if (hint === "hmac/sha256" || jwk.alg === "HS256") {
    return { name: "HMAC", hash: "SHA-256" };
  }
  if (
    hint === "aes/128" ||
    hint === "aes/192" ||
    hint === "aes/256" ||
    jwk.alg === "A256GCM" ||
    jwk.alg === "A192GCM" ||
    jwk.alg === "A128GCM"
  ) {
    const length =
      hint === "aes/128" || jwk.alg === "A128GCM"
        ? 128
        : hint === "aes/192" || jwk.alg === "A192GCM"
          ? 192
          : 256;
    return { name: "AES-GCM", length };
  }
  if (hint === "aes-kw" || jwk.alg === "A256KW" || jwk.alg === "A128KW") {
    return { name: "AES-KW", length: jwk.alg === "A128KW" ? 128 : 256 };
  }
  // Default: AES-GCM sized from k length
  const kLen = jwk.k ? Math.floor((String(jwk.k).length * 3) / 4) : 32;
  if (kLen <= 16) return { name: "AES-GCM", length: 128 };
  if (kLen <= 24) return { name: "AES-GCM", length: 192 };
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
 * @param {{ saltLength?: number, hash?: string }} [opts]
 * @returns {Promise<Uint8Array>}
 */
export async function subtleSign(key, data, opts = {}) {
  const algo = signAlgorithmForKey(key, opts);
  const sig = await crypto.subtle.sign(algo, key, data);
  return new Uint8Array(sig);
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} signature
 * @param {Uint8Array} data
 * @param {{ saltLength?: number, hash?: string }} [opts]
 */
export async function subtleVerify(key, signature, data, opts = {}) {
  const algo = signAlgorithmForKey(key, opts);
  return crypto.subtle.verify(algo, key, signature, data);
}

/**
 * @param {CryptoKey} key
 * @param {{ saltLength?: number, hash?: string }} [opts]
 */
function signAlgorithmForKey(key, opts = {}) {
  const name = key.algorithm.name;
  if (name === "ECDSA") {
    const curve = /** @type {EcKeyAlgorithm} */ (key.algorithm).namedCurve;
    const defaultHash =
      curve === "P-384" ? "SHA-384" : curve === "P-521" ? "SHA-512" : "SHA-256";
    const hash = opts.hash ? normalizeHashName(opts.hash) : defaultHash;
    return { name: "ECDSA", hash };
  }
  if (name === "RSA-PSS") {
    const saltLength =
      Number(opts.saltLength) > 0 ? Number(opts.saltLength) : 32;
    return { name: "RSA-PSS", saltLength };
  }
  if (name === "RSASSA-PKCS1-v1_5") {
    return "RSASSA-PKCS1-v1_5";
  }
  if (name === "Ed25519" || name === "HMAC") return name;
  throw new Error(`sign/verify does not support algorithm ${name}`);
}

/**
 * Default ECDH deriveBits length from a private key algorithm.
 * @param {CryptoKey} privateKey
 * @returns {number}
 */
export function ecdhDefaultBits(privateKey) {
  const name = privateKey.algorithm?.name || "";
  if (name === "X25519") return 256;
  const curve = /** @type {EcKeyAlgorithm} */ (privateKey.algorithm).namedCurve;
  if (curve === "P-384") return 384;
  if (curve === "P-521") return 528;
  return 256;
}

/**
 * ECDH/X25519 deriveBits or deriveKey (when as≠bytes).
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} publicKey
 * @param {{ bits?: number, as?: string }} [opts]
 * @returns {Promise<Uint8Array|{ type: "keypair", data: object, meta: object }>}
 */
export async function ecdhDerive(privateKey, publicKey, opts = {}) {
  const as = String(opts.as || "bytes");
  const target = deriveAsTarget(as);
  const bits =
    Number(opts.bits) > 0 ? Number(opts.bits) : ecdhDefaultBits(privateKey);
  const params = {
    name: privateKey.algorithm.name,
    public: publicKey,
  };
  if (!target) {
    const shared = await crypto.subtle.deriveBits(params, privateKey, bits);
    return new Uint8Array(shared);
  }
  const key = await crypto.subtle.deriveKey(
    params,
    privateKey,
    target.derived,
    true,
    target.usages
  );
  return {
    type: "keypair",
    data: { privateKey: key, publicKey: null, secretKey: key },
    meta: {
      alg: target.alg,
      algorithm:
        typeof target.derived === "string" ? target.derived : target.derived.name,
      symmetric: true,
      sensitive: true,
    },
  };
}

/**
 * RSA-OAEP wrapKey of an extractable CEK.
 * @param {CryptoKey} wrappingKey  RSA-OAEP public
 * @param {CryptoKey} keyToWrap
 * @param {unknown} [label]
 */
export async function rsaOaepWrap(wrappingKey, keyToWrap, label) {
  if (wrappingKey.algorithm?.name !== "RSA-OAEP") {
    throw new Error(
      `wrap mode=rsa-oaep requires an RSA-OAEP public key, got ${wrappingKey.algorithm?.name || "unknown"}`
    );
  }
  const wrapped = await crypto.subtle.wrapKey(
    "raw",
    keyToWrap,
    wrappingKey,
    rsaOaepParams(label)
  );
  return new Uint8Array(wrapped);
}

/**
 * @param {CryptoKey} wrappingKey  RSA-OAEP private
 * @param {Uint8Array} wrapped
 * @param {AlgorithmIdentifier|AesKeyAlgorithm|HmacImportParams} importAlg
 * @param {KeyUsage[]} usages
 * @param {unknown} [label]
 */
export async function rsaOaepUnwrap(wrappingKey, wrapped, importAlg, usages, label) {
  if (wrappingKey.algorithm?.name !== "RSA-OAEP") {
    throw new Error(
      `unwrap mode=rsa-oaep requires an RSA-OAEP private key, got ${wrappingKey.algorithm?.name || "unknown"}`
    );
  }
  return crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    wrappingKey,
    rsaOaepParams(label),
    importAlg,
    true,
    usages
  );
}

/**
 * Re-import an AES key under a target algorithm (AES-GCM / AES-CBC / AES-CTR).
 * @param {CryptoKey} key
 * @param {"AES-GCM"|"AES-CBC"|"AES-CTR"} name
 * @returns {Promise<CryptoKey>}
 */
export async function ensureAesAlgorithm(key, name) {
  if (key.algorithm?.name === name) return key;
  const raw = await crypto.subtle.exportKey("raw", key);
  const length = raw.byteLength * 8;
  if (length !== 128 && length !== 192 && length !== 256) {
    throw new Error(`AES key must be 128, 192, or 256 bits, got ${length}`);
  }
  try {
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name, length },
      true,
      ["encrypt", "decrypt"]
    );
  } finally {
    try {
      new Uint8Array(raw).fill(0);
    } catch (_) {
      /* wipe */
    }
  }
}

/**
 * Re-import an AES key for wrapKey/unwrapKey under AES-GCM / CBC / CTR / KW.
 * @param {CryptoKey} key
 * @param {"AES-GCM"|"AES-CBC"|"AES-CTR"|"AES-KW"} name
 * @returns {Promise<CryptoKey>}
 */
export async function ensureAesWrapKey(key, name) {
  if (
    key.algorithm?.name === name &&
    key.usages.includes("wrapKey") &&
    key.usages.includes("unwrapKey")
  ) {
    return key;
  }
  const raw = await crypto.subtle.exportKey("raw", key);
  const length = raw.byteLength * 8;
  if (length !== 128 && length !== 192 && length !== 256) {
    throw new Error(`AES wrap key must be 128, 192, or 256 bits, got ${length}`);
  }
  try {
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name, length },
      false,
      ["wrapKey", "unwrapKey"]
    );
  } finally {
    try {
      new Uint8Array(raw).fill(0);
    } catch (_) {
      /* wipe */
    }
  }
}

/**
 * Pack IV/counter with wrapped key bytes for content-mode AES wrap.
 * @param {"aes-gcm"|"aes-cbc"|"aes-ctr"} mode
 * @param {CryptoKey} wrappingKey
 * @param {CryptoKey} keyToWrap
 * @param {{ tagLength?: number, length?: number }} [opts]
 * @returns {Promise<Uint8Array>}
 */
export async function aesContentWrap(mode, wrappingKey, keyToWrap, opts = {}) {
  const m = String(mode || "").toLowerCase();
  const algName =
    m === "aes-gcm" ? "AES-GCM" : m === "aes-cbc" ? "AES-CBC" : m === "aes-ctr" ? "AES-CTR" : "";
  if (!algName) throw new Error(`Unsupported AES wrap mode=${mode}`);
  const kw = await ensureAesWrapKey(wrappingKey, algName);
  const ivLen = m === "aes-gcm" ? 12 : 16;
  const iv = crypto.getRandomValues(new Uint8Array(ivLen));
  /** @type {AesGcmParams|AesCbcParams|AesCtrParams} */
  let algorithm;
  if (m === "aes-gcm") {
    const tagLength = parseGcmTagLength(opts.tagLength);
    algorithm = { name: "AES-GCM", iv, tagLength };
  } else if (m === "aes-cbc") {
    algorithm = { name: "AES-CBC", iv };
  } else {
    algorithm = {
      name: "AES-CTR",
      counter: iv,
      length: parseCtrLength(opts.length),
    };
  }
  const wrapped = new Uint8Array(
    await crypto.subtle.wrapKey("raw", keyToWrap, kw, algorithm)
  );
  const out = new Uint8Array(iv.length + wrapped.length);
  out.set(iv, 0);
  out.set(wrapped, iv.length);
  return out;
}

/**
 * @param {"aes-gcm"|"aes-cbc"|"aes-ctr"} mode
 * @param {CryptoKey} wrappingKey
 * @param {Uint8Array} packed
 * @param {AlgorithmIdentifier|AesKeyAlgorithm|HmacImportParams} importAlg
 * @param {KeyUsage[]} usages
 * @param {{ tagLength?: number, length?: number }} [opts]
 */
export async function aesContentUnwrap(
  mode,
  wrappingKey,
  packed,
  importAlg,
  usages,
  opts = {}
) {
  const m = String(mode || "").toLowerCase();
  const algName =
    m === "aes-gcm" ? "AES-GCM" : m === "aes-cbc" ? "AES-CBC" : m === "aes-ctr" ? "AES-CTR" : "";
  if (!algName) throw new Error(`Unsupported AES unwrap mode=${mode}`);
  const ivLen = m === "aes-gcm" ? 12 : 16;
  if (packed.length <= ivLen) {
    throw new Error(`${m} wrapped key too short`);
  }
  const iv = packed.subarray(0, ivLen);
  const wrapped = packed.subarray(ivLen);
  const kw = await ensureAesWrapKey(wrappingKey, algName);
  /** @type {AesGcmParams|AesCbcParams|AesCtrParams} */
  let algorithm;
  if (m === "aes-gcm") {
    const tagLength = parseGcmTagLength(opts.tagLength);
    algorithm = { name: "AES-GCM", iv, tagLength };
  } else if (m === "aes-cbc") {
    algorithm = { name: "AES-CBC", iv };
  } else {
    algorithm = {
      name: "AES-CTR",
      counter: iv,
      length: parseCtrLength(opts.length),
    };
  }
  return crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    kw,
    algorithm,
    importAlg,
    true,
    usages
  );
}

/**
 * AES-GCM encrypt; returns IV(12) || ciphertext||tag
 * @param {CryptoKey} key
 * @param {Uint8Array} plain
 * @param {Uint8Array} [aad]
 * @param {number} [tagLength]
 */
export async function aesGcmEncrypt(key, plain, aad, tagLength) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const tag = parseGcmTagLength(tagLength);
  /** @type {AesGcmParams} */
  const params = { name: "AES-GCM", iv, tagLength: tag };
  if (aad) params.additionalData = aad;
  const ct = new Uint8Array(await crypto.subtle.encrypt(params, key, plain));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} packed  IV(12) || ciphertext||tag
 * @param {Uint8Array} [aad]
 * @param {number} [tagLength]
 */
export async function aesGcmDecrypt(key, packed, aad, tagLength) {
  if (packed.length < 13) throw new Error("aes-gcm ciphertext too short");
  const iv = packed.subarray(0, 12);
  const ct = packed.subarray(12);
  const tag = parseGcmTagLength(tagLength);
  /** @type {AesGcmParams} */
  const params = { name: "AES-GCM", iv, tagLength: tag };
  if (aad) params.additionalData = aad;
  return new Uint8Array(await crypto.subtle.decrypt(params, key, ct));
}

/**
 * AES-CBC encrypt; returns IV(16) || ciphertext
 * @param {CryptoKey} key
 * @param {Uint8Array} plain
 */
export async function aesCbcEncrypt(key, plain) {
  const aes = await ensureAesAlgorithm(key, "AES-CBC");
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aes, plain)
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} packed  IV(16) || ciphertext
 */
export async function aesCbcDecrypt(key, packed) {
  if (packed.length < 17) throw new Error("aes-cbc ciphertext too short");
  const aes = await ensureAesAlgorithm(key, "AES-CBC");
  const iv = packed.subarray(0, 16);
  const ct = packed.subarray(16);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aes, ct)
  );
}

/**
 * AES-CTR encrypt; returns IV(16) || ciphertext (IV is the 128-bit counter block).
 * @param {CryptoKey} key
 * @param {Uint8Array} plain
 * @param {number} [counterLength]  AesCtrParams.length (default 64)
 */
export async function aesCtrEncrypt(key, plain, counterLength) {
  const aes = await ensureAesAlgorithm(key, "AES-CTR");
  const counter = crypto.getRandomValues(new Uint8Array(16));
  const length = parseCtrLength(counterLength);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-CTR", counter, length },
      aes,
      plain
    )
  );
  const out = new Uint8Array(counter.length + ct.length);
  out.set(counter, 0);
  out.set(ct, counter.length);
  return out;
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} packed  IV(16) || ciphertext
 * @param {number} [counterLength]
 */
export async function aesCtrDecrypt(key, packed, counterLength) {
  if (packed.length < 17) throw new Error("aes-ctr ciphertext too short");
  const aes = await ensureAesAlgorithm(key, "AES-CTR");
  const counter = packed.subarray(0, 16);
  const ct = packed.subarray(16);
  const length = parseCtrLength(counterLength);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-CTR", counter, length },
      aes,
      ct
    )
  );
}

/**
 * @param {string} as  bytes | aes/128|192|256 | aes-kw/128|256 | hmac/sha256|384|512
 * @returns {{ derived: AlgorithmIdentifier|AesDerivedKeyParams|HmacImportParams, usages: KeyUsage[], alg: string, lengthBits: number }|null}
 */
export function deriveAsTarget(as) {
  const t = String(as || "bytes").toLowerCase();
  if (t === "bytes" || !t) return null;
  if (t === "aes/128" || t === "aes/192" || t === "aes/256") {
    const length = aesLengthFromAlg(t);
    return {
      derived: { name: "AES-GCM", length },
      usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
      alg: t,
      lengthBits: length,
    };
  }
  if (t === "aes-kw/128") {
    return {
      derived: { name: "AES-KW", length: 128 },
      usages: ["wrapKey", "unwrapKey"],
      alg: "aes-kw/128",
      lengthBits: 128,
    };
  }
  if (t === "aes-kw/256") {
    return {
      derived: { name: "AES-KW", length: 256 },
      usages: ["wrapKey", "unwrapKey"],
      alg: "aes-kw/256",
      lengthBits: 256,
    };
  }
  if (t === "hmac/sha256" || t === "hmac/sha384" || t === "hmac/sha512") {
    const hash = hmacHashFromAlg(t);
    const lengthBits = hmacLengthBits(hash);
    return {
      derived: { name: "HMAC", hash, length: lengthBits },
      usages: ["sign", "verify"],
      alg: t,
      lengthBits,
    };
  }
  throw new Error(`Unsupported derive as=${as}`);
}

/**
 * @param {Uint8Array} ikm
 * @param {{ salt?: Uint8Array, info?: Uint8Array, length: number, hash?: string, as?: string }} opts
 * @returns {Promise<Uint8Array|{ type: "keypair", data: object, meta: object }>}
 */
export async function hkdfDerive(ikm, opts) {
  const hash = opts.hash || "SHA-256";
  const target = deriveAsTarget(opts.as);
  const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, [
    target ? "deriveKey" : "deriveBits",
  ]);
  const params = {
    name: "HKDF",
    hash,
    salt: opts.salt || new Uint8Array(),
    info: opts.info || new Uint8Array(),
  };
  if (!target) {
    const bits = await crypto.subtle.deriveBits(params, baseKey, opts.length * 8);
    return new Uint8Array(bits);
  }
  const key = await crypto.subtle.deriveKey(
    params,
    baseKey,
    target.derived,
    true,
    target.usages
  );
  return {
    type: "keypair",
    data: { privateKey: key, publicKey: null, secretKey: key },
    meta: {
      alg: target.alg,
      algorithm: typeof target.derived === "string" ? target.derived : target.derived.name,
      symmetric: true,
      sensitive: true,
    },
  };
}

/**
 * @param {Uint8Array} password
 * @param {{ salt: Uint8Array, iterations: number, length: number, hash?: string, as?: string }} opts
 * @returns {Promise<Uint8Array|{ type: "keypair", data: object, meta: object }>}
 */
export async function pbkdf2Derive(password, opts) {
  const hash = opts.hash || "SHA-256";
  const target = deriveAsTarget(opts.as);
  const baseKey = await crypto.subtle.importKey("raw", password, "PBKDF2", false, [
    target ? "deriveKey" : "deriveBits",
  ]);
  const params = {
    name: "PBKDF2",
    hash,
    salt: opts.salt,
    iterations: opts.iterations,
  };
  if (!target) {
    const bits = await crypto.subtle.deriveBits(params, baseKey, opts.length * 8);
    return new Uint8Array(bits);
  }
  const key = await crypto.subtle.deriveKey(
    params,
    baseKey,
    target.derived,
    true,
    target.usages
  );
  return {
    type: "keypair",
    data: { privateKey: key, publicKey: null, secretKey: key },
    meta: {
      alg: target.alg,
      algorithm: typeof target.derived === "string" ? target.derived : target.derived.name,
      symmetric: true,
      sensitive: true,
    },
  };
}

/**
 * Re-import an oct key for AES-KW wrapKey (AES-GCM or HMAC).
 * @param {CryptoKey} keyObj
 */
export async function extractableWrapTarget(keyObj) {
  const raw = await crypto.subtle.exportKey("raw", keyObj);
  const name = keyObj.algorithm?.name || "AES-GCM";
  try {
    if (name === "HMAC") {
      const hash = /** @type {HmacKeyAlgorithm} */ (keyObj.algorithm).hash;
      const hashName = typeof hash === "string" ? hash : hash.name;
      return await crypto.subtle.importKey(
        "raw",
        raw,
        { name: "HMAC", hash: hashName },
        true,
        ["sign", "verify"]
      );
    }
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM", length: raw.byteLength * 8 },
      true,
      ["encrypt", "decrypt"]
    );
  } finally {
    try {
      new Uint8Array(raw).fill(0);
    } catch (_) {
      /* wipe */
    }
  }
}

/**
 * @param {string} alg  aes/128|192|256 | aes-kw/128|256 | hmac/sha256|384|512
 */
export function unwrapImportParams(alg) {
  const a = String(alg || "aes/256").toLowerCase();
  if (a === "aes/128" || a === "aes/192" || a === "aes/256") {
    const length = aesLengthFromAlg(a);
    return {
      importAlg: { name: "AES-GCM", length },
      usages: /** @type {KeyUsage[]} */ (["encrypt", "decrypt", "wrapKey", "unwrapKey"]),
      metaAlg: a,
    };
  }
  if (a === "aes-kw/128") {
    return {
      importAlg: { name: "AES-KW", length: 128 },
      usages: /** @type {KeyUsage[]} */ (["wrapKey", "unwrapKey"]),
      metaAlg: "aes-kw/128",
    };
  }
  if (a === "aes-kw/256") {
    return {
      importAlg: { name: "AES-KW", length: 256 },
      usages: /** @type {KeyUsage[]} */ (["wrapKey", "unwrapKey"]),
      metaAlg: "aes-kw/256",
    };
  }
  if (a === "hmac/sha256" || a === "hmac/sha384" || a === "hmac/sha512") {
    return {
      importAlg: { name: "HMAC", hash: hmacHashFromAlg(a) },
      usages: /** @type {KeyUsage[]} */ (["sign", "verify"]),
      metaAlg: a,
    };
  }
  return {
    importAlg: { name: "AES-GCM", length: 256 },
    usages: /** @type {KeyUsage[]} */ (["encrypt", "decrypt", "wrapKey", "unwrapKey"]),
    metaAlg: "aes/256",
  };
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
