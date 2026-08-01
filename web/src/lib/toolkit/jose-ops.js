/**
 * JOSE — JWS, JWE, and JWT (RFC 7515 / 7516 / 7519).
 *
 * The everyday developer case the toolkit was missing: *decode and verify a
 * JWT in a page that provably phones nowhere*. Pasting a token into a hosted
 * decoder means handing a live bearer credential to someone else's server;
 * this runs the same inspection against WebCrypto in the tab.
 *
 * Built directly on SubtleCrypto rather than on a JOSE library. Three reasons,
 * in order of weight:
 *
 *  1. The registry already speaks JWK — `export jwk` / `import jwk` /
 *     `keypair jwk` — so a JOSE op needs no key format the pipeline lacks. A
 *     library would arrive with its own key abstraction beside the CryptoKey
 *     one, not instead of it.
 *  2. Every algorithm shipped here is a SubtleCrypto primitive. JWS is a
 *     base64url framing over `sign`; JWE-GCM is a framing over `encrypt` plus
 *     a key wrap. The parts a library would add value for — RSA1_5 padding,
 *     A*CBC-HS* composite encryption, ECDH-ES key agreement — are exactly the
 *     ones deliberately left out below.
 *  3. Bundle weight is a stated constraint, and this file is smaller than the
 *     smallest published JOSE bundle.
 *
 * ## Deliberate omissions
 *
 * `alg: none` is not implemented and is *rejected on sight* — an unsecured
 * JWS is the historical CVE of this format, and a tool that will "verify" one
 * teaches the wrong reflex. `jose.decode` reads such a token happily, which is
 * the correct home for it: inspection, clearly marked unverified.
 *
 * A*CBC-HS* content encryption, ECDH-ES, RSA1_5, and PBES2 are absent. Each
 * needs composition WebCrypto does not do in one call, and each is either
 * legacy or a large surface for a first cut.
 *
 * ## Algorithm confusion
 *
 * `jose.verify` derives the algorithm it will accept from *the key*, then
 * requires the token's header to name that same algorithm. A token that says
 * `HS256` cannot be checked against an RSA public key by reinterpreting the
 * public modulus as an HMAC secret — the classic attack — because the key's
 * own `algorithm.name` is what selects the verification path, and a header
 * that disagrees with it is a hard error before any crypto runs.
 *
 * @module lib/toolkit/jose-ops
 */

import { base64ToBytes, bytesToBase64Url, bytesToText, textToBytes } from "./encode.js";
import { ensureAesWrapKey, resolveSlotKey } from "./webcrypto-ops.js";

/* ────────────────────────────── base64url ────────────────────────────── */

/**
 * @param {string} s
 * @returns {Uint8Array}
 */
function b64uToBytes(s) {
  const raw = String(s || "");
  if (/[^A-Za-z0-9\-_]/.test(raw)) {
    throw new Error("Not base64url — a compact JOSE segment may only use A–Z a–z 0–9 - _");
  }
  return base64ToBytes(raw);
}

/**
 * @param {Uint8Array} b
 * @returns {string}
 */
function bytesToB64u(b) {
  return bytesToBase64Url(b);
}

/**
 * @param {unknown} obj
 * @returns {string}
 */
function jsonToB64u(obj) {
  return bytesToB64u(textToBytes(JSON.stringify(obj)));
}

/**
 * @param {string} seg
 * @param {string} what
 * @returns {Record<string, *>}
 */
function b64uToJson(seg, what) {
  let text;
  try {
    text = bytesToText(b64uToBytes(seg));
  } catch (err) {
    throw new Error(`${what} is not valid base64url: ${err?.message || err}`);
  }
  try {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not a JSON object");
    }
    return parsed;
  } catch (err) {
    throw new Error(`${what} is not a JSON object: ${err?.message || err}`);
  }
}

/* ─────────────────────────── algorithm tables ─────────────────────────── */

/**
 * JWS algorithms, keyed by the recipe's lowercase enum value.
 *
 * `keyAlg` is the SubtleCrypto algorithm *name* the key must already have —
 * this is the anti-confusion anchor. `params` builds the call's algorithm
 * dictionary.
 * @type {Record<string, {
 *   jose: string,
 *   keyAlg: string,
 *   hash?: string,
 *   curve?: string,
 *   params: () => AlgorithmIdentifier | RsaPssParams | EcdsaParams,
 * }>}
 */
export const JWS_ALGS = {
  hs256: { jose: "HS256", keyAlg: "HMAC", hash: "SHA-256", params: () => "HMAC" },
  hs384: { jose: "HS384", keyAlg: "HMAC", hash: "SHA-384", params: () => "HMAC" },
  hs512: { jose: "HS512", keyAlg: "HMAC", hash: "SHA-512", params: () => "HMAC" },
  rs256: {
    jose: "RS256",
    keyAlg: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    params: () => "RSASSA-PKCS1-v1_5",
  },
  ps256: {
    jose: "PS256",
    keyAlg: "RSA-PSS",
    hash: "SHA-256",
    // RFC 7518 §3.5: the salt is the same length as the hash output.
    params: () => ({ name: "RSA-PSS", saltLength: 32 }),
  },
  es256: {
    jose: "ES256",
    keyAlg: "ECDSA",
    hash: "SHA-256",
    curve: "P-256",
    params: () => ({ name: "ECDSA", hash: "SHA-256" }),
  },
  es384: {
    jose: "ES384",
    keyAlg: "ECDSA",
    hash: "SHA-384",
    curve: "P-384",
    params: () => ({ name: "ECDSA", hash: "SHA-384" }),
  },
  es512: {
    jose: "ES512",
    keyAlg: "ECDSA",
    hash: "SHA-512",
    curve: "P-521",
    params: () => ({ name: "ECDSA", hash: "SHA-512" }),
  },
  eddsa: { jose: "EdDSA", keyAlg: "Ed25519", params: () => "Ed25519" },
};

/** JOSE name (`ES256`) → table entry. @type {Record<string, string>} */
const JWS_BY_JOSE = Object.fromEntries(
  Object.entries(JWS_ALGS).map(([k, v]) => [v.jose, k])
);

/** Content-encryption algorithms (`enc`). @type {Record<string, { jose: string, bits: number }>} */
export const JWE_ENCS = {
  a128gcm: { jose: "A128GCM", bits: 128 },
  a192gcm: { jose: "A192GCM", bits: 192 },
  a256gcm: { jose: "A256GCM", bits: 256 },
};

/** Key-management algorithms (`alg`). @type {Record<string, { jose: string, mode: string }>} */
export const JWE_ALGS = {
  dir: { jose: "dir", mode: "direct" },
  a128kw: { jose: "A128KW", mode: "aeskw" },
  a256kw: { jose: "A256KW", mode: "aeskw" },
  "rsa-oaep-256": { jose: "RSA-OAEP-256", mode: "rsa" },
};

const JWE_ENC_BY_JOSE = Object.fromEntries(
  Object.entries(JWE_ENCS).map(([k, v]) => [v.jose, k])
);
const JWE_ALG_BY_JOSE = Object.fromEntries(
  Object.entries(JWE_ALGS).map(([k, v]) => [v.jose, k])
);

/**
 * The algorithm a key is *able* to be used with, as a JOSE name.
 *
 * Returns null when the key's algorithm has no JOSE mapping, so callers report
 * the key rather than guessing a header.
 * @param {CryptoKey} key
 * @returns {string|null}
 */
export function joseAlgForKey(key) {
  const name = key?.algorithm?.name;
  if (!name) return null;
  if (name === "HMAC") {
    const hash = /** @type {HmacKeyAlgorithm} */ (key.algorithm).hash?.name;
    if (hash === "SHA-384") return "HS384";
    if (hash === "SHA-512") return "HS512";
    return "HS256";
  }
  if (name === "ECDSA") {
    const curve = /** @type {EcKeyAlgorithm} */ (key.algorithm).namedCurve;
    if (curve === "P-384") return "ES384";
    if (curve === "P-521") return "ES512";
    return "ES256";
  }
  if (name === "Ed25519") return "EdDSA";
  if (name === "RSASSA-PKCS1-v1_5") return "RS256";
  if (name === "RSA-PSS") return "PS256";
  return null;
}

/* ───────────────────────────── token parsing ───────────────────────────── */

/**
 * @typedef {object} DecodedJose
 * @property {"jws"|"jwe"} kind
 * @property {Record<string, *>} header  the protected header, as sent
 * @property {Record<string, *>|null} claims  parsed payload when it is a JSON object
 * @property {string|null} payloadText  raw payload when it is not JSON (JWS only)
 * @property {string[]} segments
 */

/**
 * Split and parse a compact JOSE serialization without verifying anything.
 *
 * This is the function `jose.decode` is: it must never fail on an untrusted
 * token for any reason other than the token being malformed, because refusing
 * to *show* a bad token is the opposite of what an inspector is for.
 *
 * @param {string} compact
 * @returns {DecodedJose}
 */
export function decodeCompact(compact) {
  const token = String(compact || "").trim();
  if (!token) throw new Error("jose.decode: empty token");
  const segments = token.split(".");
  if (segments.length !== 3 && segments.length !== 5) {
    throw new Error(
      `jose.decode: expected a compact JWS (3 segments) or JWE (5), got ${segments.length}`
    );
  }
  const kind = segments.length === 5 ? "jwe" : "jws";
  const header = b64uToJson(segments[0], "Protected header");

  if (kind === "jwe") {
    return { kind, header, claims: null, payloadText: null, segments };
  }

  // A JWS payload is octets: usually JSON claims (that is what makes it a
  // JWT), but RFC 7515 §3 allows anything. Report both honestly.
  let payloadText = null;
  /** @type {Record<string, *>|null} */
  let claims = null;
  try {
    payloadText = bytesToText(b64uToBytes(segments[1]));
  } catch (err) {
    throw new Error(`jose.decode: payload is not valid base64url: ${err?.message || err}`);
  }
  try {
    const parsed = JSON.parse(payloadText);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      claims = parsed;
      payloadText = null;
    }
  } catch (_) {
    /* not JSON — a bare JWS payload, kept as text */
  }
  return { kind, header, claims, payloadText, segments };
}

/**
 * Registered claims with a time value, evaluated against a clock.
 *
 * Returned as data rather than rendered: the widget re-derives the countdown
 * on every render, so a token that expires while you are looking at it goes
 * red without the recipe being re-run.
 *
 * @param {Record<string, *>|null} claims
 * @param {number} [nowMs]
 * @returns {{ exp: number|null, nbf: number|null, iat: number|null, expired: boolean, notYetValid: boolean }}
 */
export function claimTiming(claims, nowMs = Date.now()) {
  const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const exp = num(claims?.exp);
  const nbf = num(claims?.nbf);
  const iat = num(claims?.iat);
  const now = Math.floor(nowMs / 1000);
  return {
    exp,
    nbf,
    iat,
    expired: exp != null && exp <= now,
    notYetValid: nbf != null && nbf > now,
  };
}

/* ──────────────────────────────── decode ──────────────────────────────── */

/**
 * `jose.decode` — inspect a token *without* checking its signature.
 *
 * The output is deliberately shaped so that nothing downstream can mistake it
 * for a verified result: the emitted JSON leads with `"verified": false`, and
 * the artifact meta carries `joseVerified: false` for the widget's banner.
 * A tool that renders unverified claims the same way it renders verified ones
 * is how people ship authorization bugs.
 *
 * @param {{ type: string, data: * }} value
 * @param {Record<string, *>} [params]
 * @returns {{ type: string, data: string, meta: Record<string, *> }}
 */
export function execJoseDecode(value, params = {}) {
  const compact = pipelineText(value, "jose.decode");
  const decoded = decodeCompact(compact);
  const timing = claimTiming(decoded.claims);
  const body = {
    verified: false,
    kind: decoded.kind,
    header: decoded.header,
    ...(decoded.kind === "jwe"
      ? { payload: "encrypted — run jose.decrypt with the recipient key" }
      : decoded.claims
        ? { claims: decoded.claims }
        : { payload: decoded.payloadText }),
  };
  const format = String(params.format || "json").toLowerCase();
  const data =
    format === "compact" ? JSON.stringify(body) : JSON.stringify(body, null, 2);
  return {
    type: "text",
    data,
    meta: {
      // Claims out of an unverified token are not a secret — they were
      // readable by anyone holding the token, including whoever handed it
      // over. Marking them sensitive would mask exactly what the user asked
      // to see. The `unverified` marker below is the honest warning.
      sensitive: false,
      kind: "json",
      jose: {
        kind: decoded.kind,
        verified: false,
        header: decoded.header,
        claims: decoded.claims,
        payloadText: decoded.payloadText,
        timing,
      },
    },
  };
}

/* ───────────────────────────────── sign ───────────────────────────────── */

/**
 * @param {{ type: string, data: * }} value
 * @param {string} op
 * @returns {string}
 */
function pipelineText(value, op) {
  if (!value) throw new Error(`${op} expects a pipeline value`);
  if (value.type === "text") return String(value.data);
  if (value.type === "bytes") return bytesToText(value.data);
  throw new Error(`${op} expects text or bytes, got ${value.type}`);
}

/**
 * Resolve the signing/verifying key from `key=@slot`, with a clear error when
 * the recipe never bound one — the key panel fallback the WebCrypto ops use
 * does not apply here, because a JOSE op with no key has nothing to do.
 * @param {object} bindings
 * @param {*} ref
 * @param {"private"|"public"|"secret"|"either"} need
 * @param {string} op
 * @returns {Promise<CryptoKey>}
 */
async function requireSlotKey(bindings, ref, need, op) {
  const r = String(ref || "").trim();
  if (!r) {
    throw new Error(`${op}: key=@slot is required (e.g. \`genkey ec/p256 | out @k\` then \`${op} key=@k\`)`);
  }
  let key = null;
  if (need === "public" || need === "either") {
    // HMAC keys arrive as `secret`; asymmetric verification wants `public`.
    key =
      (await resolveSlotKey(bindings, r, need === "public" ? "public" : "either").catch(
        () => null
      )) || (await resolveSlotKey(bindings, r, "secret").catch(() => null));
  } else {
    key = await resolveSlotKey(bindings, r, need);
  }
  if (!key) throw new Error(`${op}: slot ${r} holds no usable key`);
  return key;
}

/**
 * `jose.sign` — JWS compact serialization (RFC 7515 §3.1).
 *
 * `alg=auto` reads the algorithm off the key, which is the only spelling that
 * cannot go wrong; naming one explicitly is checked against the key rather
 * than trusted, so `alg=hs256` with an EC key is an error and not a silently
 * different token.
 *
 * @param {{ type: string, data: * }} value
 * @param {Record<string, *>} params
 * @param {object} bindings
 */
export async function execJoseSign(value, params = {}, bindings = {}) {
  const payloadText = pipelineText(value, "jose.sign");
  const key = await requireSlotKey(bindings, params.key, "either", "jose.sign");

  const keyAlgJose = joseAlgForKey(key);
  if (!keyAlgJose) {
    throw new Error(
      `jose.sign: key algorithm ${key.algorithm?.name || "?"} has no JWS mapping (use HMAC, ECDSA, Ed25519, RSA-PSS, or RSASSA-PKCS1-v1_5)`
    );
  }
  const requested = String(params.alg || "auto").toLowerCase();
  const entryKey = requested === "auto" ? JWS_BY_JOSE[keyAlgJose] : requested;
  const entry = JWS_ALGS[entryKey];
  if (!entry) throw new Error(`jose.sign: unsupported alg "${params.alg}"`);
  if (entry.jose !== keyAlgJose) {
    throw new Error(
      `jose.sign: alg=${entry.jose} does not match the bound key (${keyAlgJose}) — algorithm and key must agree`
    );
  }
  if (!key.usages.includes("sign")) {
    throw new Error(`jose.sign: slot key cannot sign (usages: ${key.usages.join(", ") || "none"})`);
  }

  /** @type {Record<string, *>} */
  const header = { alg: entry.jose };
  const typ = String(params.typ ?? "JWT").trim();
  if (typ) header.typ = typ;
  const kid = String(params.kid || "").trim();
  if (kid) header.kid = kid;

  const protectedB64 = jsonToB64u(header);
  const payloadB64 = bytesToB64u(
    value.type === "bytes" ? value.data : textToBytes(payloadText)
  );
  const signingInput = textToBytes(`${protectedB64}.${payloadB64}`);
  const sig = new Uint8Array(await crypto.subtle.sign(entry.params(), key, signingInput));
  const token = `${protectedB64}.${payloadB64}.${bytesToB64u(sig)}`;

  /** @type {Record<string, *>|null} */
  let claims = null;
  try {
    const parsed = JSON.parse(payloadText);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) claims = parsed;
  } catch (_) {
    /* non-JSON payload — a JWS, not a JWT */
  }

  return {
    type: "text",
    data: token,
    meta: {
      /**
       * A signed token is a bearer credential: whoever holds it can use it.
       * Masked like any other secret, revealable when the recipe asked for it
       * with `out`.
       *
       * The tempting correction is that a JWS is *signed, not encrypted*, so
       * its header and payload are not confidential — true, and it is not the
       * question this flag answers. `sensitive` is the *displayability* axis
       * (`keyring.add` moves a secret while masked precisely because storing
       * is not displaying), and a compact JWS on screen is a live credential
       * on screen. What the readable half is owed is a **read-out that draws
       * while masked**, and the `jose-token` kind now declares one: the
       * `publicView` there renders this `jose` body — header, claims,
       * validity — and never the third segment, so the mask withholds exactly
       * the signature. Flipping this flag was the wrong lever; the missing
       * `publicView` was the defect.
       */
      sensitive: true,
      kind: "jws",
      jose: {
        kind: "jws",
        verified: true,
        signed: true,
        header,
        claims,
        payloadText: claims ? null : payloadText,
        timing: claimTiming(claims),
      },
    },
  };
}

/* ──────────────────────────────── verify ──────────────────────────────── */

/**
 * `jose.verify` — check a compact JWS and emit its payload.
 *
 * Fail-loud by design, and with no soft mode: unlike WebCrypto `verify`, whose
 * boolean can be a legitimate branch, a JWS that does not verify has no
 * payload worth handing downstream — the claims inside it are attacker-chosen.
 * Inspecting a token you cannot verify is `jose.decode`'s job.
 *
 * Expiry is part of the check by default (`expiry=check`). A verifier that
 * ignores `exp` is the second-most-common JWT bug after skipping verification
 * altogether; `expiry=ignore` remains available for looking at old tokens.
 *
 * @param {{ type: string, data: * }} value
 * @param {Record<string, *>} params
 * @param {object} bindings
 */
export async function execJoseVerify(value, params = {}, bindings = {}) {
  const compact = pipelineText(value, "jose.verify");
  const decoded = decodeCompact(compact);
  if (decoded.kind !== "jws") {
    throw new Error("jose.verify: this is a JWE (5 segments) — use jose.decrypt");
  }

  const headerAlg = String(decoded.header.alg || "");
  if (!headerAlg) throw new Error("jose.verify: header has no alg");
  if (headerAlg.toLowerCase() === "none") {
    throw new Error(
      'jose.verify: refusing alg="none" — an unsecured JWS is not a verified one (use jose.decode to inspect it)'
    );
  }

  const key = await requireSlotKey(bindings, params.key, "public", "jose.verify");
  const keyAlgJose = joseAlgForKey(key);
  if (!keyAlgJose) {
    throw new Error(
      `jose.verify: key algorithm ${key.algorithm?.name || "?"} has no JWS mapping`
    );
  }
  // Algorithm confusion: the key decides, the header must agree.
  if (headerAlg !== keyAlgJose) {
    throw new Error(
      `jose.verify: token says alg=${headerAlg} but the bound key is ${keyAlgJose} — refusing to reinterpret the key`
    );
  }
  const wanted = String(params.alg || "auto").toLowerCase();
  if (wanted !== "auto" && JWS_ALGS[wanted]?.jose !== headerAlg) {
    throw new Error(
      `jose.verify: alg=${JWS_ALGS[wanted]?.jose || params.alg} was required but the token is ${headerAlg}`
    );
  }
  const entry = JWS_ALGS[JWS_BY_JOSE[headerAlg]];
  if (!entry) throw new Error(`jose.verify: unsupported alg ${headerAlg}`);
  if (!key.usages.includes("verify")) {
    throw new Error(
      `jose.verify: slot key cannot verify (usages: ${key.usages.join(", ") || "none"})`
    );
  }

  const signingInput = textToBytes(`${decoded.segments[0]}.${decoded.segments[1]}`);
  const sig = b64uToBytes(decoded.segments[2]);
  const ok = await crypto.subtle.verify(entry.params(), key, sig, signingInput);
  if (!ok) throw new Error("jose.verify: signature verification failed");

  const timing = claimTiming(decoded.claims);
  const expiry = String(params.expiry || "check").toLowerCase();
  if (expiry !== "ignore") {
    if (timing.expired) {
      throw new Error(
        `jose.verify: signature is valid but the token expired at ${new Date(
          /** @type {number} */ (timing.exp) * 1000
        ).toISOString()} (expiry=ignore to inspect it anyway)`
      );
    }
    if (timing.notYetValid) {
      throw new Error(
        `jose.verify: signature is valid but the token is not valid before ${new Date(
          /** @type {number} */ (timing.nbf) * 1000
        ).toISOString()} (expiry=ignore to inspect it anyway)`
      );
    }
  }

  const payload = decoded.claims
    ? JSON.stringify(decoded.claims, null, 2)
    : String(decoded.payloadText ?? "");
  return {
    type: "text",
    data: payload,
    meta: {
      sensitive: false,
      kind: decoded.claims ? "json" : "opaque",
      jose: {
        kind: "jws",
        verified: true,
        header: decoded.header,
        claims: decoded.claims,
        payloadText: decoded.payloadText,
        timing,
        expiryChecked: expiry !== "ignore",
      },
    },
  };
}

/* ───────────────────────────────── JWE ───────────────────────────────── */

/**
 * @param {number} bits
 * @returns {Promise<CryptoKey>}
 */
function generateCek(bits) {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: bits }, true, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * `jose.encrypt` — JWE compact serialization (RFC 7516 §3.1) with GCM content
 * encryption.
 *
 * Only the AEAD content encryptions are implemented (`A128GCM`/`A192GCM`/
 * `A256GCM`); `A*CBC-HS*` is a composite construction WebCrypto cannot do in
 * one call and is a legacy option besides.
 *
 * @param {{ type: string, data: * }} value
 * @param {Record<string, *>} params
 * @param {object} bindings
 */
export async function execJoseEncrypt(value, params = {}, bindings = {}) {
  const plaintext =
    value?.type === "bytes"
      ? /** @type {Uint8Array} */ (value.data)
      : textToBytes(pipelineText(value, "jose.encrypt"));

  const encKey = String(params.enc || "a256gcm").toLowerCase();
  const enc = JWE_ENCS[encKey];
  if (!enc) throw new Error(`jose.encrypt: unsupported enc "${params.enc}"`);
  const algKey = String(params.alg || "dir").toLowerCase();
  const alg = JWE_ALGS[algKey];
  if (!alg) throw new Error(`jose.encrypt: unsupported alg "${params.alg}"`);

  /** @type {Record<string, *>} */
  const header = { alg: alg.jose, enc: enc.jose };
  const kid = String(params.kid || "").trim();
  if (kid) header.kid = kid;

  /** @type {CryptoKey} */
  let cek;
  /** @type {Uint8Array} */
  let encryptedKey = new Uint8Array(0);

  if (alg.mode === "direct") {
    const key = await requireSlotKey(bindings, params.key, "secret", "jose.encrypt");
    cek = await ensureAesGcmKey(key, enc.bits, "jose.encrypt");
  } else if (alg.mode === "aeskw") {
    const kek = await requireSlotKey(bindings, params.key, "secret", "jose.encrypt");
    const wrapKey = await ensureAesWrapKey(kek, "AES-KW");
    const wantBits = alg.jose === "A128KW" ? 128 : 256;
    const haveBits = /** @type {AesKeyAlgorithm} */ (wrapKey.algorithm).length;
    if (haveBits !== wantBits) {
      throw new Error(
        `jose.encrypt: alg=${alg.jose} needs a ${wantBits}-bit key, slot holds ${haveBits}-bit`
      );
    }
    cek = await generateCek(enc.bits);
    encryptedKey = new Uint8Array(
      await crypto.subtle.wrapKey("raw", cek, wrapKey, "AES-KW")
    );
  } else {
    const pub = await requireSlotKey(bindings, params.key, "public", "jose.encrypt");
    if (pub.algorithm?.name !== "RSA-OAEP") {
      throw new Error(
        `jose.encrypt: alg=${alg.jose} needs an RSA-OAEP public key, slot holds ${pub.algorithm?.name || "?"} (try \`genkey rsa/2048 usage=encrypt\`)`
      );
    }
    cek = await generateCek(enc.bits);
    encryptedKey = new Uint8Array(
      await crypto.subtle.wrapKey("raw", cek, pub, { name: "RSA-OAEP" })
    );
  }

  const protectedB64 = jsonToB64u(header);
  // RFC 7516 §5.1 step 14: the AAD is the ASCII of the encoded protected
  // header — so tampering with `alg`/`enc` breaks the tag rather than
  // silently changing how the recipient decrypts.
  const aad = textToBytes(protectedB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      cek,
      plaintext
    )
  );
  // WebCrypto returns ciphertext||tag; JWE carries them as separate segments.
  const ciphertext = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);

  const token = [
    protectedB64,
    bytesToB64u(encryptedKey),
    bytesToB64u(iv),
    bytesToB64u(ciphertext),
    bytesToB64u(tag),
  ].join(".");

  return {
    type: "text",
    data: token,
    meta: {
      sensitive: true,
      kind: "jwe",
      jose: { kind: "jwe", verified: true, header, claims: null, timing: claimTiming(null) },
    },
  };
}

/**
 * @param {CryptoKey} key
 * @param {number} bits
 * @param {string} op
 * @returns {Promise<CryptoKey>}
 */
async function ensureAesGcmKey(key, bits, op) {
  const name = key.algorithm?.name;
  const have = /** @type {AesKeyAlgorithm} */ (key.algorithm)?.length;
  if (name === "AES-GCM" && have === bits) return key;
  if (!String(name || "").startsWith("AES")) {
    throw new Error(`${op}: alg=dir needs an AES key, slot holds ${name || "?"}`);
  }
  if (have !== bits) {
    throw new Error(
      `${op}: alg=dir with this enc needs a ${bits}-bit key, slot holds ${have}-bit`
    );
  }
  const raw = await crypto.subtle.exportKey("raw", key);
  try {
    return await crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: bits }, true, [
      "encrypt",
      "decrypt",
    ]);
  } finally {
    try {
      new Uint8Array(raw).fill(0);
    } catch (_) {
      /* wipe */
    }
  }
}

/**
 * `jose.decrypt` — the inverse of `jose.encrypt`.
 *
 * @param {{ type: string, data: * }} value
 * @param {Record<string, *>} params
 * @param {object} bindings
 */
export async function execJoseDecrypt(value, params = {}, bindings = {}) {
  const compact = pipelineText(value, "jose.decrypt");
  const decoded = decodeCompact(compact);
  if (decoded.kind !== "jwe") {
    throw new Error("jose.decrypt: this is a JWS (3 segments) — use jose.verify");
  }
  const header = decoded.header;
  const algJose = String(header.alg || "");
  const encJose = String(header.enc || "");
  const alg = JWE_ALGS[JWE_ALG_BY_JOSE[algJose]];
  const enc = JWE_ENCS[JWE_ENC_BY_JOSE[encJose]];
  if (!alg) throw new Error(`jose.decrypt: unsupported alg ${algJose || "(missing)"}`);
  if (!enc) {
    throw new Error(
      `jose.decrypt: unsupported enc ${encJose || "(missing)"} — only the AES-GCM content encryptions are implemented`
    );
  }

  const [, ekSeg, ivSeg, ctSeg, tagSeg] = decoded.segments;
  const encryptedKey = ekSeg ? b64uToBytes(ekSeg) : new Uint8Array(0);
  const iv = b64uToBytes(ivSeg);
  const ciphertext = b64uToBytes(ctSeg);
  const tag = b64uToBytes(tagSeg);

  /** @type {CryptoKey} */
  let cek;
  if (alg.mode === "direct") {
    const key = await requireSlotKey(bindings, params.key, "secret", "jose.decrypt");
    cek = await ensureAesGcmKey(key, enc.bits, "jose.decrypt");
  } else if (alg.mode === "aeskw") {
    const kek = await requireSlotKey(bindings, params.key, "secret", "jose.decrypt");
    const unwrapKey = await ensureAesWrapKey(kek, "AES-KW");
    cek = await crypto.subtle.unwrapKey(
      "raw",
      encryptedKey,
      unwrapKey,
      "AES-KW",
      { name: "AES-GCM", length: enc.bits },
      true,
      ["encrypt", "decrypt"]
    );
  } else {
    const priv = await requireSlotKey(bindings, params.key, "private", "jose.decrypt");
    cek = await crypto.subtle.unwrapKey(
      "raw",
      encryptedKey,
      priv,
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: enc.bits },
      true,
      ["encrypt", "decrypt"]
    );
  }

  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);
  const aad = textToBytes(decoded.segments[0]);
  /** @type {Uint8Array} */
  let plain;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
        cek,
        sealed
      )
    );
  } catch (err) {
    throw new Error(
      `jose.decrypt: authentication failed — wrong key, or the token was modified (${err?.message || err})`
    );
  }

  const text = bytesToText(plain);
  /** @type {Record<string, *>|null} */
  let claims = null;
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) claims = parsed;
  } catch (_) {
    /* opaque plaintext */
  }

  return {
    type: "text",
    data: text,
    meta: {
      // Plaintext recovered from a JWE was encrypted for a reason.
      sensitive: true,
      kind: claims ? "json" : "opaque",
      jose: {
        kind: "jwe",
        verified: true,
        decrypted: true,
        header,
        claims,
        payloadText: claims ? null : text,
        timing: claimTiming(claims),
      },
    },
  };
}
