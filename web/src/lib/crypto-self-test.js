/**
 * Basilisk crypto self-test module.
 *
 * Implements a FIPS 140-3-inspired Pre-Operational Self-Test (POST) and
 * per-algorithm Conditional Algorithm Self-Tests (CASTs) for OpenPGP.js and
 * WebCrypto (SubtleCrypto) paths used by the toolkit.
 *
 * ── POST (Pre-Operational Self-Test, FIPS 140-3 §4.9.1) ─────────────────────
 *   In FIPS 140-3, startup integrity is primarily the responsibility of
 *   code-signing / SRI (already enforced by the server via HTTP headers).
 *   Algorithm self-tests are moved to the CAST phase, but running them all at
 *   startup (before any user-initiated crypto) is conservative and permitted.
 *
 * ── CASTs (Conditional Algorithm Self-Tests, FIPS 140-3 §4.9.2) ─────────────
 *   CASTs are run right before each algorithm category is used for the first
 *   time.  This module runs all CASTs eagerly at startup (POST phase) and also
 *   exposes assertCryptoReady() so that every crypto entry point can call it as
 *   a late gate.  Suites:
 *
 *     OpenPGP suite
 *     CAST-1  Key generation (Curve25519 / X25519 / Ed25519)
 *     CAST-2  Asymmetric encrypt + decrypt (ECDH + AES-OCB or AES-GCM)
 *     CAST-3  Detached digital signature + verification (Ed25519 + SHA-512)
 *     CAST-4  Signed + encrypted combined message
 *     CAST-5  Password encrypt + decrypt (Argon2 S2K + AES — loads OpenPGP WASM)
 *
 *     WebCrypto suite (shared helpers with toolkit/webcrypto-ops.js)
 *     CAST-6  Digest KAT (SHA-256 "basilisk")
 *     CAST-7  AES-GCM roundtrip
 *     CAST-8  Ed25519 sign / verify
 *     CAST-9  ECDH P-256 agree
 *     CAST-10 HKDF-SHA-256 KAT
 *     CAST-11 AES-KW wrap / unwrap
 *     CAST-13 AES-CBC roundtrip
 *     CAST-14 AES-CTR roundtrip
 *
 *     SSS suite
 *     CAST-12 GF(256) SSS split/combine + BLIP39 encode/decode roundtrip
 *
 * ── Error state (FIPS 140-3 §4.9.3) ────────────────────────────────────────
 *   Any POST or CAST failure latches the module into ERROR state permanently
 *   for the page lifetime.  Once in ERROR state:
 *     · assertCryptoReady() throws CryptoModuleError.
 *     · All cryptographic services are refused.
 *     · Failure details are preserved in the structured failure log.
 *   The error state cannot be cleared without a full page reload.
 *
 * ── Failure logging (FIPS 140-3 §4.9.3) ────────────────────────────────────
 *   _failureLog records { timestamp, phase, cast, message } for the most
 *   recent failure.  getModuleStatus() exposes this log to the operator UI.
 *
 * ── Zeroization (FIPS 140-3 §4.9.3) ────────────────────────────────────────
 *   Ephemeral test key material is zeroed via zeroKeyMaterial / Uint8Array
 *   fills after each test round. Wipe with inlined fill(0) at each site
 *   (see `src/lib/memory-safety.js`) — do not reintroduce a shared zeroBuffer.
 *
 * ── Module integrity (SRI + Merkle attestation) ─────────────────────────────
 *   FIPS 140-3 treats startup integrity as code-signing / verified load.
 *   In the browser this is Subresource Integrity enforced by the UA:
 *     · Entry scripts, styles, and modulepreloads carry integrity= (sha384)
 *       from vite-plugin-sri-gen.
 *     · Lazy chunks, dynamic import(), and module workers are covered by an
 *       external import map at /importmaps/importmap-*.json (also SRI’d),
 *       externalized post-build so CSP stays script-src 'self' plus the
 *       narrow 'wasm-unsafe-eval' keyword (never 'unsafe-eval').
 *     · 'wasm-unsafe-eval' exists solely for OpenPGP.js Argon2id: the library
 *       base64-embeds WASM and calls WebAssembly.instantiate(). CSP3 cannot
 *       hash-allowlist that blob; integrity is transitive through SRI on the
 *       openpgp JS chunk that contains it. Without XSS that already runs
 *       attacker JS, the keyword does not widen script injection. Compatible
 *       / iterated S2K avoids loading WASM. Refs: W3C CSP3 §4.5,
 *       https://www.w3.org/TR/CSP3/#can-compile-wasm-bytes ; MDN script-src
 *       'wasm-unsafe-eval'; WebAssembly CSP proposal.
 *     · On hash mismatch the browser refuses to execute the module — fail
 *       closed on CDN cache skew (old chunk + new HTML) or tampering.
 *   After CASTs pass, computeLoadedModulesRoot() folds those SRI digests
 *   into a SHA-256 Merkle root. Production builds also emit
 *   /integrity/module-roots.json and inject pin <meta> tags; the POST then
 *   fetches the pin (cache: no-store) and fails closed on mismatch, and on a
 *   page that has SRI but names no pin at all. The pin is served by the same
 *   origin as the code, so an edge that rewrites both agrees with itself:
 *   VITE_INTEGRITY_PIN_MIRRORS would name pin copies on other origins and
 *   `verifyModuleRootAgainstPins` requires all of them to agree, but nothing
 *   in this repository sets that variable, publishes such a copy, or allows a
 *   second origin in the deployed connect-src — so that comparison does not
 *   run anywhere, and what is claimed above is the same-origin check alone.
 *   docs/THREAT-MODEL.md lists what making it run would take. Packaging:
 *   externalize-importmaps.js, write-module-integrity-pin.mjs,
 *   scripts/package-static.sh.
 *
 * Called at page startup by decrypt.js and encrypt.js; also imported by
 * vitest for CI coverage (src/test/crypto-self-test.test.js).
 *
 * Memory-protection note (summary — full rules in memory-safety.js):
 *   WebCrypto places no normative zeroization duty on UAs when CryptoKey
 *   references drop (https://www.w3.org/TR/webcrypto/#security-developers).
 *   Best-effort mitigations: CSP+SRI; wipe owned Uint8Arrays; clear DOM;
 *   short key lifetime; worker terminate(); transferable postMessage for
 *   cross-window secret octets. Strings and mlock are not available levers.
 */

import {
  createMessage,
  decrypt,
  encrypt,
  enums,
  generateKey,
  readMessage,
  readSignature,
  sign,
  verify,
} from "openpgp";
import {
  computeLoadedModulesRoot,
  shortModuleRoot,
  verifyModuleRootAgainstPins,
} from "./module-integrity.js";
import { zeroKeyMaterial } from "./pgp/memory.js";
import { textToBytes } from "./toolkit/encode.js";
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  aesCtrDecrypt,
  aesCtrEncrypt,
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesKwUnwrap,
  aesKwWrap,
  ecdhSharedBits,
  hkdfDerive,
  subtleSign,
  subtleVerify,
} from "./toolkit/webcrypto-ops.js";
import { decodeShareSet, encodeShareSet } from "./slip39/blip39.js";
import { combineRawShares, splitRawShares } from "./slip39/slip39.js";

// ── Module state ─────────────────────────────────────────────────────────────

/** @type {'INITIALIZING' | 'READY' | 'ERROR'} */
let _state = "INITIALIZING";

/** @type {Array<{ timestamp: string, phase: string, cast: string, message: string }>} */
let _failureLog = [];

/** Singleton promise for the POST run — prevents double-execution. */
let _postPromise = null;

/** @type {SelfTestResult|null} */
let _lastResult = null;

/** SHA-256("basilisk") — CAST-6 known answer. */
const CAST6_SHA256_BASILISK =
  "08aaa9f32114b313e08f0c1b0f8a85d797835a4e34afe67fafbc1e520e080c89";

/**
 * HKDF-SHA-256 KAT (CAST-10):
 *   IKM  = "basilisk-hkdf-ikm-v1"
 *   salt = "basilisk-hkdf-salt"
 *   info = "cast-10"
 *   L    = 32
 */
const CAST10_HKDF_OKM =
  "563f2100d5ab3bf4c8d2d5c9de441d370ca7d95180de6c74b86027c7665e9cd8";

// ── Public error class ────────────────────────────────────────────────────────

/**
 * Thrown by assertCryptoReady() when the module is in ERROR state.
 * Callers should treat this as a hard, non-recoverable failure.
 */
export class CryptoModuleError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "CryptoModuleError";
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Latch the module into ERROR state and record a structured log entry.
 * This function is idempotent — subsequent calls add additional log entries
 * but do not change the already-ERROR state.
 *
 * @param {string} phase  - 'POST' or 'CAST'
 * @param {string} cast   - CAST identifier, e.g. 'CAST-1'
 * @param {string} message
 */
function enterErrorState(phase, cast, message) {
  _state = "ERROR";
  _failureLog.push({
    timestamp: new Date().toISOString(),
    phase,
    cast,
    message,
  });
  // Emit a structured console error so browser devtools / monitoring tools
  // can capture it.  Do not include key material in the message.
  console.error(
    `[Basilisk] Crypto module ${phase} failure (${cast}): ${message}`
  );
}

const SELF_TEST_UID = [
  { name: "Basilisk Self-Test", email: "selftest@basilisk.invalid" },
];

/** Fixed known plaintext used in all KAT-style roundtrips. */
const POST_CANARY =
  "Basilisk POST canary v1 \x00\x01\x02\xff integrity-check";

/**
 * Generate an ephemeral Curve25519 key pair for self-test use.
 * @returns {Promise<{ privateKey: import("openpgp").PrivateKey, publicKey: import("openpgp").PublicKey }>}
 */
async function generateEphemeralKey() {
  return generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: SELF_TEST_UID,
    format: "object",
  });
}

// ── Core test runner ──────────────────────────────────────────────────────────

/**
 * Run all OpenPGP + WebCrypto CASTs and populate the module result.
 * @returns {Promise<SelfTestResult>}
 */
async function _runAllTests() {
  const t0 = Date.now();

  /** @type {SelfTestResults} */
  const results = {
    keyGeneration: false,
    encryptDecrypt: false,
    signVerify: false,
    signedEncrypt: false,
    passwordArgon2: false,
    digestKat: false,
    aesGcmRoundtrip: false,
    subtleSignVerify: false,
    ecdhAgree: false,
    hkdfKat: false,
    aesKwRoundtrip: false,
    aesCbcRoundtrip: false,
    aesCtrRoundtrip: false,
    sssRoundtrip: false,
  };

  let privateKey = null;

  try {
    // ── CAST-1: Asymmetric key generation ─────────────────────────────────
    // Verifies that the ECC key-generation primitive (Curve25519 / X25519 /
    // Ed25519) produces well-formed, non-null key objects.
    const kp = await generateEphemeralKey();
    if (!kp.privateKey || !kp.publicKey)
      throw new Error("CAST-1: generateKey returned null");
    privateKey = kp.privateKey;
    const { publicKey } = kp;
    results.keyGeneration = true;

    // ── CAST-2: Asymmetric encrypt / decrypt ──────────────────────────────
    // Encrypts POST_CANARY to the just-generated public key (exercising ECDH
    // key agreement + AES-OCB or AES-GCM), then decrypts and compares the
    // recovered plaintext to the original.  A mismatch means the symmetric
    // or asymmetric primitive is broken.
    const plainMsg = await createMessage({ text: POST_CANARY });
    const ciphertext = await encrypt({
      message: plainMsg,
      encryptionKeys: publicKey,
    });
    const { data: decrypted } = await decrypt({
      message: await readMessage({ armoredMessage: ciphertext }),
      decryptionKeys: privateKey,
    });
    if (decrypted !== POST_CANARY)
      throw new Error(
        `CAST-2: decrypt mismatch (got ${JSON.stringify(decrypted)})`
      );
    results.encryptDecrypt = true;

    // ── CAST-3: Detached digital signature + verification ─────────────────
    // Signs POST_CANARY with the private key (Ed25519 + SHA-512) and verifies
    // the detached signature against the public key.  Failure indicates a
    // broken hash or signature primitive.
    const detachedSig = await sign({
      message: await createMessage({ text: POST_CANARY }),
      signingKeys: privateKey,
      detached: true,
    });
    const verifyResult = await verify({
      message: await createMessage({ text: POST_CANARY }),
      signature: await readSignature({ armoredSignature: detachedSig }),
      verificationKeys: publicKey,
    });
    // .verified rejects if signature is invalid — surface the error upward.
    await verifyResult.signatures[0].verified;
    results.signVerify = true;

    // ── CAST-4: Signed + encrypted combined ───────────────────────────────
    // Exercises the full pipeline: sign, encrypt (outer), decrypt, verify.
    // Catches failures in SEIPD packet construction or embedded signature
    // verification that the individual tests above might not expose.
    const combined = await encrypt({
      message: await createMessage({ text: POST_CANARY }),
      encryptionKeys: publicKey,
      signingKeys: privateKey,
    });
    const { data: decCombined, signatures: combinedSigs } = await decrypt({
      message: await readMessage({ armoredMessage: combined }),
      decryptionKeys: privateKey,
      verificationKeys: publicKey,
    });
    if (decCombined !== POST_CANARY)
      throw new Error("CAST-4: combined decrypt mismatch");
    await combinedSigs[0].verified;
    results.signedEncrypt = true;

    // ── CAST-5: Password encrypt / decrypt (Argon2) ───────────────────────
    // Modern SKESK path used by toolkit symencrypt and passphrase encrypt.
    // OpenPGP.js implements Argon2 via WebAssembly — this CAST also proves
    // the page CSP permits 'wasm-unsafe-eval' (without allowing JS eval).
    const password = "basilisk-post-cast5-argon2";
    /** @type {Partial<import("openpgp").Config>} */
    const argon2Config = {
      s2kType: enums.s2k.argon2,
      aeadProtect: true,
      preferredAEADAlgorithm: enums.aead.ocb,
      preferredSymmetricAlgorithm: enums.symmetric.aes256,
    };
    const pwCiphertext = await encrypt({
      message: await createMessage({ text: POST_CANARY }),
      passwords: [password],
      config: argon2Config,
    });
    const { data: pwPlain } = await decrypt({
      message: await readMessage({ armoredMessage: pwCiphertext }),
      passwords: [password],
      config: argon2Config,
    });
    if (pwPlain !== POST_CANARY)
      throw new Error(
        `CAST-5: Argon2 password decrypt mismatch (got ${JSON.stringify(pwPlain)})`
      );
    results.passwordArgon2 = true;

    // ── Zeroization (OpenPGP ephemeral) ───────────────────────────────────
    zeroKeyMaterial(privateKey);
    privateKey = null;

    // ── CAST-6: Digest KAT (SHA-256) ──────────────────────────────────────
    {
      const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", textToBytes("basilisk"))
      );
      const hex = bytesToHexLower(digest);
      digest.fill(0);
      if (hex !== CAST6_SHA256_BASILISK) {
        throw new Error(`CAST-6: SHA-256 KAT mismatch (got ${hex})`);
      }
      results.digestKat = true;
    }

    // ── CAST-7: AES-GCM roundtrip ─────────────────────────────────────────
    {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
      const plain = textToBytes(POST_CANARY);
      const packed = await aesGcmEncrypt(key, plain);
      const recovered = await aesGcmDecrypt(key, packed);
      const ok =
        recovered.length === plain.length &&
        recovered.every((b, i) => b === plain[i]);
      plain.fill(0);
      packed.fill(0);
      recovered.fill(0);
      if (!ok) throw new Error("CAST-7: AES-GCM decrypt mismatch");
      results.aesGcmRoundtrip = true;
    }

    // ── CAST-8: Ed25519 sign / verify (SubtleCrypto) ──────────────────────
    {
      const skp = await crypto.subtle.generateKey("Ed25519", false, [
        "sign",
        "verify",
      ]);
      const data = textToBytes(POST_CANARY);
      const sig = await subtleSign(skp.privateKey, data);
      const ok = await subtleVerify(skp.publicKey, sig, data);
      data.fill(0);
      sig.fill(0);
      if (!ok) throw new Error("CAST-8: Ed25519 verify failed");
      results.subtleSignVerify = true;
    }

    // ── CAST-9: ECDH P-256 agree ──────────────────────────────────────────
    {
      const alice = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits", "deriveKey"]
      );
      const bob = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits", "deriveKey"]
      );
      const aBits = await ecdhSharedBits(alice.privateKey, bob.publicKey, 256);
      const bBits = await ecdhSharedBits(bob.privateKey, alice.publicKey, 256);
      const ok =
        aBits.length === bBits.length && aBits.every((b, i) => b === bBits[i]);
      aBits.fill(0);
      bBits.fill(0);
      if (!ok) throw new Error("CAST-9: ECDH shared bits disagree");
      results.ecdhAgree = true;
    }

    // ── CAST-10: HKDF-SHA-256 KAT ─────────────────────────────────────────
    {
      const ikm = textToBytes("basilisk-hkdf-ikm-v1");
      const salt = textToBytes("basilisk-hkdf-salt");
      const info = textToBytes("cast-10");
      const okm = await hkdfDerive(ikm, {
        salt,
        info,
        length: 32,
        hash: "SHA-256",
      });
      const hex = bytesToHexLower(okm);
      ikm.fill(0);
      salt.fill(0);
      info.fill(0);
      okm.fill(0);
      if (hex !== CAST10_HKDF_OKM) {
        throw new Error(`CAST-10: HKDF KAT mismatch (got ${hex})`);
      }
      results.hkdfKat = true;
    }

    // ── CAST-11: AES-KW wrap / unwrap ─────────────────────────────────────
    {
      const wrappingKey = await crypto.subtle.generateKey(
        { name: "AES-KW", length: 256 },
        false,
        ["wrapKey", "unwrapKey"]
      );
      const cek = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const wrapped = await aesKwWrap(wrappingKey, cek);
      const unwrapped = await aesKwUnwrap(
        wrappingKey,
        wrapped,
        { name: "AES-GCM", length: 256 },
        ["encrypt", "decrypt"]
      );
      const rawA = new Uint8Array(await crypto.subtle.exportKey("raw", cek));
      const rawB = new Uint8Array(await crypto.subtle.exportKey("raw", unwrapped));
      const ok =
        rawA.length === rawB.length && rawA.every((b, i) => b === rawB[i]);
      wrapped.fill(0);
      rawA.fill(0);
      rawB.fill(0);
      if (!ok) throw new Error("CAST-11: AES-KW unwrap mismatch");
      results.aesKwRoundtrip = true;
    }

    // ── CAST-13: AES-CBC roundtrip ────────────────────────────────────────
    {
      const key = await crypto.subtle.generateKey(
        { name: "AES-CBC", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const plain = textToBytes(POST_CANARY);
      const packed = await aesCbcEncrypt(key, plain);
      const recovered = await aesCbcDecrypt(key, packed);
      const ok =
        recovered.length === plain.length &&
        recovered.every((b, i) => b === plain[i]);
      plain.fill(0);
      packed.fill(0);
      recovered.fill(0);
      if (!ok) throw new Error("CAST-13: AES-CBC decrypt mismatch");
      results.aesCbcRoundtrip = true;
    }

    // ── CAST-14: AES-CTR roundtrip ────────────────────────────────────────
    {
      const key = await crypto.subtle.generateKey(
        { name: "AES-CTR", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const plain = textToBytes(POST_CANARY);
      const packed = await aesCtrEncrypt(key, plain);
      const recovered = await aesCtrDecrypt(key, packed);
      const ok =
        recovered.length === plain.length &&
        recovered.every((b, i) => b === plain[i]);
      plain.fill(0);
      packed.fill(0);
      recovered.fill(0);
      if (!ok) throw new Error("CAST-14: AES-CTR decrypt mismatch");
      results.aesCtrRoundtrip = true;
    }

    // ── CAST-12: SSS split/combine + BLIP39 roundtrip ──────────────────────
    {
      /** Fixed 32-byte master (toolkit SSS length constraint). */
      const secret = new Uint8Array(32);
      for (let i = 0; i < 32; i++) secret[i] = (i * 17 + 3) & 0xff;
      const rawSet = await splitRawShares(secret, { threshold: 2, shares: 3 });
      const fromRaw = await combineRawShares({
        raw: rawSet.raw.slice(0, 2),
        threshold: 2,
        flags: rawSet.flags,
      });
      const rawOk =
        fromRaw.length === secret.length &&
        fromRaw.every((b, i) => b === secret[i]);
      fromRaw.fill(0);
      if (!rawOk) throw new Error("CAST-12: SSS combine mismatch");

      const mnemonic = encodeShareSet(rawSet);
      const decoded = decodeShareSet(mnemonic.mnemonics);
      const fromMn = await combineRawShares(decoded);
      const mnOk =
        fromMn.length === secret.length &&
        fromMn.every((b, i) => b === secret[i]);
      fromMn.fill(0);
      secret.fill(0);
      for (const sh of rawSet.raw || []) {
        try {
          sh.data.fill(0);
        } catch (_) {
          /* wipe */
        }
      }
      if (!mnOk) throw new Error("CAST-12: BLIP39 encode/decode mismatch");
      results.sssRoundtrip = true;
    }

    const moduleIntegrity = await computeLoadedModulesRoot({
      selfModuleUrl: import.meta.url,
    });

    // Cross-check live Merkle root against pin document(s). The same-origin pin
    // catches CDN HTML/asset skew. Mirrors on other origins would catch a
    // single edge rewriting HTML, JS and pin together — no deployment in this
    // repository publishes one, and `docs/THREAT-MODEL.md` says so rather than
    // claiming the protection.
    //
    // `requirePins` because of the branch above: this runs only when the page
    // carried real SRI digests, and every build that emits those also emits a
    // `basilisk-integrity-pins` meta — `scripts/package-static.sh` refuses to
    // package a page without one. So on a served page an empty pin list is not
    // "unpinned build", it is "the meta is missing from the bytes I was sent",
    // and treating that as a pass would make deleting one attribute the cheapest
    // way to switch this check off.
    if (moduleIntegrity.source === "sri" && moduleIntegrity.root) {
      const pin = await verifyModuleRootAgainstPins(moduleIntegrity.root, {
        requirePins: true,
      });
      moduleIntegrity.pin = pin;
      if (pin.required && !pin.ok) {
        enterErrorState("POST", "INTEGRITY", pin.message);
        const failResult = {
          passed: false,
          error: pin.message,
          results,
          elapsed: Date.now() - t0,
          moduleIntegrity,
        };
        _lastResult = failResult;
        return failResult;
      }
    }

    _state = "READY";
    const okResult = {
      passed: true,
      results,
      elapsed: Date.now() - t0,
      moduleIntegrity,
    };
    _lastResult = okResult;
    return okResult;
  } catch (err) {
    // Identify which CAST failed for the log entry.
    const castMap = {
      keyGeneration: "CAST-1",
      encryptDecrypt: "CAST-2",
      signVerify: "CAST-3",
      signedEncrypt: "CAST-4",
      passwordArgon2: "CAST-5",
      digestKat: "CAST-6",
      aesGcmRoundtrip: "CAST-7",
      subtleSignVerify: "CAST-8",
      ecdhAgree: "CAST-9",
      hkdfKat: "CAST-10",
      aesKwRoundtrip: "CAST-11",
      sssRoundtrip: "CAST-12",
      aesCbcRoundtrip: "CAST-13",
      aesCtrRoundtrip: "CAST-14",
    };
    const failedKey = /** @type {keyof SelfTestResults | undefined} */ (
      Object.keys(results).find((k) => !results[/** @type {any} */ (k)])
    );
    const castId = (failedKey && castMap[failedKey]) || "POST";
    const msg = err?.message || String(err);

    // Zeroize test key material even on failure.
    if (privateKey) {
      zeroKeyMaterial(privateKey);
      privateKey = null;
    }

    enterErrorState("POST", castId, msg);
    const failResult = {
      passed: false,
      error: msg,
      results,
      elapsed: Date.now() - t0,
      moduleIntegrity: { root: "", leafCount: 0, source: "none" },
    };
    _lastResult = failResult;
    return failResult;
  }
}

/** @param {Uint8Array} bytes */
function bytesToHexLower(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Run all self-tests (POST + CASTs).
 *
 * Idempotent — subsequent calls return the same promise that was created on
 * the first call.  This guarantees the tests run exactly once per page load
 * regardless of how many modules import this function.
 *
 * @returns {Promise<SelfTestResult>}
 */
export async function runCryptoSelfTests() {
  if (!_postPromise) {
    _postPromise = _runAllTests();
  }
  return _postPromise;
}

/**
 * Assert that the crypto module is in READY state before performing any
 * cryptographic operation.  Must be awaited at the start of every
 * encrypt / decrypt / sign entry point.
 *
 * If the POST has not completed yet, this function waits for it.
 * If the module is in ERROR state, throws CryptoModuleError immediately.
 *
 * @throws {CryptoModuleError}
 */
export async function assertCryptoReady() {
  // Fast path — already ready.
  if (_state === "READY") return;

  // Wait for POST (start it if the page entry point forgot to).
  await runCryptoSelfTests();

  if (_state !== "READY") {
    const last = _failureLog.at(-1);
    throw new CryptoModuleError(
      last
        ? `Crypto module in error state [${last.cast}]: ${last.message}`
        : "Crypto module in error state (self-test failed)"
    );
  }
}

/**
 * Return the current module status and the structured failure log.
 *
 * @returns {{ state: 'INITIALIZING' | 'READY' | 'ERROR', failureLog: typeof _failureLog }}
 */
export function getModuleStatus() {
  return { state: _state, failureLog: [..._failureLog] };
}

/**
 * Per-suite verification status for toolkit badges / FIPS mode.
 *
 * @returns {import("./toolkit/suite-gate.js").SuiteStatusMap}
 */
export function getSuiteStatus() {
  /** @type {import("./toolkit/suite-gate.js").SuiteState} */
  const errOr = (ok) => {
    if (_state === "ERROR") return "error";
    return ok ? "verified" : "unverified";
  };
  const r = _lastResult?.results;
  const openpgpOk = !!(
    r?.keyGeneration &&
    r?.encryptDecrypt &&
    r?.signVerify &&
    r?.signedEncrypt &&
    r?.passwordArgon2
  );
  const webcryptoOk = !!(
    r?.digestKat &&
    r?.aesGcmRoundtrip &&
    r?.subtleSignVerify &&
    r?.ecdhAgree &&
    r?.hkdfKat &&
    r?.aesKwRoundtrip &&
    r?.aesCbcRoundtrip &&
    r?.aesCtrRoundtrip
  );
  const sssOk = !!r?.sssRoundtrip;
  return {
    openpgp: errOr(openpgpOk),
    webcrypto: errOr(webcryptoOk),
    sss: errOr(sssOk),
  };
}

/**
 * Assert a verification suite is ready (for FIPS hard gates).
 * @param {'openpgp'|'webcrypto'|'sss'} suite
 * @throws {CryptoModuleError}
 */
export async function assertSuiteReady(suite) {
  await assertCryptoReady();
  const status = getSuiteStatus();
  if (status[suite] !== "verified") {
    throw new CryptoModuleError(
      `Suite "${suite}" is not verified by POST/CAST (status=${status[suite]})`
    );
  }
}

/**
 * Human-readable labels for each CAST / self-test check.
 * @type {Record<keyof SelfTestResults, string>}
 */
export const SELF_TEST_LABELS = {
  keyGeneration: "CAST-1: Key generation (Curve25519 / Ed25519)",
  encryptDecrypt: "CAST-2: Asymmetric encrypt + decrypt (ECDH + AES-OCB/GCM)",
  signVerify: "CAST-3: Detached signature + verification (Ed25519 + SHA-512)",
  signedEncrypt: "CAST-4: Signed + encrypted combined",
  passwordArgon2: "CAST-5: Password encrypt + decrypt (Argon2 + WASM)",
  digestKat: "CAST-6: Digest KAT (SHA-256)",
  aesGcmRoundtrip: "CAST-7: AES-GCM roundtrip",
  subtleSignVerify: "CAST-8: Ed25519 sign + verify (WebCrypto)",
  ecdhAgree: "CAST-9: ECDH P-256 agree",
  hkdfKat: "CAST-10: HKDF-SHA-256 KAT",
  aesKwRoundtrip: "CAST-11: AES-KW wrap + unwrap",
  sssRoundtrip: "CAST-12: SSS split/combine + BLIP39 roundtrip",
  aesCbcRoundtrip: "CAST-13: AES-CBC roundtrip",
  aesCtrRoundtrip: "CAST-14: AES-CTR roundtrip",
};

/**
 * Suite-aware operator banner (toolkit).
 * @param {SelfTestResult} [result]
 * @returns {string}
 */
export function formatSuiteStatusMessage(result) {
  const status = getSuiteStatus();
  const mark = (s) =>
    s === "verified" ? "✓" : s === "error" ? "✖" : "⚠";
  const ms = Number(result?.elapsed) || Number(_lastResult?.elapsed) || 0;
  const root = result?.moduleIntegrity?.root || _lastResult?.moduleIntegrity?.root || "";
  const short = shortModuleRoot(root, 16);
  const leafCount =
    result?.moduleIntegrity?.leafCount ||
    _lastResult?.moduleIntegrity?.leafCount ||
    0;
  const pin = result?.moduleIntegrity?.pin || _lastResult?.moduleIntegrity?.pin;
  let msg = `OpenPGP ${mark(status.openpgp)} · WebCrypto ${mark(status.webcrypto)} · SSS ${mark(status.sss)}`;
  if (ms) msg += ` · ${ms} ms`;
  if (short) {
    msg += ` · modules ${short}`;
    if (leafCount > 0) msg += ` (${leafCount} leaf${leafCount === 1 ? "" : "es"})`;
  }
  if (pin?.matched) {
    msg += ` · pin ok`;
    if (pin.fetched > 1) msg += `×${pin.fetched}`;
  }
  return msg + ".";
}

/**
 * OpenPGP-focused success line for encrypt / decrypt pages.
 * @param {SelfTestResult} result
 * @returns {string}
 */
export function formatOpenPgpVerifiedMessage(result) {
  const ms = Number(result.elapsed) || 0;
  const root = result.moduleIntegrity?.root || "";
  const short = shortModuleRoot(root, 16);
  const leafCount = result.moduleIntegrity?.leafCount || 0;
  const pin = result.moduleIntegrity?.pin;
  let msg = `OpenPGP verified (${ms} ms) — CAST-1…5 passed`;
  if (short) {
    msg += ` · modules ${short}`;
    if (leafCount > 0) msg += ` (${leafCount} leaf${leafCount === 1 ? "" : "es"})`;
  }
  if (pin?.matched) {
    msg += ` · pin ok`;
    if (pin.fetched > 1) msg += `×${pin.fetched}`;
  }
  return msg + ".";
}

/**
 * @deprecated Prefer formatSuiteStatusMessage or formatOpenPgpVerifiedMessage.
 * @param {SelfTestResult} result
 * @returns {string}
 */
export function formatCryptoVerifiedMessage(result) {
  return formatSuiteStatusMessage(result);
}

// ── JSDoc types ───────────────────────────────────────────────────────────────

/**
 * @typedef {{
 *   keyGeneration: boolean,
 *   encryptDecrypt: boolean,
 *   signVerify: boolean,
 *   signedEncrypt: boolean,
 *   passwordArgon2: boolean,
 *   digestKat: boolean,
 *   aesGcmRoundtrip: boolean,
 *   subtleSignVerify: boolean,
 *   ecdhAgree: boolean,
 *   hkdfKat: boolean,
 *   aesKwRoundtrip: boolean,
 *   aesCbcRoundtrip: boolean,
 *   aesCtrRoundtrip: boolean,
 *   sssRoundtrip: boolean,
 * }} SelfTestResults
 * @typedef {{ root: string, leafCount: number, source: "sri" | "self" | "none", pin?: * }} ModuleIntegrity
 * @typedef {{ passed: boolean, results: SelfTestResults, elapsed: number, error?: string, moduleIntegrity?: ModuleIntegrity }} SelfTestResult
 */
