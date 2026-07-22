/**
 * Basilisk crypto self-test module.
 *
 * Implements a FIPS 140-3-inspired Pre-Operational Self-Test (POST) and
 * per-algorithm Conditional Algorithm Self-Tests (CASTs) for OpenPGP.js.
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
 *   a late gate.  The four CASTs mirror the four distinct algorithm paths:
 *
 *     CAST-1  Key generation (Curve25519 / X25519 / Ed25519)
 *     CAST-2  Asymmetric encrypt + decrypt (ECDH + AES-OCB or AES-GCM)
 *     CAST-3  Detached digital signature + verification (Ed25519 + SHA-512)
 *     CAST-4  Signed + encrypted combined message
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
 * ── Module integrity (SRI) ──────────────────────────────────────────────────
 *   FIPS 140-3 treats startup integrity as code-signing / verified load.
 *   In the browser this is Subresource Integrity enforced by the UA:
 *     · Entry scripts, styles, and modulepreloads carry integrity= (sha384)
 *       from vite-plugin-sri-gen.
 *     · Lazy chunks, dynamic import(), and module workers are covered by an
 *       external import map at /importmaps/importmap-*.json (also SRI’d),
 *       externalized post-build so CSP can stay script-src 'self'.
 *     · On hash mismatch the browser refuses to execute the module — fail
 *       closed on CDN cache skew (old chunk + new HTML) or tampering.
 *   This file’s algorithm POST does not re-hash CDN bytes; packaging lives in
 *   web/scripts/externalize-importmaps.js and scripts/package-static.sh.
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
  generateKey,
  readMessage,
  readSignature,
  sign,
  verify,
} from "openpgp";
import { zeroKeyMaterial } from "./pgp/memory.js";

// ── Module state ─────────────────────────────────────────────────────────────

/** @type {'INITIALIZING' | 'READY' | 'ERROR'} */
let _state = "INITIALIZING";

/** @type {Array<{ timestamp: string, phase: string, cast: string, message: string }>} */
let _failureLog = [];

/** Singleton promise for the POST run — prevents double-execution. */
let _postPromise = null;

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
 * Run all four CASTs and populate the module result.
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

    // ── Zeroization ───────────────────────────────────────────────────────
    // Best-effort: zero ephemeral private-key material as soon as the tests
    // have passed.  This reduces the window during which a GC dump could
    // expose the test key.
    zeroKeyMaterial(privateKey);
    privateKey = null;

    _state = "READY";
    return { passed: true, results, elapsed: Date.now() - t0 };
  } catch (err) {
    // Identify which CAST failed for the log entry.
    const castMap = {
      keyGeneration: "CAST-1",
      encryptDecrypt: "CAST-2",
      signVerify: "CAST-3",
      signedEncrypt: "CAST-4",
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
    return { passed: false, error: msg, results, elapsed: Date.now() - t0 };
  }
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

  // If POST is running (or hasn't been started), wait for it.
  if (_postPromise) {
    await _postPromise;
  }

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
 * Human-readable labels for each CAST / self-test check.
 * @type {Record<keyof SelfTestResults, string>}
 */
export const SELF_TEST_LABELS = {
  keyGeneration: "CAST-1: Key generation (Curve25519 / Ed25519)",
  encryptDecrypt: "CAST-2: Asymmetric encrypt + decrypt (ECDH + AES-OCB/GCM)",
  signVerify: "CAST-3: Detached signature + verification (Ed25519 + SHA-512)",
  signedEncrypt: "CAST-4: Signed + encrypted combined",
};

// ── JSDoc types ───────────────────────────────────────────────────────────────

/**
 * @typedef {{ keyGeneration: boolean, encryptDecrypt: boolean, signVerify: boolean, signedEncrypt: boolean }} SelfTestResults
 * @typedef {{ passed: boolean, results: SelfTestResults, elapsed: number, error?: string }} SelfTestResult
 */
