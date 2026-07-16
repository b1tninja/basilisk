/**
 * Basilisk crypto self-test module.
 *
 * Runs a keygen + encrypt/decrypt + sign/verify roundtrip with an ephemeral
 * Curve25519 key pair to verify that OpenPGP.js is loaded and functional.
 * Called at page startup by decrypt.js and compose.js; also imported by
 * vitest for CI coverage (src/test/crypto-self-test.test.js).
 *
 * Memory-protection note: JS engines do not expose deterministic memory
 * management to userland — we cannot guarantee that zeroing a Uint8Array
 * actually erases all copies the engine may have made during JIT compilation
 * or GC compaction. The best-effort mitigations available are:
 *   1. Strict CSP + SRI (already enforced) — blocks XSS key exfiltration.
 *   2. Zeroing Uint8Array secret-key buffers immediately after use.
 *   3. Clearing DOM fields so devtools / extensions can't read them.
 *   4. Short key lifetime — parse, use, wipe in a single async scope.
 *   5. beforeunload warning — prevents accidental tab close with key in DOM.
 * True OS-level memory protection (e.g. mlock) is not available in browsers.
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

const SELF_TEST_UID = [{ name: "Basilisk Self-Test", email: "selftest@basilisk.invalid" }];

/**
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

/**
 * Run all self-tests.
 * @returns {Promise<{
 *   passed: boolean,
 *   results: { keyGeneration: boolean, encryptDecrypt: boolean, signVerify: boolean, signedEncrypt: boolean },
 *   error?: string,
 *   elapsed?: number,
 * }>}
 */
export async function runCryptoSelfTests() {
  const t0 = Date.now();
  const results = {
    keyGeneration: false,
    encryptDecrypt: false,
    signVerify: false,
    signedEncrypt: false,
  };

  try {
    // --- Test 1: key generation ---
    const { privateKey, publicKey } = await generateEphemeralKey();
    if (!privateKey || !publicKey) throw new Error("generateKey returned null");
    results.keyGeneration = true;

    const canary = `basilisk-canary-${Math.random().toString(36).slice(2, 10)}`;

    // --- Test 2: encrypt / decrypt roundtrip ---
    const plainMsg = await createMessage({ text: canary });
    const ciphertext = await encrypt({ message: plainMsg, encryptionKeys: publicKey });
    const { data: decrypted } = await decrypt({
      message: await readMessage({ armoredMessage: ciphertext }),
      decryptionKeys: privateKey,
    });
    if (decrypted !== canary) throw new Error(`Decrypt mismatch: got ${JSON.stringify(decrypted)}`);
    results.encryptDecrypt = true;

    // --- Test 3: detached sign / verify ---
    const detachedSig = await sign({
      message: await createMessage({ text: canary }),
      signingKeys: privateKey,
      detached: true,
    });
    const verifyResult = await verify({
      message: await createMessage({ text: canary }),
      signature: await readSignature({ armoredSignature: detachedSig }),
      verificationKeys: publicKey,
    });
    await verifyResult.signatures[0].verified; // throws on invalid signature
    results.signVerify = true;

    // --- Test 4: signed + encrypted combined ---
    const combined = await encrypt({
      message: await createMessage({ text: canary }),
      encryptionKeys: publicKey,
      signingKeys: privateKey,
    });
    const { data: decCombined, signatures } = await decrypt({
      message: await readMessage({ armoredMessage: combined }),
      decryptionKeys: privateKey,
      verificationKeys: publicKey,
    });
    if (decCombined !== canary) throw new Error("Combined decrypt mismatch");
    await signatures[0].verified;
    results.signedEncrypt = true;

    return { passed: true, results, elapsed: Date.now() - t0 };
  } catch (err) {
    return {
      passed: false,
      error: err?.message || String(err),
      results,
      elapsed: Date.now() - t0,
    };
  }
}

/**
 * Names of the self-test checks, for display.
 * @type {Record<keyof ReturnType<typeof runCryptoSelfTests> extends Promise<infer T> ? T['results'] : never, string>}
 */
export const SELF_TEST_LABELS = {
  keyGeneration: "Key generation (Curve25519)",
  encryptDecrypt: "Encrypt / decrypt roundtrip",
  signVerify: "Detached sign / verify",
  signedEncrypt: "Signed + encrypted combined",
};
