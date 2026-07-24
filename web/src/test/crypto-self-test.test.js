/**
 * Vitest suite for the Basilisk crypto self-test module.
 *
 * These tests run in Node.js (OpenPGP.js is isomorphic) and serve as CI
 * verification that the library is importable, functional, and produces
 * correct outputs for all CAST operations:
 *   CAST-1  Key generation (Curve25519 / Ed25519)
 *   CAST-2  Asymmetric encrypt + decrypt
 *   CAST-3  Detached signature + verification
 *   CAST-4  Signed + encrypted combined
 *   CAST-5  Password encrypt + decrypt (Argon2)
 *
 * Also verifies the module-state management (READY/ERROR) and the
 * assertCryptoReady() / getModuleStatus() public API.
 *
 * Run with: npm test   (from the web/ directory)
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// NOTE: vitest re-uses module instances across tests in the same file.
// We import the module once; the singleton _postPromise persists between
// test cases (by design — simulating a real page lifecycle).  The "already
// READY" tests below rely on that caching behaviour.
import {
  CryptoModuleError,
  SELF_TEST_LABELS,
  assertCryptoReady,
  formatCryptoVerifiedMessage,
  getModuleStatus,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";

describe("crypto-self-test — SELF_TEST_LABELS", () => {
  it("exports labels for all CAST checks", () => {
    const keys = Object.keys(SELF_TEST_LABELS);
    expect(keys).toContain("keyGeneration");
    expect(keys).toContain("encryptDecrypt");
    expect(keys).toContain("signVerify");
    expect(keys).toContain("signedEncrypt");
    expect(keys).toContain("passwordArgon2");
  });

  it("labels include CAST identifiers", () => {
    expect(SELF_TEST_LABELS.keyGeneration).toMatch(/CAST-1/);
    expect(SELF_TEST_LABELS.encryptDecrypt).toMatch(/CAST-2/);
    expect(SELF_TEST_LABELS.signVerify).toMatch(/CAST-3/);
    expect(SELF_TEST_LABELS.signedEncrypt).toMatch(/CAST-4/);
    expect(SELF_TEST_LABELS.passwordArgon2).toMatch(/CAST-5/);
  });
});

describe("crypto-self-test — runCryptoSelfTests", () => {
  it("passes all CAST checks in a healthy environment", async () => {
    const result = await runCryptoSelfTests();

    expect(
      result.passed,
      `Self-test failed: ${result.error ?? JSON.stringify(result.results)}`
    ).toBe(true);

    expect(result.results.keyGeneration, "CAST-1 keyGeneration").toBe(true);
    expect(result.results.encryptDecrypt, "CAST-2 encryptDecrypt").toBe(true);
    expect(result.results.signVerify, "CAST-3 signVerify").toBe(true);
    expect(result.results.signedEncrypt, "CAST-4 signedEncrypt").toBe(true);
    expect(result.results.passwordArgon2, "CAST-5 passwordArgon2").toBe(true);

    // Argon2 + WASM can be slower; stay within vitest's default budget
    expect(result.elapsed).toBeLessThan(20_000);
    expect(result.error).toBeUndefined();
    expect(result.moduleIntegrity).toBeTruthy();
    expect(typeof result.moduleIntegrity.root).toBe("string");
  });

  it("is idempotent — subsequent calls return the same cached result", async () => {
    const first = await runCryptoSelfTests();
    const second = await runCryptoSelfTests();
    // Strict equality: same object reference from the cached promise
    expect(first).toBe(second);
  });

  it("formatCryptoVerifiedMessage includes module root when present", async () => {
    const result = await runCryptoSelfTests();
    const msg = formatCryptoVerifiedMessage(result);
    expect(msg).toMatch(/Crypto module verified/);
    expect(msg).toMatch(/checks passed/);
    if (result.moduleIntegrity?.root) {
      expect(msg).toMatch(/modules [0-9a-f]{16}/);
    }
  });
});

describe("crypto-self-test — module state", () => {
  it("reports READY state after a successful POST", async () => {
    await runCryptoSelfTests();
    const { state, failureLog } = getModuleStatus();
    expect(state).toBe("READY");
    expect(failureLog).toHaveLength(0);
  });

  it("assertCryptoReady resolves without throwing in READY state", async () => {
    await runCryptoSelfTests();
    await expect(assertCryptoReady()).resolves.toBeUndefined();
  });
});

describe("crypto-self-test — CryptoModuleError", () => {
  it("is an Error subclass with the correct name", () => {
    const err = new CryptoModuleError("test");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("CryptoModuleError");
    expect(err.message).toBe("test");
  });
});
