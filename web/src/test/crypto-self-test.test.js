/**
 * Vitest suite for the Basilisk crypto self-test module.
 *
 * These tests run in Node.js (OpenPGP.js is isomorphic) and serve as CI
 * verification that the library is importable, functional, and produces
 * correct outputs for all four CAST operations:
 *   CAST-1  Key generation (Curve25519 / Ed25519)
 *   CAST-2  Asymmetric encrypt + decrypt
 *   CAST-3  Detached signature + verification
 *   CAST-4  Signed + encrypted combined
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
  getModuleStatus,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";

describe("crypto-self-test — SELF_TEST_LABELS", () => {
  it("exports labels for all four CAST checks", () => {
    const keys = Object.keys(SELF_TEST_LABELS);
    expect(keys).toContain("keyGeneration");
    expect(keys).toContain("encryptDecrypt");
    expect(keys).toContain("signVerify");
    expect(keys).toContain("signedEncrypt");
  });

  it("labels include CAST identifiers", () => {
    expect(SELF_TEST_LABELS.keyGeneration).toMatch(/CAST-1/);
    expect(SELF_TEST_LABELS.encryptDecrypt).toMatch(/CAST-2/);
    expect(SELF_TEST_LABELS.signVerify).toMatch(/CAST-3/);
    expect(SELF_TEST_LABELS.signedEncrypt).toMatch(/CAST-4/);
  });
});

describe("crypto-self-test — runCryptoSelfTests", () => {
  it("passes all four CAST checks in a healthy environment", async () => {
    const result = await runCryptoSelfTests();

    expect(
      result.passed,
      `Self-test failed: ${result.error ?? JSON.stringify(result.results)}`
    ).toBe(true);

    expect(result.results.keyGeneration, "CAST-1 keyGeneration").toBe(true);
    expect(result.results.encryptDecrypt, "CAST-2 encryptDecrypt").toBe(true);
    expect(result.results.signVerify, "CAST-3 signVerify").toBe(true);
    expect(result.results.signedEncrypt, "CAST-4 signedEncrypt").toBe(true);

    // Should complete well within the 20 s vitest timeout
    expect(result.elapsed).toBeLessThan(10_000);
    expect(result.error).toBeUndefined();
  });

  it("is idempotent — subsequent calls return the same cached result", async () => {
    const first = await runCryptoSelfTests();
    const second = await runCryptoSelfTests();
    // Strict equality: same object reference from the cached promise
    expect(first).toBe(second);
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
