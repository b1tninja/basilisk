/**
 * Vitest suite for the Basilisk crypto self-test module.
 *
 * These tests run in Node.js (OpenPGP.js is isomorphic) and serve as CI
 * verification that the library is importable, functional, and produces
 * correct outputs for all CAST operations:
 *   CAST-1…5   OpenPGP
 *   CAST-6…11  WebCrypto
 *
 * Also verifies module-state management, suite status, and assertCryptoReady().
 *
 * Run with: npm test   (from the web/ directory)
 */

import { describe, expect, it } from "vitest";

import {
  CryptoModuleError,
  SELF_TEST_LABELS,
  assertCryptoReady,
  assertSuiteReady,
  formatCryptoVerifiedMessage,
  formatOpenPgpVerifiedMessage,
  formatSuiteStatusMessage,
  getModuleStatus,
  getSuiteStatus,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import { assertRecipeAllowedUnderFips } from "../lib/toolkit/suite-gate.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("crypto-self-test — SELF_TEST_LABELS", () => {
  it("exports labels for all CAST checks", () => {
    const keys = Object.keys(SELF_TEST_LABELS);
    expect(keys).toContain("keyGeneration");
    expect(keys).toContain("encryptDecrypt");
    expect(keys).toContain("signVerify");
    expect(keys).toContain("signedEncrypt");
    expect(keys).toContain("passwordArgon2");
    expect(keys).toContain("digestKat");
    expect(keys).toContain("aesGcmRoundtrip");
    expect(keys).toContain("subtleSignVerify");
    expect(keys).toContain("ecdhAgree");
    expect(keys).toContain("hkdfKat");
    expect(keys).toContain("aesKwRoundtrip");
    expect(keys).toContain("aesCbcRoundtrip");
    expect(keys).toContain("aesCtrRoundtrip");
    expect(keys).toContain("sssRoundtrip");
  });

  it("labels include CAST identifiers", () => {
    expect(SELF_TEST_LABELS.keyGeneration).toMatch(/CAST-1/);
    expect(SELF_TEST_LABELS.encryptDecrypt).toMatch(/CAST-2/);
    expect(SELF_TEST_LABELS.signVerify).toMatch(/CAST-3/);
    expect(SELF_TEST_LABELS.signedEncrypt).toMatch(/CAST-4/);
    expect(SELF_TEST_LABELS.passwordArgon2).toMatch(/CAST-5/);
    expect(SELF_TEST_LABELS.digestKat).toMatch(/CAST-6/);
    expect(SELF_TEST_LABELS.aesGcmRoundtrip).toMatch(/CAST-7/);
    expect(SELF_TEST_LABELS.subtleSignVerify).toMatch(/CAST-8/);
    expect(SELF_TEST_LABELS.ecdhAgree).toMatch(/CAST-9/);
    expect(SELF_TEST_LABELS.hkdfKat).toMatch(/CAST-10/);
    expect(SELF_TEST_LABELS.aesKwRoundtrip).toMatch(/CAST-11/);
    expect(SELF_TEST_LABELS.sssRoundtrip).toMatch(/CAST-12/);
    expect(SELF_TEST_LABELS.aesCbcRoundtrip).toMatch(/CAST-13/);
    expect(SELF_TEST_LABELS.aesCtrRoundtrip).toMatch(/CAST-14/);
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
    expect(result.results.digestKat, "CAST-6 digestKat").toBe(true);
    expect(result.results.aesGcmRoundtrip, "CAST-7 aesGcmRoundtrip").toBe(true);
    expect(result.results.subtleSignVerify, "CAST-8 subtleSignVerify").toBe(true);
    expect(result.results.ecdhAgree, "CAST-9 ecdhAgree").toBe(true);
    expect(result.results.hkdfKat, "CAST-10 hkdfKat").toBe(true);
    expect(result.results.aesKwRoundtrip, "CAST-11 aesKwRoundtrip").toBe(true);
    expect(result.results.sssRoundtrip, "CAST-12 sssRoundtrip").toBe(true);
    expect(result.results.aesCbcRoundtrip, "CAST-13 aesCbcRoundtrip").toBe(true);
    expect(result.results.aesCtrRoundtrip, "CAST-14 aesCtrRoundtrip").toBe(true);

    expect(result.elapsed).toBeLessThan(20_000);
    expect(result.error).toBeUndefined();
    expect(result.moduleIntegrity).toBeTruthy();
    expect(typeof result.moduleIntegrity.root).toBe("string");
  });

  it("is idempotent — subsequent calls return the same cached result", async () => {
    const first = await runCryptoSelfTests();
    const second = await runCryptoSelfTests();
    expect(first).toBe(second);
  });

  it("formatSuiteStatusMessage is suite-aware", async () => {
    const result = await runCryptoSelfTests();
    const msg = formatSuiteStatusMessage(result);
    expect(msg).toMatch(/OpenPGP ✓/);
    expect(msg).toMatch(/WebCrypto ✓/);
    expect(msg).toMatch(/SSS ✓/);
    if (result.moduleIntegrity?.root) {
      expect(msg).toMatch(/modules [0-9a-f]{16}/);
    }
  });

  it("formatOpenPgpVerifiedMessage mentions OpenPGP CAST-1…5", async () => {
    const result = await runCryptoSelfTests();
    const msg = formatOpenPgpVerifiedMessage(result);
    expect(msg).toMatch(/OpenPGP verified/);
    expect(msg).toMatch(/CAST-1/);
  });

  it("formatCryptoVerifiedMessage aliases suite message", async () => {
    const result = await runCryptoSelfTests();
    expect(formatCryptoVerifiedMessage(result)).toBe(formatSuiteStatusMessage(result));
  });
});

describe("crypto-self-test — suite status", () => {
  it("reports openpgp + webcrypto + sss verified after POST", async () => {
    await runCryptoSelfTests();
    const status = getSuiteStatus();
    expect(status.openpgp).toBe("verified");
    expect(status.webcrypto).toBe("verified");
    expect(status.sss).toBe("verified");
  });

  it("assertSuiteReady allows openpgp, webcrypto, and sss", async () => {
    await runCryptoSelfTests();
    await expect(assertSuiteReady("openpgp")).resolves.toBeUndefined();
    await expect(assertSuiteReady("webcrypto")).resolves.toBeUndefined();
    await expect(assertSuiteReady("sss")).resolves.toBeUndefined();
  });

  it("FIPS gate allows SSS after CAST-12", async () => {
    await runCryptoSelfTests();
    const { ast } = compileRecipe("random 32 | sss.split threshold=2 shares=3 | hex");
    expect(() =>
      assertRecipeAllowedUnderFips(ast, getSuiteStatus(), true)
    ).not.toThrow();
  });

  it("FIPS gate allows WebCrypto after CAST-6…11", async () => {
    await runCryptoSelfTests();
    const { ast } = compileRecipe("random 16 | digest | hex");
    expect(() =>
      assertRecipeAllowedUnderFips(ast, getSuiteStatus(), true)
    ).not.toThrow();
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
