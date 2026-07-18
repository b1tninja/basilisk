/**
 * Vitest: encrypt intent summaries, deprecation notices, preference parsing.
 */

import { describe, expect, it } from "vitest";
import { config, generateKey } from "openpgp";
import {
  describeEncryptIntent,
  describeProfileDivergence,
  formatProfileSpec,
} from "../lib/pgp/encrypt-intent.js";
import {
  PROFILE_COMPATIBLE,
  PROFILE_MODERN,
} from "../lib/pgp/encrypt.js";
import { collectDeprecationWarnings } from "../lib/pgp/deprecation.js";
import { readKeyPreferences } from "../lib/pgp/preferences.js";

describe("encrypt-intent", () => {
  it("formatProfileSpec uses concrete algorithm names", () => {
    expect(formatProfileSpec(PROFILE_COMPATIBLE)).toBe(
      "AES-256 · SEIPD v1 (CFB+MDC) · iterated S2K"
    );
    expect(formatProfileSpec(PROFILE_MODERN)).toBe(
      "AES-256 · OCB · SEIPD v2 · Argon2"
    );
  });

  it("describeEncryptIntent reflects modern when all recipients capable", () => {
    const intent = describeEncryptIntent(PROFILE_MODERN, {
      hasKeys: true,
      hasPassphrase: false,
      allModern: true,
      totalKeys: 2,
      legacyCount: 0,
    });
    expect(intent.useAead).toBe(true);
    expect(intent.degraded).toBe(false);
    expect(intent.summary).toContain("OCB");
    expect(intent.summary).toContain("SEIPD v2");
  });

  it("describeEncryptIntent degrades when any recipient lacks SEIPDv2", () => {
    const intent = describeEncryptIntent(PROFILE_MODERN, {
      hasKeys: true,
      hasPassphrase: true,
      allModern: false,
      totalKeys: 2,
      legacyCount: 1,
    });
    expect(intent.useAead).toBe(false);
    expect(intent.degraded).toBe(true);
    expect(intent.summary).toContain("SEIPD v1");
    expect(intent.summary).toContain("Argon2");
    expect(intent.note).toMatch(/1 of 2/);
  });

  it("describeProfileDivergence flags custom cipher", () => {
    const d = describeProfileDivergence({
      cipher: "aes128",
      aead: "ocb",
      compression: "uncompressed",
      s2k: "argon2",
    });
    expect(d.preset).toBe("custom");
    expect(d.explanation).toMatch(/AES-128/);
    expect(d.explanation).toMatch(/Modern/);
  });

  it("describeProfileDivergence matches named presets", () => {
    expect(describeProfileDivergence(PROFILE_COMPATIBLE).preset).toBe("compatible");
    expect(describeProfileDivergence(PROFILE_MODERN).preset).toBe("modern");
  });
});

describe("deprecation", () => {
  it("warns for EdDSA legacy / ElGamal / DSA / SHA-1", () => {
    const warnings = collectDeprecationWarnings({
      primary: { algorithm: "eddsaLegacy", curve: "ed25519Legacy" },
      subkeys: [{ algorithm: "elgamal" }],
      hashAlgorithm: 2,
    });
    expect(warnings.some((w) => /EdDSA Legacy/i.test(w))).toBe(true);
    expect(warnings.some((w) => /ElGamal/i.test(w))).toBe(true);
    expect(warnings.some((w) => /SHA-1/i.test(w))).toBe(true);

    const dsa = collectDeprecationWarnings({
      primary: { algorithm: "dsa" },
    });
    expect(dsa.some((w) => /DSA/i.test(w))).toBe(true);
  });

  it("is silent for modern algorithms", () => {
    const warnings = collectDeprecationWarnings({
      primary: { algorithm: "ed25519" },
      hashAlgorithm: 10,
    });
    expect(warnings).toEqual([]);
  });
});

describe("preferences", () => {
  it("reads preference subpackets from a generated key", async () => {
    const prev = config.aeadProtect;
    config.aeadProtect = true;
    try {
      const { publicKey } = await generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        userIDs: [{ name: "Prefs", email: "prefs@example.com" }],
        format: "object",
      });
      const prefs = await readKeyPreferences(publicKey);
      expect(prefs.symmetric.length).toBeGreaterThan(0);
      expect(prefs.hash.length).toBeGreaterThan(0);
      expect(prefs.compression.length).toBeGreaterThan(0);
      expect(typeof prefs.noModify).toBe("boolean");
    } finally {
      config.aeadProtect = prev;
    }
  });
});
