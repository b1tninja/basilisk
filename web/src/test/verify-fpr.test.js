import { describe, expect, it } from "vitest";
import {
  compareFingerprints,
  normalizeFingerprintInput,
  normalizeSearchQuery,
} from "../lib/pgp/verify-fpr.js";

describe("verify-fpr", () => {
  it("normalizes openpgp4fpr URIs and spaced hex", () => {
    expect(
      normalizeFingerprintInput("openpgp4fpr:abb3a7283d5ee084295cf439fdba0d5445aa8148")
    ).toBe("ABB3A7283D5EE084295CF439FDBA0D5445AA8148");
    expect(
      normalizeFingerprintInput("ABB3 A728 3D5E E084 295C F439 FDBA 0D54 45AA 8148")
    ).toBe("ABB3A7283D5EE084295CF439FDBA0D5445AA8148");
  });

  it("PASS when fingerprints match", () => {
    const fpr = "ABB3A7283D5EE084295CF439FDBA0D5445AA8148";
    const r = compareFingerprints(fpr, `openpgp4fpr:${fpr.toLowerCase()}`);
    expect(r.ok).toBe(true);
  });

  it("FAIL on mismatch", () => {
    const r = compareFingerprints(
      "ABB3A7283D5EE084295CF439FDBA0D5445AA8148",
      "0000000000000000000000000000000000000000"
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/do not match/i);
  });

  it("normalizeSearchQuery strips spaces from fingerprints", () => {
    expect(
      normalizeSearchQuery("ABB3 A728 3D5E E084 295C F439 FDBA 0D54 45AA 8148")
    ).toBe("ABB3A7283D5EE084295CF439FDBA0D5445AA8148");
    expect(normalizeSearchQuery("alice@example.com")).toBe("alice@example.com");
    expect(normalizeSearchQuery("Alice Example")).toBe("Alice Example");
  });
});
