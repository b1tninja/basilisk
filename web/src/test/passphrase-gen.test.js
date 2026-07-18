import { describe, expect, it } from "vitest";
import {
  BITS_PER_WORD,
  WORDLIST,
  generateCharPassphrase,
  generateWordPassphrase,
} from "../lib/passphrase-gen.js";

describe("EFF large wordlist", () => {
  it("has exactly 7776 entries (6^5, standard diceware size)", () => {
    expect(WORDLIST.length).toBe(7776);
  });

  it("has no duplicates", () => {
    expect(new Set(WORDLIST).size).toBe(7776);
  });

  it("matches known EFF entries (first, last)", () => {
    expect(WORDLIST[0]).toBe("abacus");
    expect(WORDLIST[7775]).toBe("zoom");
  });

  it("contains only lowercase words (no dice numbers leaked from parsing)", () => {
    for (const w of WORDLIST) {
      expect(w).toMatch(/^[a-z-]+$/);
    }
  });

  it("reports ~12.9 bits per word", () => {
    expect(BITS_PER_WORD).toBeCloseTo(12.925, 2);
  });
});

describe("generateWordPassphrase", () => {
  it("produces six EFF words by default (~77 bits, EFF recommendation)", () => {
    const { passphrase, bits, words } = generateWordPassphrase();
    expect(words).toBe(6);
    expect(bits).toBe(77);
    // Default separator is "-"; a few EFF words also contain "-" (e.g. t-shirt),
    // so do not split the passphrase on that character to count words.
    expect(passphrase).toContain("-");

    // Verify membership with a separator that cannot appear in the wordlist.
    const { passphrase: joined } = generateWordPassphrase(6, "\u0001");
    const parts = joined.split("\u0001");
    expect(parts.length).toBe(6);
    for (const p of parts) {
      expect(WORDLIST).toContain(p);
    }
  });

  it("clamps word count to [4, 12]", () => {
    expect(generateWordPassphrase(1).words).toBe(4);
    expect(generateWordPassphrase(99).words).toBe(12);
  });

  it("supports a custom separator", () => {
    const { passphrase } = generateWordPassphrase(5, " ");
    expect(passphrase.split(" ").length).toBe(5);
  });

  it("does not repeat across invocations (overwhelming probability)", () => {
    const seen = new Set();
    for (let i = 0; i < 50; i++) {
      seen.add(generateWordPassphrase(6).passphrase);
    }
    expect(seen.size).toBe(50);
  });
});

describe("generateCharPassphrase", () => {
  it("produces the requested length with sane entropy", () => {
    const { passphrase, bits, length } = generateCharPassphrase(20);
    expect(passphrase.length).toBe(20);
    expect(length).toBe(20);
    expect(bits).toBeGreaterThanOrEqual(110); // 20 * log2(69) ≈ 122
  });

  it("clamps length to [12, 64]", () => {
    expect(generateCharPassphrase(3).length).toBe(12);
    expect(generateCharPassphrase(999).length).toBe(64);
  });

  it("avoids ambiguous characters", () => {
    for (let i = 0; i < 20; i++) {
      const { passphrase } = generateCharPassphrase(32);
      expect(passphrase).not.toMatch(/[lI1O0]/);
    }
  });
});
