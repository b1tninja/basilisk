/**
 * Vitest: passphrase strength estimator.
 */

import { describe, expect, it } from "vitest";
import { estimatePassphraseStrength } from "../lib/pgp/passphrase.js";

describe("passphrase strength", () => {
  it("labels empty input", () => {
    const e = estimatePassphraseStrength("");
    expect(e.label).toBe("empty");
    expect(e.bits).toBe(0);
  });

  it("flags common / short passwords as weak", () => {
    expect(estimatePassphraseStrength("password").label).toBe("weak");
    expect(estimatePassphraseStrength("hunter2").label).toBe("weak");
    expect(estimatePassphraseStrength("aaaa").label).toBe("weak");
  });

  it("rates a long mixed passphrase as strong", () => {
    const e = estimatePassphraseStrength("correct-horse-battery-staple-9X!");
    expect(e.bits).toBeGreaterThanOrEqual(50);
    expect(e.label).toBe("strong");
  });

  it("rates medium length mixed as at least fair", () => {
    const e = estimatePassphraseStrength("Tr0ub4dor&3-extra");
    expect(["fair", "strong"]).toContain(e.label);
    expect(e.bits).toBeGreaterThanOrEqual(35);
  });
});
