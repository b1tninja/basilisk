/**
 * FIPS mode preference helpers.
 */
import { describe, expect, it } from "vitest";
import {
  FIPS_MODE_DISCLAIMER,
  FIPS_MODE_STORAGE_KEY,
  getFipsMode,
  setFipsMode,
} from "../lib/fips-mode.js";

describe("fips-mode", () => {
  it("defaults off and persists in memory", () => {
    setFipsMode(false);
    expect(getFipsMode()).toBe(false);
    setFipsMode(true);
    expect(getFipsMode()).toBe(true);
    setFipsMode(false);
    expect(getFipsMode()).toBe(false);
  });

  it("exports a non-certification disclaimer", () => {
    expect(FIPS_MODE_DISCLAIMER).toMatch(/Not a FIPS 140/);
    expect(FIPS_MODE_STORAGE_KEY).toBe("basilisk.fipsMode");
  });
});
