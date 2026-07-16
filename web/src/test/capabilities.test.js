/**
 * Vitest: SEIPDv2 capability detection.
 */

import { describe, expect, it } from "vitest";
import { config, generateKey } from "openpgp";
import { supportsSeipdV2 } from "../lib/pgp/capabilities.js";

async function keyWithAead(flag) {
  const prev = config.aeadProtect;
  config.aeadProtect = flag;
  try {
    return await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: "Cap Test", email: "cap@example.com" }],
      format: "object",
    });
  } finally {
    config.aeadProtect = prev;
  }
}

describe("capabilities", () => {
  it("detects SEIPDv2 feature on keys generated with aeadProtect", async () => {
    const { publicKey } = await keyWithAead(true);
    expect(await supportsSeipdV2(publicKey)).toBe(true);
  });

  it("returns false for legacy keys without seipdv2 feature", async () => {
    const { publicKey } = await keyWithAead(false);
    expect(await supportsSeipdV2(publicKey)).toBe(false);
  });

  it("returns false for null/undefined", async () => {
    expect(await supportsSeipdV2(null)).toBe(false);
    expect(await supportsSeipdV2(undefined)).toBe(false);
  });
});
