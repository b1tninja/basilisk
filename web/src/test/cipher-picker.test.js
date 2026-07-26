import { describe, expect, it } from "vitest";
import {
  CIPHER_PICKER_ALIASES,
  getStep,
  instantiateCipherPick,
  listCipherPickerSteps,
} from "../lib/toolkit/registry.js";
import { CIPHER_DISPATCH_TARGETS } from "../lib/toolkit/step-names.js";

describe("cipher meta-picker catalog", () => {
  it("lists only WebCrypto dispatch targets in shelf order", () => {
    const names = listCipherPickerSteps().map((s) => s.name);
    expect(names).toEqual([
      "aes-gcm",
      "aes-cbc",
      "aes-ctr",
      "rsa-oaep",
      "rsa-pkcs1",
    ]);
    for (const n of names) {
      expect(CIPHER_DISPATCH_TARGETS.has(n)).toBe(true);
      expect(getStep(n)?.toolbox).toBe("webcrypto");
    }
  });

  it("exposes JCE / sized alias hints per pick", () => {
    expect(CIPHER_PICKER_ALIASES["aes-gcm"]).toContain("AES/GCM/NoPadding");
    expect(CIPHER_PICKER_ALIASES["rsa-oaep"]?.[0]).toMatch(/OAEP/i);
  });

  it("instantiateCipherPick returns concrete name + decode, never encrypt", () => {
    expect(instantiateCipherPick("aes-gcm", false)).toEqual({
      name: "aes-gcm",
      params: {},
    });
    expect(instantiateCipherPick("aes-gcm", true)).toEqual({
      name: "aes-gcm",
      params: { decode: true },
    });
    expect(instantiateCipherPick("RSA-OAEP", true).name).toBe("rsa-oaep");
    expect(() => instantiateCipherPick("encrypt", false)).toThrow(/Unknown cipher/);
    expect(() => instantiateCipherPick("gpg.encrypt", false)).toThrow(
      /Unknown cipher/
    );
  });
});
