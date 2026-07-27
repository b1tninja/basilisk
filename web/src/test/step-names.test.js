import { describe, expect, it } from "vitest";
import {
  compileRecipe,
  migrateRecipe,
  parseRecipe,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";
import {
  decodeTwinToken,
  LEGACY_STEP_MIGRATE,
  resolveAlternateForm,
  resolveCipherTransform,
  resolveDecodeTwinVerb,
} from "../lib/toolkit/step-names.js";

describe("step name alternates", () => {
  it("maps OpenSSL-sized and JCE forms to canonical", () => {
    expect(resolveAlternateForm("aes-256-gcm")).toEqual({
      canonical: "aes-gcm",
      expectedKeyBits: 256,
    });
    expect(resolveAlternateForm("AES/GCM/NoPadding")?.canonical).toBe("aes-gcm");
    expect(resolveAlternateForm("RSA/ECB/PKCS1Padding")?.canonical).toBe("rsa-pkcs1");
  });

  it("parses alternates and serializes canonical", () => {
    const { ast, errors } = parseRecipe("random 16 | AES/GCM/NoPadding key=@k");
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.name).toBe("aes-gcm");
    expect(ast?.steps?.[1]?.params?.expectedKeyBits).toBeUndefined();
    const sized = parseRecipe("random 16 | aes-256-gcm key=@k");
    expect(sized.errors).toEqual([]);
    expect(sized.ast?.steps?.[1]?.name).toBe("aes-gcm");
    expect(sized.ast?.steps?.[1]?.params?.expectedKeyBits).toBe(256);
    expect(serializeRecipe(sized.ast)).toContain("aes-gcm");
    expect(serializeRecipe(sized.ast)).not.toContain("aes-256-gcm");
  });

  it("rejects Basilisk-legacy tokens with a migrator hint", () => {
    const { errors } = parseRecipe("random 16 | aesgcm");
    expect(errors.some((e) => /removed|aes-gcm/i.test(e.message))).toBe(true);
  });
});

describe("encrypt / decrypt cipher sugar", () => {
  it("resolveCipherTransform accepts JCE, sized, and hyphen forms", () => {
    expect(resolveCipherTransform("AES/GCM/NoPadding")?.canonical).toBe("aes-gcm");
    expect(resolveCipherTransform("aes-256-gcm")).toEqual({
      canonical: "aes-gcm",
      expectedKeyBits: 256,
    });
    expect(resolveCipherTransform("aes-gcm")?.canonical).toBe("aes-gcm");
    expect(resolveCipherTransform("digest")).toBeNull();
  });

  it("encrypt TRANSFORM rewrites to concrete aes-gcm and serializes hyphen", () => {
    const { ast, errors } = parseRecipe(
      "random 16 | encrypt AES/GCM/NoPadding key=@k"
    );
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.name).toBe("aes-gcm");
    expect(ast?.steps?.[1]?.params?.decode).toBeFalsy();
    expect(serializeRecipe(ast)).toContain("aes-gcm");
    expect(serializeRecipe(ast)).not.toMatch(/\bencrypt\b/);
  });

  it("decrypt sized transform sets decode + expectedKeyBits", () => {
    const { ast, errors } = parseRecipe(
      "random 16 | decrypt aes-256-gcm key=@k"
    );
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.name).toBe("aes-gcm");
    expect(ast?.steps?.[1]?.params?.decode).toBe(true);
    expect(ast?.steps?.[1]?.params?.expectedKeyBits).toBe(256);
    expect(serializeRecipe(ast)).toMatch(/aes-gcm\s+-d/);
  });

  it("encrypt -d before transform decrypts", () => {
    const { ast, errors } = parseRecipe("random 16 | encrypt -d aes-gcm key=@k");
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.name).toBe("aes-gcm");
    expect(ast?.steps?.[1]?.params?.decode).toBe(true);
  });

  it("bare encrypt without transform errors", () => {
    const { errors } = parseRecipe("random 16 | encrypt");
    expect(errors.some((e) => /requires a cipher transform/i.test(e.message))).toBe(
      true
    );
  });

  it("gpg.encrypt remains OpenPGP and distinct from encrypt sugar", () => {
    const { ast, errors } = parseRecipe("gpg.encrypt");
    expect(errors).toEqual([]);
    expect(ast?.steps?.[0]?.name).toBe("gpg.encrypt");
  });
});

describe("encode / decode twin verbs", () => {
  it("resolveDecodeTwinVerb maps pem.encode / pem.decode", () => {
    expect(resolveDecodeTwinVerb("pem.encode", getStep)).toEqual({
      canonical: "pem",
      decode: false,
    });
    expect(resolveDecodeTwinVerb("PEM.DECODE", getStep)).toEqual({
      canonical: "pem",
      decode: true,
    });
    expect(resolveDecodeTwinVerb("aes-gcm.decode", getStep)).toBeNull();
    expect(resolveDecodeTwinVerb("pem", getStep)).toBeNull();
  });

  it("decodeTwinToken prefers dotted verbs for encodings", () => {
    expect(decodeTwinToken(getStep("pem"), false)).toBe("pem.encode");
    expect(decodeTwinToken(getStep("pem"), true)).toBe("pem.decode");
    expect(decodeTwinToken(getStep("aes-gcm"), true)).toBe("aes-gcm -d");
  });

  it("parses and serializes encoding verbs", () => {
    const { ast, errors } = parseRecipe("random 16 | base64.encode | base64.decode");
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.params?.decode).toBeFalsy();
    expect(ast?.steps?.[2]?.params?.decode).toBe(true);
    expect(serializeRecipe(ast)).toBe("random 16 | base64.encode | base64.decode");
  });
});

describe("migrateRecipe", () => {
  it("rewrites the full legacy matrix", () => {
    const src = `decrypt gpg | blip39 -d | recover
… | sss.split threshold=2 shares=3 | blip39 | foreach
  - encrypt gpg
wa-prf | hkdf 32 | aesgcm
rsaoaep -d
symencrypt | symdecrypt`;
    const { recipe, changes } = migrateRecipe(src);
    expect(recipe).toContain("gpg.decrypt");
    expect(recipe).not.toMatch(/gpg\.decrypt\s+gpg/);
    expect(recipe).toContain("sss.combine");
    expect(recipe).toContain("sss.split");
    expect(recipe).toContain("gpg.encrypt");
    expect(recipe).not.toMatch(/gpg\.encrypt\s+gpg/);
    expect(recipe).toContain("webauthn.prf");
    expect(recipe).toContain("aes-gcm");
    expect(recipe).toContain("rsa-oaep");
    expect(recipe).toContain("gpg.symencrypt");
    expect(recipe).not.toMatch(/\baesgcm\b/);
    expect(changes.length).toBeGreaterThan(0);
    expect(LEGACY_STEP_MIGRATE.encrypt).toBeUndefined();
    expect(LEGACY_STEP_MIGRATE.decrypt).toBeUndefined();
  });

  it("does not rewrite bare encrypt (WebCrypto sugar)", () => {
    const { recipe, changes } = migrateRecipe(
      "input | utf8 | encrypt AES/GCM/NoPadding key=@cek"
    );
    expect(recipe).toContain("encrypt AES/GCM/NoPadding");
    expect(changes.some((c) => c.from === "encrypt")).toBe(false);
  });

  it("compileRecipe accepts only after migrate", () => {
    const legacy = compileRecipe(
      "genkey aes/256 | out @cek\n\ninput | utf8 | aesgcm key=@cek | out @ct"
    );
    expect(legacy.validation.ok).toBe(false);
    const m = migrateRecipe(
      "genkey aes/256 | out @cek\n\ninput | utf8 | aesgcm key=@cek | out @ct"
    );
    const compiled = compileRecipe(m.recipe);
    expect(compiled.validation.ok).toBe(true);
    expect(compiled.ast && serializeRecipe(compiled.ast)).toContain("aes-gcm");
  });
});

describe("namespaced registry", () => {
  it("compiles gpg / sss / webauthn tokens", () => {
    expect(compileRecipe("gpg.encrypt").validation.ok || compileRecipe("gpg.encrypt").ast).toBeTruthy();
    const sss = compileRecipe("random 32 | sss.split threshold=2 shares=3");
    expect(sss.validation.ok).toBe(true);
    expect(compileRecipe("webauthn.caps").ast?.steps?.[0]?.name).toBe("webauthn.caps");
  });
});
