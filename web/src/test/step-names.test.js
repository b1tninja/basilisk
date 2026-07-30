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
  BASE_ENCODINGS,
  isBaseEncoding,
  legacyRemovalHint,
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
    expect(sized.ast?.steps?.[1]?.params?.keyBits).toBe(256);
    expect(serializeRecipe(sized.ast)).toContain("aes-gcm");
    expect(serializeRecipe(sized.ast)).not.toContain("aes-256-gcm");
  });

  it("rejects Basilisk-legacy tokens with a migrator hint", () => {
    const { errors } = parseRecipe("random 16 | aesgcm");
    expect(errors.some((e) => /removed|aes-gcm/i.test(e.message))).toBe(true);
  });
});

describe("encrypt / decrypt cipher sugar (migrator-only)", () => {
  it("resolveCipherTransform accepts JCE, sized, and hyphen forms", () => {
    expect(resolveCipherTransform("AES/GCM/NoPadding")?.canonical).toBe("aes-gcm");
    expect(resolveCipherTransform("aes-256-gcm")).toEqual({
      canonical: "aes-gcm",
      expectedKeyBits: 256,
    });
    expect(resolveCipherTransform("aes-gcm")?.canonical).toBe("aes-gcm");
    expect(resolveCipherTransform("digest")).toBeNull();
  });

  it("live parse rejects encrypt / decrypt sugar", () => {
    const { errors } = parseRecipe(
      "random 16 | encrypt AES/GCM/NoPadding key=@k"
    );
    expect(errors.some((e) => /removed from live parse|Upgrade recipe/i.test(e.message))).toBe(
      true
    );
  });

  it("migrateRecipe rewrites encrypt TRANSFORM to concrete aes-gcm", () => {
    const { recipe, changes } = migrateRecipe(
      "random 16 | encrypt AES/GCM/NoPadding key=@k"
    );
    expect(recipe).toContain("aes-gcm");
    expect(recipe).not.toMatch(/\bencrypt\b/);
    expect(changes.some((c) => c.from === "encrypt/decrypt")).toBe(true);
    const { ast, errors } = parseRecipe(recipe);
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.name).toBe("aes-gcm");
    expect(ast?.steps?.[1]?.params?.decode).toBeFalsy();
    expect(serializeRecipe(ast)).toContain("aes-gcm");
  });

  it("migrateRecipe rewrites decrypt sized transform to decode + keyBits", () => {
    const { recipe } = migrateRecipe("random 16 | decrypt aes-256-gcm key=@k");
    expect(recipe).toMatch(/aes-256-gcm\s+-d/);
    const { ast, errors } = parseRecipe(recipe);
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.name).toBe("aes-gcm");
    expect(ast?.steps?.[1]?.params?.decode).toBe(true);
    expect(ast?.steps?.[1]?.params?.keyBits).toBe(256);
    expect(serializeRecipe(ast)).toMatch(/aes-gcm\s+-d/);
  });

  it("migrateRecipe rewrites encrypt -d before transform", () => {
    const { recipe } = migrateRecipe("random 16 | encrypt -d aes-gcm key=@k");
    expect(recipe).toMatch(/aes-gcm\s+-d/);
    const { ast, errors } = parseRecipe(recipe);
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.params?.decode).toBe(true);
  });

  it("bare encrypt without transform errors", () => {
    const { errors } = parseRecipe("random 16 | encrypt");
    expect(
      errors.some((e) => /removed from live parse|Upgrade recipe|cipher/i.test(e.message))
    ).toBe(true);
  });

  it("gpg.encrypt remains OpenPGP and distinct from encrypt sugar", () => {
    const { ast, errors } = parseRecipe("gpg.encrypt");
    expect(errors).toEqual([]);
    expect(ast?.steps?.[0]?.name).toBe("gpg.encrypt");
  });
});

describe("encode / decode twin verbs", () => {
  it("resolveDecodeTwinVerb maps base64.encode / base64.decode (not pem)", () => {
    expect(resolveDecodeTwinVerb("base64.encode", getStep)).toEqual({
      canonical: "base64",
      decode: false,
    });
    expect(resolveDecodeTwinVerb("BASE64.DECODE", getStep)).toEqual({
      canonical: "base64",
      decode: true,
    });
    expect(resolveDecodeTwinVerb("aes-gcm.decode", getStep)).toBeNull();
    expect(resolveDecodeTwinVerb("pem.encode", getStep)).toBeNull();
    expect(resolveDecodeTwinVerb("pem.decode", getStep)).toBeNull();
    expect(resolveDecodeTwinVerb("pem", getStep)).toBeNull();
    expect(resolveDecodeTwinVerb("hex.encode", getStep)).toBeNull();
    expect(resolveDecodeTwinVerb("to.encode", getStep)).toBeNull();
    expect(resolveDecodeTwinVerb("from", getStep)).toBeNull();
  });

  it("decodeTwinToken prefers dotted verbs for encodings", () => {
    expect(decodeTwinToken(getStep("base64"), false)).toBe("base64.encode");
    expect(decodeTwinToken(getStep("base64"), true)).toBe("base64.decode");
    expect(decodeTwinToken(getStep("aes-gcm"), true)).toBe("aes-gcm -d");
  });

  it("parses and serializes encoding verbs", () => {
    const { ast, errors } = parseRecipe("random 16 | base64.encode | base64.decode");
    expect(errors).toEqual([]);
    expect(ast?.steps?.[1]?.params?.decode).toBeFalsy();
    expect(ast?.steps?.[2]?.params?.decode).toBe(true);
    expect(serializeRecipe(ast)).toBe("random 16 | base64.encode | base64.decode");
  });

  it("pem ↔ der conjugate has no .encode/.decode or -d aliases", () => {
    const { errors: e1 } = parseRecipe("export spki | pem.encode | out @pub");
    expect(e1.some((e) => /Unknown step|pem\.encode/i.test(e.message))).toBe(true);
    const { errors: e2 } = parseRecipe("in @pub | pem.decode | import spki");
    expect(e2.some((e) => /Unknown step|pem\.decode/i.test(e.message))).toBe(true);
    const { errors: e3 } = parseRecipe("in @pub | pem -d | import spki");
    expect(e3.some((e) => /Unknown flag|Unknown step|-d/i.test(e.message))).toBe(true);
    const { ast, errors } = parseRecipe(
      "export spki | pem | out @pub\n\nin @pub | der | import spki"
    );
    expect(errors).toEqual([]);
    expect(ast?.chains?.[0]?.steps?.map((s) => s.name)).toEqual([
      "export",
      "pem",
      "out",
    ]);
    expect(ast?.chains?.[1]?.steps?.map((s) => s.name)).toEqual([
      "in",
      "der",
      "import",
    ]);
    expect(serializeRecipe(ast)).toBe(
      "export spki | pem | out @pub\n\n@pub | der | import spki"
    );
  });

  it("encode ↔ decode hex conjugate — bare hex/unhex rejected", () => {
    const { errors: e1 } = parseRecipe("random 8 | hex | out @h");
    expect(e1.some((e) => /hex.*removed|Unknown step|encode hex/i.test(e.message))).toBe(
      true
    );
    const { errors: e2 } = parseRecipe("in @h | unhex");
    expect(e2.some((e) => /unhex.*removed|Unknown step|decode hex/i.test(e.message))).toBe(
      true
    );
    const { errors: e3 } = parseRecipe("in @h | encode hex -d");
    expect(e3.some((e) => /Unknown flag|-d/i.test(e.message))).toBe(true);
    const { ast, errors } = parseRecipe("random 8 | encode hex | out @h\n\nin @h | decode hex");
    expect(errors).toEqual([]);
    expect(ast?.chains?.[0]?.steps?.map((s) => s.name)).toEqual(["random", "encode", "out"]);
    expect(ast?.chains?.[0]?.steps?.[1]?.params?.encoding).toBe("hex");
    expect(ast?.chains?.[1]?.steps?.map((s) => s.name)).toEqual(["in", "decode"]);
    expect(ast?.chains?.[1]?.steps?.[1]?.params?.encoding).toBe("hex");
    expect(serializeRecipe(ast)).toBe("random 8 | encode hex | out @h\n\n@h | decode hex");
  });

  it("isBaseEncoding covers every alphabet the verbs accept", () => {
    for (const enc of BASE_ENCODINGS) expect(isBaseEncoding(enc), enc).toBe(true);
    expect(isBaseEncoding("rot13")).toBe(false);
  });

  it("retires `to` / `from` from live parse, with a hint", () => {
    // Removed rather than aliased so there is one name per operation. Old text
    // is handled by Upgrade recipe, the same route `hex`/`unhex` already take.
    for (const [src, want] of [
      ["random 8 | to hex", /"to" was renamed|Unknown step/i],
      ["in @h | from hex", /"from" was renamed|Unknown step/i],
    ]) {
      const { errors } = parseRecipe(src);
      expect(errors.some((e) => want.test(e.message)), src).toBe(true);
    }
    expect(legacyRemovalHint("to")).toMatch(/encode/);
    // `from` was overloaded — the hint has to name both of its replacements.
    expect(legacyRemovalHint("from")).toMatch(/decode/);
    expect(legacyRemovalHint("from")).toMatch(/in @slot/);
  });

  it("migrates both roles of `from` in one line", () => {
    // Slot load and decode, side by side — the case the old hex-only rule got
    // wrong the moment a second alphabet existed.
    expect(migrateRecipe("from @h | from base64").recipe).toBe("in @h | decode base64");
    expect(migrateRecipe("random 8 | to base64").recipe).toBe("random 8 | encode base64");
    // Already-current text is left alone.
    expect(migrateRecipe("random 8 | encode base32").recipe).toBe("random 8 | encode base32");
  });

  it("parses the current spelling and round-trips it", () => {
    const ok = parseRecipe("random 8 | encode base64url | out @h\n\nin @h | decode base64url");
    expect(ok.errors).toEqual([]);
    expect(ok.ast?.chains?.[0]?.steps?.[1]?.name).toBe("encode");
    expect(ok.ast?.chains?.[1]?.steps?.[1]?.name).toBe("decode");
    expect(serializeRecipe(ok.ast)).toBe(
      "random 8 | encode base64url | out @h\n\n@h | decode base64url"
    );
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

  it("rewrites bare encrypt/decrypt sugar to concrete ciphers", () => {
    const { recipe, changes } = migrateRecipe(
      "input | utf8 | encrypt AES/GCM/NoPadding key=@cek"
    );
    expect(recipe).toContain("aes-gcm");
    expect(recipe).not.toMatch(/\bencrypt\b/);
    expect(changes.some((c) => c.from === "encrypt/decrypt")).toBe(true);
  });

  it("rewrites bare slot labels to @", () => {
    const { recipe, changes } = migrateRecipe(
      "genkey aes/256 | out cek\n\nrandom 16 | aes-gcm key=cek"
    );
    expect(recipe).toContain("out @cek");
    expect(recipe).toContain("key=@cek");
    expect(changes.some((c) => c.from === "bare-slot-@")).toBe(true);
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
