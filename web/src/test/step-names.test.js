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
  isToFromEncoding,
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
      "export spki | pem | out @pub\n\nin @pub | der | import spki"
    );
  });

  it("to ↔ from hex conjugate — bare hex/unhex rejected", () => {
    const { errors: e1 } = parseRecipe("random 8 | hex | out @h");
    expect(e1.some((e) => /hex.*removed|Unknown step|to hex/i.test(e.message))).toBe(
      true
    );
    const { errors: e2 } = parseRecipe("in @h | unhex");
    expect(e2.some((e) => /unhex.*removed|Unknown step|from hex/i.test(e.message))).toBe(
      true
    );
    const { errors: e3 } = parseRecipe("in @h | to hex -d");
    expect(e3.some((e) => /Unknown flag|-d/i.test(e.message))).toBe(true);
    const { ast, errors } = parseRecipe("random 8 | to hex | out @h\n\nin @h | from hex");
    expect(errors).toEqual([]);
    expect(ast?.chains?.[0]?.steps?.map((s) => s.name)).toEqual(["random", "to", "out"]);
    expect(ast?.chains?.[0]?.steps?.[1]?.params?.encoding).toBe("hex");
    expect(ast?.chains?.[1]?.steps?.map((s) => s.name)).toEqual(["in", "from"]);
    expect(ast?.chains?.[1]?.steps?.[1]?.params?.encoding).toBe("hex");
    expect(serializeRecipe(ast)).toBe("random 8 | to hex | out @h\n\nin @h | from hex");
  });

  it("isToFromEncoding recognizes hex only for now", () => {
    expect(isToFromEncoding("hex")).toBe(true);
    expect(isToFromEncoding("base64")).toBe(false);
  });

  it("from is encoding only — slot load uses in", () => {
    const slot = compileRecipe("from @h | from hex");
    expect(slot.validation.ok).toBe(false);
    expect(slot.ast?.steps?.[0]?.name).toBe("from");
    expect(slot.ast?.steps?.[0]?.params?.encoding).toBe("@h");
    const enc = parseRecipe("from hex | digest");
    expect(enc.errors).toEqual([]);
    expect(enc.ast?.steps?.[0]?.name).toBe("from");
    expect(enc.ast?.steps?.[0]?.params?.encoding).toBe("hex");
    const ok = parseRecipe("in @h | from hex");
    expect(ok.errors).toEqual([]);
    expect(ok.ast?.steps?.[0]?.name).toBe("in");
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
