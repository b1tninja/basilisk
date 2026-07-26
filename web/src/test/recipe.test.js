import { describe, expect, it } from "vitest";
import {
  PRESETS,
  compileRecipe,
  canonicalizeRecipe,
  parseRecipe,
  registryIssues,
  serializeRecipe,
  unresolvedRecipients,
  validateRecipe,
} from "../lib/toolkit/recipe.js";
import { listSteps } from "../lib/toolkit/registry.js";

describe("registry completeness", () => {
  it("has no completeness issues", () => {
    expect(registryIssues()).toEqual([]);
  });

  it("lists canonical steps with docs and io types", () => {
    const steps = listSteps();
    expect(steps.length).toBeGreaterThan(8);
    for (const s of steps) {
      expect(s.doc.length).toBeGreaterThan(10);
      expect(s.input).toBeTruthy();
      expect(s.output).toBeTruthy();
    }
  });
});

describe("parse / serialize", () => {
  it("round-trips a simple recipe", () => {
    const src = "genkey ec/p256 | export pkcs8 | pem";
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(ast.steps.map((s) => s.name)).toEqual(["genkey", "export", "pem"]);
    expect(ast.steps[0].params.alg).toBe("ec/p256");
    expect(serializeRecipe(ast)).toBe(src);
  });

  it("canonicalizeRecipe normalizes case, aliases, and spacing", () => {
    const { text, errors, changed } = canonicalizeRecipe(
      "  GENKEY  EC/P256  |  EXPORT   pkcs8|PEM  "
    );
    expect(errors).toEqual([]);
    expect(changed).toBe(true);
    expect(text).toBe("genkey ec/p256 | export pkcs8 | pem");
  });

  it("canonicalizeRecipe formats foreach bodies and spacing", () => {
    const { text, errors } = canonicalizeRecipe(
      "random 16|sss.split threshold=2 shares=2|foreach\n  - out @share"
    );
    expect(errors).toEqual([]);
    expect(text).toBe("random 16 | sss.split shares=2 | foreach\n  - out @share");
  });

  it("rejects retired foreach aliases", () => {
    for (const alias of ["fork", "each", "map"]) {
      const { errors } = parseRecipe(
        `random 16 | sss.split shares=2 threshold=2 | ${alias}\n  - out`
      );
      expect(errors.some((e) => /Unknown step/i.test(e.message))).toBe(true);
    }
  });

  it("rejects unknown steps with position", () => {
    const { errors } = parseRecipe("genkey ec/p256 | nope");
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].message).toMatch(/Unknown step/);
    expect(errors[0].start).toBeGreaterThan(0);
  });
});

describe("validation", () => {
  it("accepts the quorum preset", () => {
    const { validation } = compileRecipe(PRESETS.find((p) => p.id === "quorum-gpg").recipe);
    expect(validation.ok).toBe(true);
    expect(validation.recipientSlots).toBe(3);
    expect(validation.foreachGpg).toBe(true);
  });

  it("suggests foreach when piping shares into a non-collection step", () => {
    const { ast } = parseRecipe("random 32 | sss.split threshold=2 shares=3 | pem");
    const v = validateRecipe(ast);
    expect(v.ok).toBe(false);
    expect(v.errors.some((e) => /foreach/i.test(e.message))).toBe(true);
  });

  it("rejects foreach without shares", () => {
    const { ast, errors } = parseRecipe("genkey ec/p256 | foreach\n  - out");
    const msgs = [...errors, ...(ast ? validateRecipe(ast).errors : [])];
    expect(msgs.some((e) => /collection|shares/i.test(e.message))).toBe(true);
  });

  it("rejects nested foreach", () => {
    const { ast, errors } = parseRecipe(
      "random 32 | sss.split threshold=2 shares=3 | foreach\n  - foreach\n    - out"
    );
    const msgs = [...errors, ...(ast ? validateRecipe(ast).errors : [])];
    expect(
      msgs.some((e) => /Nested|nested list|Cannot use "foreach"/i.test(e.message))
    ).toBe(true);
  });

  it("rejects threshold > shares", () => {
    const { ast } = parseRecipe("random 32 | sss.split threshold=5 shares=2");
    const v = validateRecipe(ast);
    expect(v.ok).toBe(false);
  });

  it("never serializes recipient identities", () => {
    const recipe =
      "genkey ec/p256 | export scalar | sss.split threshold=2 shares=3 | foreach\n  - gpg.encrypt";
    const { ast } = parseRecipe(recipe);
    const out = serializeRecipe(ast);
    expect(out).not.toMatch(/to=/);
    expect(out).toContain("gpg.encrypt");
    expect(unresolvedRecipients(ast).slots).toBe(3);
  });

  it("requires export before pem", () => {
    const { validation } = compileRecipe("genkey ec/p256 | pem");
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /export/i.test(e.message))).toBe(true);
  });

  it("parses and serializes -d decode flags", () => {
    const src = "shares | blip39 -d | sss.combine | utf8 | pem -d | import pkcs8 alg=ec/p256 | export pkcs8 | pem";
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(ast.steps.find((s) => s.name === "pem" && s.params.decode === true)).toBeTruthy();
    expect(serializeRecipe(ast)).toContain("pem -d");
    expect(serializeRecipe(ast)).not.toContain("decode=true");
  });

  it("rejects shares | sss.combine without blip39 -d", () => {
    const { validation } = compileRecipe("shares | sss.combine | base64");
    expect(validation.ok).toBe(false);
    expect(
      validation.errors.some((e) => /blip39 -d|shares\/raw/i.test(e.message))
    ).toBe(true);
  });

  it("allows shares | blip39 -d | sss.combine and reports inputNeeds", () => {
    const { validation } = compileRecipe("shares | blip39 -d | sss.combine | base64");
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds).toContain("shares");
  });

  it("input step reports text inputNeeds and canonicalizes paste/cat aliases", () => {
    const { validation } = compileRecipe("input | utf8 | hex");
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds).toContain("text");

    const { ast, errors } = parseRecipe("paste | utf8 | hex");
    expect(errors).toEqual([]);
    expect(ast.steps[0].name).toBe("input");
    expect(parseRecipe("cat | utf8 | hex").ast.steps[0].name).toBe("input");
  });

  it("rejects more than one input step per pipeline", () => {
    const { validation } = compileRecipe("input | utf8 | base64");
    expect(validation.ok).toBe(true);
    const dup = compileRecipe("input | utf8 | base64 | input");
    expect(dup.validation.ok).toBe(false);
  });

  it("rejects retired gpgdecrypt alias", () => {
    const { errors } = parseRecipe("gpgdecrypt | sss.combine | hex");
    expect(errors.some((e) => /Unknown step/i.test(e.message))).toBe(true);
  });

  it("parses gpg.decrypt", () => {
    const { ast, errors } = parseRecipe("gpg.decrypt | blip39 -d | sss.combine | hex");
    expect(errors).toEqual([]);
    expect(ast.steps[0].name).toBe("gpg.decrypt");
    expect(serializeRecipe(ast)).toContain("gpg.decrypt");
  });

  it("decrypt recipes request gpg + shares panels for hybrid recovery", () => {
    const { validation } = compileRecipe("gpg.decrypt | blip39 -d | sss.combine | hex");
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds).toEqual(
      expect.arrayContaining(["gpg", "shares"])
    );
  });

  it("accepts rebuild-p256 preset", () => {
    const { validation } = compileRecipe(
      PRESETS.find((p) => p.id === "rebuild-p256").recipe
    );
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds).toContain("shares");
  });

  it("rejects pem | sss.split at compile time", () => {
    const { validation } = compileRecipe(
      "genkey ec/p256 | export pkcs8 | pem | sss.split threshold=2 shares=3"
    );
    expect(validation.ok).toBe(false);
    expect(
      validation.errors.some((e) => /sss|export scalar|gpg.symencrypt/i.test(e.message))
    ).toBe(true);
  });

  it("accepts export scalar | sss.split", () => {
    const { validation } = compileRecipe(
      "genkey ec/p256 | export scalar | sss.split threshold=2 shares=3"
    );
    expect(validation.ok).toBe(true);
  });

  it("accepts pem | gpg.symencrypt | sss.split", () => {
    const { validation } = compileRecipe(
      "genkey ec/p256 | export pkcs8 | pem | gpg.symencrypt | sss.split threshold=2 shares=3"
    );
    expect(validation.ok).toBe(true);
  });

  it("rejects gpg.symencrypt on master-sized bytes", () => {
    const { validation } = compileRecipe("random 32 | gpg.symencrypt");
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /gpg.symencrypt/i.test(e.message))).toBe(true);
  });

  it("rejects P-384 scalar | sss.split (not 16/32)", () => {
    const { validation } = compileRecipe(
      "genkey ec/p384 | export scalar | sss.split threshold=2 shares=3"
    );
    expect(validation.ok).toBe(false);
  });
});
