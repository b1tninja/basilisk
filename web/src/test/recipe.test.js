import { describe, expect, it } from "vitest";
import {
  PRESETS,
  compileRecipe,
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

  it("canonicalizes foreach aliases", () => {
    const { ast, errors } = parseRecipe(
      "random 32 | slip39 threshold=2 shares=3 | map | out"
    );
    expect(errors).toEqual([]);
    expect(ast.steps.map((s) => s.name)).toEqual([
      "random",
      "slip39",
      "foreach",
      "out",
    ]);
    expect(serializeRecipe(ast)).toContain("foreach");
    expect(serializeRecipe(ast)).not.toContain("| map");
  });

  it("canonicalizes fork and each to foreach", () => {
    for (const alias of ["fork", "each", "map"]) {
      const { ast } = parseRecipe(`random 16 | slip39 shares=2 threshold=2 | ${alias} | out`);
      expect(ast.steps.some((s) => s.name === "foreach")).toBe(true);
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
    const { ast } = parseRecipe("random 32 | slip39 threshold=2 shares=3 | pem");
    const v = validateRecipe(ast);
    expect(v.ok).toBe(false);
    expect(v.errors.some((e) => /foreach/i.test(e.message))).toBe(true);
  });

  it("rejects foreach without shares", () => {
    const { ast } = parseRecipe("genkey ec/p256 | foreach | out");
    const v = validateRecipe(ast);
    expect(v.ok).toBe(false);
    expect(v.errors.some((e) => /collection|shares/i.test(e.message))).toBe(true);
  });

  it("rejects nested foreach", () => {
    const { ast } = parseRecipe(
      "random 32 | slip39 threshold=2 shares=3 | foreach | foreach | out"
    );
    const v = validateRecipe(ast);
    expect(v.ok).toBe(false);
    expect(v.errors.some((e) => /Nested foreach/i.test(e.message))).toBe(true);
  });

  it("rejects threshold > shares", () => {
    const { ast } = parseRecipe("random 32 | slip39 threshold=5 shares=2");
    const v = validateRecipe(ast);
    expect(v.ok).toBe(false);
  });

  it("never serializes recipient identities", () => {
    const recipe = "genkey ec/p256 | export pkcs8 | pem | slip39 threshold=2 shares=3 | foreach | gpg";
    const { ast } = parseRecipe(recipe);
    const out = serializeRecipe(ast);
    expect(out).not.toMatch(/@/);
    expect(out).not.toMatch(/to=/);
    expect(unresolvedRecipients(ast).slots).toBe(3);
  });

  it("requires export before pem", () => {
    const { validation } = compileRecipe("genkey ec/p256 | pem");
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /export/i.test(e.message))).toBe(true);
  });
});
