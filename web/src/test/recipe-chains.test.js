/**
 * Multi-chain recipes + @slot in/out — docs/RECIPE.md
 */
import { describe, expect, it } from "vitest";
import {
  canonicalizeRecipe,
  compileRecipe,
  parseRecipe,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

describe("multi-chain + @slots", () => {
  it("parses blank-line chains", () => {
    const src = `genkey ec/p256 | out @kp

in @kp | export pkcs8 | pem`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(ast.chains).toHaveLength(2);
    expect(ast.chains[0].steps.map((s) => s.name)).toEqual(["genkey", "out"]);
    expect(ast.chains[1].steps.map((s) => s.name)).toEqual([
      "in",
      "export",
      "pem",
    ]);
    expect(ast.chains[1].steps[0].params.ref).toBe("@kp");
  });

  it("canonicalizes bare out/in labels to @ and from→in", () => {
    const { text, errors } = canonicalizeRecipe(`genkey ec/p256 | out kp

from kp | export pkcs8 | pem`);
    expect(errors).toEqual([]);
    expect(text).toBe(`genkey ec/p256 | out @kp

in @kp | export pkcs8 | pem`);
  });

  it("canonicalizes out name=public to out @public", () => {
    const { text, errors } = canonicalizeRecipe(
      "genkey ec/p256 | export pkcs8 | pem | out name=public"
    );
    expect(errors).toEqual([]);
    expect(text).toBe("genkey ec/p256 | export pkcs8 | pem | out @public");
  });

  it("rejects path-like out refs", () => {
    const { errors } = parseRecipe("genkey ec/p256 | out ./key.pem");
    expect(errors.some((e) => /File paths|not supported/i.test(e.message))).toBe(
      true
    );
  });

  it("rejects duplicate out labels", () => {
    const { validation } = compileRecipe(
      "genkey ec/p256 | out @kp | export pkcs8 | out @kp"
    );
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /Duplicate out slot/i.test(e.message))).toBe(
      true
    );
  });

  it("rejects unknown in slot", () => {
    const { validation } = compileRecipe("in @missing | export pkcs8");
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /unknown slot/i.test(e.message))).toBe(
      true
    );
  });

  it("runs in @kp after out @kp", async () => {
    const { ast, validation } = compileRecipe(`genkey ec/p256 | out @kp

in @kp | export pkcs8 | pem | out @private`);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.some((a) => /BEGIN PRIVATE KEY/i.test(a.content))).toBe(true);
  }, 30_000);

  it("resolves in 1 to first out slot", async () => {
    const { ast, validation } = compileRecipe(`genkey ec/p256 | out @kp

in 1 | export pkcs8 | pem`);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.some((a) => /BEGIN PRIVATE KEY/i.test(a.content))).toBe(true);
  }, 30_000);

  it("round-trips serialize with blank line between chains", () => {
    const src = `genkey ec/p256 | out @kp

in @kp | .public | export spki | pem | out @public`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const out = serializeRecipe(ast);
    expect(out).toContain("\n\n");
    expect(out).toContain("out @kp");
    expect(out).toContain("in @kp");
    expect(parseRecipe(out).errors).toEqual([]);
  });
});
