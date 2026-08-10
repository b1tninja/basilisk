/**
 * Multi-chain recipes + $slot in/out — docs/RECIPE.md
 */
import { describe, expect, it } from "vitest";
import {
  canonicalizeRecipe,
  compileRecipe,
  parseRecipe,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

describe("multi-chain + $slots", () => {
  it("parses blank-line chains", () => {
    const src = `genkey ec/p256 | out $kp

in $kp | export pkcs8 | pem`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(ast.chains).toHaveLength(2);
    expect(ast.chains[0].steps.map((s) => s.name)).toEqual(["genkey", "out"]);
    expect(ast.chains[1].steps.map((s) => s.name)).toEqual([
      "in",
      "export",
      "pem",
    ]);
    expect(ast.chains[1].steps[0].params.ref).toBe("$kp");
  });

  it("rejects bare out labels (require $)", () => {
    const { errors } = parseRecipe(`genkey ec/p256 | out kp

$kp | export pkcs8 | pem`);
    expect(errors.some((e) => /require \$|\$kp/i.test(e.message))).toBe(true);
  });

  it("migrateRecipe rewrites bare out labels to @", async () => {
    const { migrateRecipe } = await import("../lib/toolkit/step-names.js");
    const { recipe } = migrateRecipe(`genkey ec/p256 | out kp

in kp | export pkcs8 | pem`);
    expect(recipe).toContain("out $kp");
    expect(recipe).toContain("in $kp");
    const { text, errors } = canonicalizeRecipe(recipe);
    expect(errors).toEqual([]);
    expect(text).toBe(`genkey ec/p256 | out $kp

$kp | export pkcs8 | pem`);
  });

  it("accepts bare $slot source and $slot | out inheritance", () => {
    const { text, errors } = canonicalizeRecipe(`genkey ec/p256 | out $kp

$kp | out`);
    expect(errors).toEqual([]);
    expect(text).toBe(`genkey ec/p256 | out $kp

$kp | out $kp`);
  });

  it("canonicalizes out name=$public", () => {
    const { text, errors } = canonicalizeRecipe(
      "genkey ec/p256 | export pkcs8 | pem | out $public"
    );
    expect(errors).toEqual([]);
    expect(text).toBe("genkey ec/p256 | export pkcs8 | pem | out $public");
  });

  it("migrateRecipe rewrites out name=public to out $public", async () => {
    const { migrateRecipe } = await import("../lib/toolkit/step-names.js");
    const { recipe } = migrateRecipe(
      "genkey ec/p256 | export pkcs8 | pem | out name=public"
    );
    expect(recipe).toContain("out $public");
  });

  it("rejects path-like out refs", () => {
    const { errors } = parseRecipe("genkey ec/p256 | out ./key.pem");
    expect(errors.some((e) => /File paths|not supported/i.test(e.message))).toBe(
      true
    );
  });

  it("rejects duplicate out labels", () => {
    const { validation } = compileRecipe(
      "genkey ec/p256 | out $kp | export pkcs8 | out $kp"
    );
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /Duplicate out slot/i.test(e.message))).toBe(
      true
    );
  });

  it("rejects unknown in slot", () => {
    const { validation } = compileRecipe("in $missing | export pkcs8");
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /unknown slot/i.test(e.message))).toBe(
      true
    );
  });

  it("runs in $kp after out $kp", async () => {
    const { ast, validation } = compileRecipe(`genkey ec/p256 | out $kp

in $kp | export pkcs8 | pem | out $private`);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.some((a) => /BEGIN PRIVATE KEY/i.test(a.content))).toBe(true);
  }, 30_000);

  it("resolves in 1 to first out slot", async () => {
    const { ast, validation } = compileRecipe(`genkey ec/p256 | out $kp

in 1 | export pkcs8 | pem`);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.some((a) => /BEGIN PRIVATE KEY/i.test(a.content))).toBe(true);
  }, 30_000);

  it("round-trips serialize with blank line between chains", () => {
    const src = `genkey ec/p256 | out $kp

in $kp | :public | export spki | pem | out $public`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const out = serializeRecipe(ast);
    expect(out).toContain("\n\n");
    expect(out).toContain("out $kp");
    expect(out).toContain("$kp | :public");
    expect(out).not.toContain("in $kp");
    expect(parseRecipe(out).errors).toEqual([]);
  });
});
