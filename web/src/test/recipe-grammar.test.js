/**
 * Conformance corpus from docs/RECIPE.md examples + negatives.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, parseRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";

const EXAMPLES = [
  "genkey ec/p256 | export pkcs8 | pem",
  `genkey ec/p256 | tee {
  - .private | inspect
  - .public | export spki | pem | out @public
} | export pkcs8 | pem`,
  `genkey ec/p256 | tee
  - .private | inspect
  - .public | export spki | pem | out @public
| export pkcs8 | pem`,
  `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share`,
  `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach .items
  - .value | out @share`,
  "random 32 | sss.split threshold=2 shares=3 | blip39 | [1] | out @share-1",
];

describe("RECIPE.md conformance", () => {
  for (const [i, src] of EXAMPLES.entries()) {
    it(`example ${i + 1} parses and validates`, () => {
      const { ast, validation } = compileRecipe(src);
      expect(validation.errors.map((e) => e.message)).toEqual([]);
      expect(validation.ok).toBe(true);
      expect(ast?.steps?.length).toBeGreaterThan(0);
      const again = parseRecipe(serializeRecipe(ast));
      expect(again.errors).toEqual([]);
    });
  }
});

describe("recipe grammar negatives", () => {
  it("rejects tabs", () => {
    const { errors } = parseRecipe("genkey ec/p256\n\t| pem");
    expect(errors.some((e) => /Tabs/i.test(e.message))).toBe(true);
  });

  it("rejects unknown .foo", () => {
    const { errors } = parseRecipe(`genkey ec/p256 | tee
  - .foo | inspect`);
    expect(errors.some((e) => /Unknown selector/i.test(e.message))).toBe(true);
  });

  it("rejects bare merge", () => {
    const { errors } = parseRecipe("random 16 | sss.split threshold=2 shares=2 | merge");
    expect(errors.some((e) => /not used/i.test(e.message))).toBe(true);
  });

  it("rejects tee without body", () => {
    const { validation } = compileRecipe("genkey ec/p256 | tee | export pkcs8");
    expect(validation.ok).toBe(false);
  });
});
