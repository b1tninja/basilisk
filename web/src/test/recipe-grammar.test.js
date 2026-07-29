/**
 * Conformance corpus from docs/RECIPE.md examples + negatives.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, parseRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";

const EXAMPLES = [
  "genkey ec/p256 | export pkcs8 | pem",
  `genkey ec/p256 | tee {
  - :private | inspect
  - :public | export spki | pem | out @public
} | export pkcs8 | pem`,
  `genkey ec/p256 | tee
  - :private | inspect
  - :public | export spki | pem | out @public
| export pkcs8 | pem`,
  `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share`,
  `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach :items
  - :value | out @share`,
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

describe("stem literals", () => {
  it("parses string and int literals; serializes ints as decimal", () => {
    const { ast, errors } = parseRecipe(`"hello world" | out @var

0xff | out @n`);
    expect(errors).toEqual([]);
    expect(ast.chains[0].steps[0]).toMatchObject({
      name: "lit",
      params: { kind: "text", value: "hello world" },
    });
    expect(ast.chains[1].steps[0]).toMatchObject({
      name: "lit",
      params: { kind: "int", value: 255 },
    });
    const text = serializeRecipe(ast);
    expect(text).toContain('"hello world" | out @var');
    expect(text).toContain("255 | out @n");
    expect(text).not.toContain("0xff");
  });

  it("parses bool literals", () => {
    const { ast, errors } = parseRecipe(`true | out @ok

false | as bool | out @no`);
    expect(errors).toEqual([]);
    expect(ast.chains[0].steps[0]).toMatchObject({
      name: "lit",
      params: { kind: "bool", value: true },
    });
    expect(serializeRecipe(ast)).toContain("true | out @ok");
    expect(serializeRecipe(ast)).toContain("false | as bool | out @no");
  });

  it("rejects unquoted bare words as stages", () => {
    const { errors } = parseRecipe("hello | out @var");
    expect(errors.some((e) => /Unknown step|Expected a step/i.test(e.message))).toBe(
      true
    );
  });

  it("parses positional emails with @ (hkp.search)", () => {
    const { ast, errors } = parseRecipe(
      "hkp.search alice@example.org | hkp.filter | out @alices"
    );
    expect(errors).toEqual([]);
    expect(ast.steps[0].params.query).toBe("alice@example.org");
  });

  it("sized cipher forms serialize keyBits", () => {
    const { ast, errors } = parseRecipe("input | utf8 | aes-256-gcm key=@cek");
    expect(errors).toEqual([]);
    expect(ast.steps[2].params.keyBits).toBe(256);
    expect(serializeRecipe(ast)).toContain("keyBits=256");
  });
});

describe("recipe grammar negatives", () => {
  it("rejects unknown named kwargs", () => {
    const { errors } = parseRecipe("genkey ec/p256 bogus=1");
    expect(errors.some((e) => /Unknown parameter "bogus"/i.test(e.message))).toBe(
      true
    );
  });

  it("accepts known named kwargs", () => {
    const { ast, errors } = parseRecipe(
      "random 32 | sss.split threshold=2 shares=3 | out @s"
    );
    expect(errors).toEqual([]);
    expect(ast.steps[1].params).toMatchObject({
      threshold: 2,
      shares: 3,
    });
  });

  it("rejects tabs", () => {
    const { errors } = parseRecipe("genkey ec/p256\n\t| pem");
    expect(errors.some((e) => /Tabs/i.test(e.message))).toBe(true);
  });

  it("rejects dot members (use colon selectors)", () => {
    const { errors } = parseRecipe(`genkey ec/p256 | tee
  - .foo | inspect`);
    expect(
      errors.some((e) => /Member selectors use :|:foo|namespaced ops/i.test(e.message))
    ).toBe(true);
  });

  it("parses colon selectors", () => {
    const { ast, errors } = parseRecipe("genkey ec/p256 | :public | export spki");
    expect(errors).toEqual([]);
    expect(ast.steps[1].name).toBe("select");
    expect(ast.steps[1].params.selector).toBe(":public");
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
