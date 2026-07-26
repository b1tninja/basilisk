/**
 * Nested list bodies (flat stem) for tee / foreach — docs/RECIPE.md.
 */
import { describe, expect, it } from "vitest";
import {
  compileRecipe,
  parseRecipe,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

describe("nested list recipe syntax", () => {
  it("parses foreach indented list body", () => {
    const src = `random 16 | sss threshold=2 shares=3 | blip39 | foreach
  - out @share`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const fe = ast.steps.find((s) => s.name === "foreach");
    expect(fe.body?.map((b) => b.name)).toEqual(["out"]);
    expect(ast.steps.filter((s) => s.name === "out")).toHaveLength(0);
  });

  it("parses tee body then continues stem with |", () => {
    const src = `genkey ec/p256 | tee
  - export spki which=public
  - pem
  - out @public
| export pkcs8 | pem`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(ast.steps.map((s) => s.name)).toEqual([
      "genkey",
      "tee",
      "export",
      "pem",
    ]);
    expect(ast.steps[1].body?.map((b) => b.name)).toEqual([
      "export",
      "pem",
      "out",
    ]);
  });

  it("parses brace tee body", () => {
    const src = `genkey ec/p256 | tee {
  - .private | inspect
  - .public | export spki | out @pub
} | export pkcs8 | pem`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const tee = ast.steps.find((s) => s.name === "tee");
    expect(tee.bodyForm).toBe("brace");
    expect(tee.branches?.map((b) => b.member)).toEqual(["private", "public"]);
  });

  it("round-trips nested foreach via serialize", () => {
    const src = `random 16 | sss threshold=2 shares=3 | blip39 | foreach
  - out @share`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const out = serializeRecipe(ast);
    expect(out).toContain("foreach\n");
    expect(out).toMatch(/-\s+out/);
    const again = parseRecipe(out);
    expect(again.errors).toEqual([]);
    expect(again.ast.steps.find((s) => s.name === "foreach")?.body?.[0].name).toBe(
      "out"
    );
  });

  it("rejects flat foreach without body", () => {
    const { validation } = compileRecipe(
      "random 16 | sss threshold=2 shares=3 | blip39 | foreach | out @share"
    );
    expect(validation.ok).toBe(false);
    expect(
      validation.errors.some((e) => /foreach requires a body|Unexpected/i.test(e.message))
    ).toBe(true);
  });

  it("parses at and [n] alias", () => {
    const a = parseRecipe(
      "random 16 | sss threshold=2 shares=3 | blip39 | at 1 | out @s"
    );
    expect(a.errors).toEqual([]);
    expect(a.ast.steps.some((s) => s.name === "at")).toBe(true);
    expect(a.ast.steps.find((s) => s.name === "at")?.params.selector).toBe("1");

    const b = parseRecipe(
      "random 16 | sss threshold=2 shares=3 | blip39 | [2] | out @s"
    );
    expect(b.errors).toEqual([]);
    expect(b.ast.steps.find((s) => s.name === "at")?.params.selector).toBe("2");
  });

  it("rejects orphan indented list", () => {
    const { errors } = parseRecipe("genkey ec/p256\n  - export pkcs8");
    expect(
      errors.some((e) => /Unexpected indent|Unexpected indented|nest/i.test(e.message))
    ).toBe(true);
  });

  it("rejects tabs", () => {
    const { errors } = parseRecipe("genkey ec/p256 | foreach\n\t- out");
    expect(errors.some((e) => /Tabs/i.test(e.message))).toBe(true);
  });

  it("rejects bare merge", () => {
    const { errors } = parseRecipe(
      "random 16 | sss threshold=2 shares=3 | blip39 | merge"
    );
    expect(errors.some((e) => /not used|dedent/i.test(e.message))).toBe(true);
  });

  it("runs nested foreach body", async () => {
    const { ast, validation } = compileRecipe(
      `random 16 | sss threshold=2 shares=3 | blip39 | foreach
  - out @share`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.filter((a) => a.role === "share").length).toBe(3);
  }, 30_000);

  it("foreach .items projects .value", async () => {
    const { ast, validation } = compileRecipe(
      `random 16 | sss threshold=2 shares=3 | blip39 | foreach .items
  - .value | out @share`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.filter((a) => a.role === "share").length).toBe(3);
  }, 30_000);

  it("at 1 selects a single share", async () => {
    const { ast, validation } = compileRecipe(
      "random 16 | sss threshold=2 shares=3 | blip39 | at 1 | out @one"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.length).toBeGreaterThanOrEqual(1);
    expect(arts[0].content.split(/\s+/).length).toBeGreaterThan(5);
  }, 30_000);

  it("tee list body emits side out without consuming stem", async () => {
    const { ast, validation } = compileRecipe(
      `genkey ec/p256 | tee
  - export spki which=public
  - out @pub
| export pkcs8 | pem | out @priv`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const names = arts.map((a) => a.filename || a.label).join(" ");
    expect(names).toMatch(/pub/i);
    expect(names).toMatch(/priv/i);
  }, 30_000);

  it("parses tee selector branches", () => {
    const src = `genkey ec/p256 | tee
  - .private | inspect
  - .public | export spki | out @pub`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const tee = ast.steps.find((s) => s.name === "tee");
    expect(tee.branches?.map((b) => b.member)).toEqual(["private", "public"]);
    expect(tee.branches?.[0].body.map((b) => b.name)).toEqual(["inspect"]);
    expect(tee.branches?.[1].body.map((b) => b.name)).toEqual(["export", "out"]);
  });

  it("runs .private selector branch inspect without consuming stem", async () => {
    const { ast, validation } = compileRecipe(
      `genkey ec/p256 | tee
  - .private | inspect
| export pkcs8 | pem | out @priv`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.some((a) => /type: keypair|private JWK/i.test(a.content))).toBe(
      true
    );
    expect(arts.some((a) => /BEGIN PRIVATE KEY/i.test(a.content))).toBe(true);
  }, 30_000);

  it("rejects unknown selectors", () => {
    const { errors } = parseRecipe(`genkey ec/p256 | tee
  - .foo | inspect`);
    expect(errors.some((e) => /Unknown selector/i.test(e.message))).toBe(true);
  });

  it("rejects empty tee (use peek)", () => {
    const { validation } = compileRecipe("genkey ec/p256 | tee | export pkcs8 | pem");
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /tee requires a body|peek/i.test(e.message))).toBe(
      true
    );
  });

  it("peek emits side inspect without consuming stem", async () => {
    const { ast, validation } = compileRecipe(
      "genkey ec/p256 | peek kp | export pkcs8 | pem | out @priv"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.some((a) => /peek:|inspect/i.test(a.label || a.filename || ""))).toBe(
      true
    );
    expect(arts.some((a) => /BEGIN PRIVATE KEY/i.test(a.content))).toBe(true);
  }, 30_000);
});
