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

  it("holds foreach-body out labels to the same duplicate rule", () => {
    // A body `out $share` binds a real slot now (a bundle of every iteration's
    // value), so it claims its label like any other `out`. Two cells cannot
    // both write it — this used to compile, because body outs were exempt from
    // the slot walk, and the second loop's values silently shadowed nothing.
    const { validation } = compileRecipe(
      [
        "random 32 | sss.split 2/3 | blip39 | foreach\n  - out $share",
        "random 32 | sss.split 2/3 | blip39 | foreach\n  - out $share",
      ].join("\n\n")
    );
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /Duplicate out slot \$share/.test(e.message))).toBe(
      true
    );
    // …and against a top-level out of the same label, in either order.
    const mixed = compileRecipe(
      '"x" | out $share\n\nrandom 32 | sss.split 2/3 | blip39 | foreach\n  - out $share'
    );
    expect(mixed.validation.errors.some((e) => /Duplicate out slot \$share/.test(e.message))).toBe(
      true
    );
  });

  it("types a foreach-body out label as a bundle the collector accepts", async () => {
    // `in $share` after a foreach used to be a compile error — "unknown slot"
    // about a label the notebook visibly writes. The slot is a bundle of the
    // loop's values, sized by the split when the text states the count, and
    // `shares` collects bundles — so the recovery can *name* the set instead
    // of leaning on the tray or the indexed sweep.
    const src = [
      "random 32 | sss.split 2/3 | blip39 | foreach\n  - out $share",
      "$share | shares | blip39 -d | sss.combine | encode hex | out $secret",
    ].join("\n\n");
    const { ast, validation } = compileRecipe(src);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    const arts = await runRecipe(ast);
    expect(
      arts.find((a) => /secret/i.test(a.label || a.filename || ""))?.content
    ).toMatch(/^[0-9a-f]{64}$/);
  }, 30_000);

  it("rejects unknown in slot", () => {
    const { validation } = compileRecipe("in $missing | export pkcs8");
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /unknown slot/i.test(e.message))).toBe(
      true
    );
  });

  it("runs in $mine after a selected share was put there, share meta and all", async () => {
    // The two-browser ceremony finding, as a layer test: `$set | at 1 | out
    // $mine` used to report ok, draw a tile and register nothing, because the
    // registry diverted any value carrying `meta.shareIndex` away from the
    // label map — so the next cell failed with "unknown slot (register earlier
    // with out $mine)", a remedy already performed. `out` binds its label now
    // whatever the value carries.
    const { ast, validation } = compileRecipe(
      [
        "random 32 | sss.split 2/3 | blip39 | out $set",
        "in $set | at 1 | out $mine",
        "in $mine | digest | encode hex | out $check",
      ].join("\n\n")
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    const arts = await runRecipe(ast);
    expect(
      arts.find((a) => /check/i.test(a.label || a.filename || ""))?.content
    ).toMatch(/^[0-9a-f]{64}$/);
  }, 30_000);

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
    // Two sugars converge in this one line, and both are the same trade: an
    // input form that is shorter to type, and a canonical form that is the one
    // the two ends digest. `in $kp` is written `$kp`, and `:public` is written
    // `public` — a keypair half is a step, so it is spelled like one.
    expect(out).toContain("$kp | public");
    expect(out).not.toContain("in $kp");
    expect(out).not.toContain(":public");
    expect(parseRecipe(out).errors).toEqual([]);
  });
});
