/**
 * Conformance corpus from docs/RECIPE.md examples + negatives.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, parseRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";

const EXAMPLES = [
  "genkey ec/p256 | export pkcs8 | pem",
  `genkey ec/p256 | tee {
  - :private | inspect
  - :public | export spki | pem | out $public
} | export pkcs8 | pem`,
  `genkey ec/p256 | tee
  - :private | inspect
  - :public | export spki | pem | out $public
| export pkcs8 | pem`,
  `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`,
  `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach :items
  - :value | out $share`,
  "random 32 | sss.split threshold=2 shares=3 | blip39 | [1] | out $share-1",
  "gpg.decrypt count=all | shares tray=merge | blip39 -d | sss.combine | out $secret",
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
    const { ast, errors } = parseRecipe(`"hello world" | out $var

0xff | out $n`);
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
    expect(text).toContain('"hello world" | out $var');
    expect(text).toContain("255 | out $n");
    expect(text).not.toContain("0xff");
  });

  it("parses bool literals", () => {
    const { ast, errors } = parseRecipe(`true | out $ok

false | as bool | out $no`);
    expect(errors).toEqual([]);
    expect(ast.chains[0].steps[0]).toMatchObject({
      name: "lit",
      params: { kind: "bool", value: true },
    });
    expect(serializeRecipe(ast)).toContain("true | out $ok");
    expect(serializeRecipe(ast)).toContain("false | as bool | out $no");
  });

  it("rejects unquoted bare words as stages", () => {
    const { errors } = parseRecipe("hello | out $var");
    expect(errors.some((e) => /Unknown step|Expected a step/i.test(e.message))).toBe(
      true
    );
  });

  it("parses positional emails with @ (hkp.search)", () => {
    const { ast, errors } = parseRecipe(
      "hkp.search alice@example.org | hkp.filter | out $alices"
    );
    expect(errors).toEqual([]);
    expect(ast.steps[0].params.query).toBe("alice@example.org");
  });

  it("sized cipher forms serialize keyBits", () => {
    const { ast, errors } = parseRecipe("input | utf8 | aes-256-gcm key=$cek");
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
      "random 32 | sss.split threshold=2 shares=3 | out $s"
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

/**
 * `$` is the slot sigil; `@` names the peer at the chain-header position. The
 * three cases below are the whole of the migration's risk surface: the
 * compatibility read, the header position it must not swallow, and the
 * start-anchoring that keeps a `$` inside a value literal.
 */
describe("slot sigil", () => {
  it("reads a pre-swap @slot, warns, and re-serializes it as $", () => {
    const legacy = `genkey ec/p256 | out @kp

@kp | export spki | pem | out @pub`;
    const { ast, validation } = compileRecipe(legacy);
    expect(validation.errors).toEqual([]);
    expect(ast).toBeTruthy();

    // Warned, not errored: the recipe ran before and still runs.
    expect(validation.ok).toBe(true);
    expect(validation.warnings.length).toBeGreaterThan(0);
    expect(
      validation.warnings.some((w) => /\$kp/.test(w.message) && /@kp/.test(w.message))
    ).toBe(true);

    // The AST never carries the old sigil, so the next serialize upgrades the
    // text — which is how a `#r=` link in the wild fixes itself on first load.
    const text = serializeRecipe(ast);
    expect(text).toBe(
      "genkey ec/p256 | out $kp\n\n$kp | export spki | pem | out $pub"
    );
    expect(text).not.toContain("@");
    const again = compileRecipe(text);
    expect(again.validation.errors).toEqual([]);
    expect(again.validation.warnings).toEqual([]);
  });

  it("reads `@` at the head of a chain as the peer, not a slot", () => {
    // No `out @…` / `in @…` / `=@…` anywhere, so nothing proves this is a
    // pre-swap recipe and `@alice` is the peer the cell runs for.
    const { ast, errors } = parseRecipe("@alice\ngenkey ec/p256 | out $kp");
    expect(errors).toEqual([]);
    expect(ast.chains[0].peer).toBe("alice");
    expect(ast.steps[0].name).toBe("genkey");
  });

  it("still replays a pre-swap recipe whose chain head is a slot", () => {
    // The reservation must not unmake itself: pass 1 reads this `@kp` as a
    // peer, and only the *unambiguous* `out @kp` in the cell above it is
    // evidence enough to replay the whole source with the legacy slot read.
    const { ast, validation } = compileRecipe(
      "genkey ec/p256 | out @kp\n\n@kp | export spki | pem | out @pub"
    );
    expect(validation.errors).toEqual([]);
    expect(ast.chains[1].peer).toBeUndefined();
    expect(ast.chains[1].steps[0]).toMatchObject({
      name: "in",
      params: { ref: "$kp" },
    });
  });

  it("does not treat a `$` inside a value as a slot", () => {
    // The vehicle used to be `gpg.symencrypt passphrase=my$ecret`, and moved
    // when every passphrase param became `$ref`-only: a secret written as a
    // literal is refused now, whatever characters are in it. The grammar
    // property is unchanged and still needs a `slot: true` param to be about
    // anything — on those, a `$` that does not open the value is just a
    // character.
    const { ast, errors } = parseRecipe("file.read | age.encrypt to=my$ecret");
    expect(errors).toEqual([]);
    expect(ast.steps[1].params.to).toBe("my$ecret");
    // Same rule for the sigil `@` has always followed: an address stays an
    // address, and now it needs no positional tie-break to say so.
    const to = parseRecipe("input | gpg.encrypt to=alice@example.org");
    expect(to.errors).toEqual([]);
    expect(to.ast.steps[1].params.to).toBe("alice@example.org");
  });
});
