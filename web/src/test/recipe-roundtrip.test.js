/**
 * Serializing a recipe must produce text that parses back.
 *
 * `serializeStep` is not a debug convenience — the chip flow re-serializes on
 * every mutation and "Copy link" serializes to build the share URL. So a value
 * that survives compiling but not the round trip does not merely look wrong:
 * editing a chip near it, or sharing the notebook, hands back text that will
 * not parse.
 *
 * The sweep below is the real test. `file.read accept=.pem` was the op's *own
 * documented example* and it round-tripped to `Unexpected "."` — nothing
 * checked that the examples we ship to users actually survive, so a whole class
 * of positional-quoting bugs had no gate. Asserting over the registry's own
 * `Example:` strings means the next op to add one is covered the day it lands.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { STEPS } from "../lib/toolkit/registry.js";

/** Compile → serialize → compile, returning the second pass's errors. */
const roundTrip = (src) => {
  const first = compileRecipe(src);
  expect(first.validation.errors, `fixture should compile: ${src}`).toEqual([]);
  const text = serializeRecipe({ chains: first.ast.chains });
  return { text, errors: compileRecipe(text).validation.errors.map((e) => e.message) };
};

/** The `Example: \`…\`` recipe out of an op's doc string, when it has one. */
const exampleOf = (spec) => {
  const m = /Example:\s*`([^`]+)`/.exec(String(spec.doc || ""));
  return m ? m[1].trim() : null;
};

/**
 * Only the examples that stand alone.
 *
 * Roughly half are deliberately fragments — `input | ssh.sign key=@id` names a
 * slot an earlier cell registers, and `hkp.filter` continues a search. Those
 * cannot compile by themselves, and *making* them compile would mean rewriting
 * doc strings to suit a test, which is the tail wagging the dog. The round trip
 * is a property of serialization, so the self-contained half exercises it just
 * as well.
 */
const standalone = STEPS.map((s) => [s.name, exampleOf(s)])
  .filter(([, ex]) => ex)
  .filter(([, ex]) => {
    try {
      return compileRecipe(ex).validation.errors.length === 0;
    } catch {
      return false;
    }
  });

describe("every self-contained documented Example: survives a round trip", () => {
  it("finds examples to check, so the sweep cannot pass by being empty", () => {
    // A floor, not the exact count: ops get added, and a sweep that has to be
    // re-pinned on every addition gets re-pinned without being read.
    expect(standalone.length).toBeGreaterThan(20);
  });

  for (const [name, src] of standalone) {
    it(`${name}: ${src}`, () => {
      const { text, errors } = roundTrip(src);
      expect(errors, `re-parsing \`${text}\` failed`).toEqual([]);
    });
  }
});

describe("a positional value the parser cannot read bare is quoted", () => {
  it("keeps file.read accept=.pem parseable — the reported case", () => {
    const { text, errors } = roundTrip("file.read accept=.pem | inspect");
    expect(text).toContain('".pem"');
    expect(errors).toEqual([]);
  });

  it("leaves ordinary positionals unquoted, so recipes stay readable", () => {
    // The fix must not quote everything: `genkey ec/p256` reads as itself, and
    // turning it into `genkey "ec/p256"` would churn every saved recipe and
    // every share link for no gain.
    const { text } = roundTrip("genkey ec/p256 | export pkcs8 | pem");
    expect(text).toContain("genkey ec/p256");
    expect(text).not.toContain('"ec/p256"');
  });

  it("still quotes for whitespace, pipe and =, as it did before", () => {
    const { text, errors } = roundTrip('hkp.search "john doe"');
    expect(text).toContain('"john doe"');
    expect(errors).toEqual([]);
  });

  it("covers the whole class, not just a leading dot", () => {
    // Asserted through the parser rather than against a character blacklist:
    // the rule is "the argument loop dispatches on letter, digit or @", and a
    // blacklist would miss the next character nobody thought of.
    for (const accept of [".pem", ".p12,.pfx", "-weird", "+plus"]) {
      const { text, errors } = roundTrip(`file.read accept=${JSON.stringify(accept)}`);
      expect(errors, `accept=${accept} round-tripped to ${text}`).toEqual([]);
    }
  });
});
