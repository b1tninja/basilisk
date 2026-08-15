/**
 * `sss.split 2/3` — the quorum as the verb's object (LANGUAGE.md, "The quorum
 * as a fraction").
 *
 * The named pair (`threshold=2 shares=3`) still reads forever; what these
 * tests pin is that every spelling is *one dialect*: all of them normalize to
 * the same AST params, serialize to the same fraction, and refuse the same
 * degenerate quorums with the same sentences. A refusal reachable from the
 * object form but not the named form (or vice versa) would be two languages
 * wearing one grammar.
 */
import { describe, expect, it } from "vitest";
import {
  COPY_NOT_A_QUORUM,
  compileRecipe,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { ceremonyIssues, ceremonyNotes } from "../lib/toolkit/ceremony.js";

/** Compile, expecting success, and hand back the canonical text. */
const canonical = (src) => {
  const c = compileRecipe(src);
  expect(c.validation.errors, src).toEqual([]);
  return serializeRecipe(c.ast);
};

/** Compile, expecting failure, and hand back the error messages. */
const refusals = (src) => {
  const c = compileRecipe(src);
  const msgs = c.validation.errors.map((e) => e.message);
  expect(msgs.length, `expected a refusal: ${src}`).toBeGreaterThan(0);
  return msgs;
};

describe("the object form normalizes into the params the engine reads", () => {
  it("binds K/N to threshold and shares", () => {
    const { ast } = compileRecipe("random 32 | sss.split 2/3 | out $set");
    const split = ast.chains[0].steps.find((s) => s.name === "sss.split");
    expect(split.params.threshold).toBe(2);
    expect(split.params.shares).toBe(3);
    // The token itself never survives into the AST — one place to read the
    // quorum from, not two.
    expect(split.params.quorum).toBeUndefined();
  });

  it("reads a bare N as a majority, and serializes the fraction", () => {
    // Majority, not half: floor(N/2)+1. The even case is the load-bearing one
    // — ceil(4/2) = 2 would let two disjoint pairs each rebuild the secret,
    // which is the property the majority rule exists to deny.
    expect(canonical("random 32 | sss.split 3 | out $set")).toContain(
      "sss.split 2/3"
    );
    expect(canonical("random 32 | sss.split 4 | out $set")).toContain(
      "sss.split 3/4"
    );
    expect(canonical("random 32 | sss.split 5 | out $set")).toContain(
      "sss.split 3/5"
    );
  });

  it("keeps the passphrase slot ref beside the object", () => {
    const text = canonical(
      'input | out $pw\n\nrandom 32 | sss.split 2/3 passphrase=$pw | out $set'
    );
    expect(text).toContain("sss.split 2/3 passphrase=$pw");
  });

  it("refuses an object contradicted by a named param", () => {
    // `2/3 shares=4` states the share count twice and the statements disagree;
    // arbitrating would make the text mean something one clause denies.
    const msgs = refusals("random 32 | sss.split 2/3 shares=4 | out $set");
    expect(msgs.join(" ")).toContain("already states the quorum");
  });

  it("refuses an object that is not K/N or N", () => {
    for (const src of [
      "random 32 | sss.split 2/3/4 | out $set",
      "random 32 | sss.split x/y | out $set",
    ]) {
      const msgs = refusals(src);
      expect(msgs.join(" "), src).toContain("the object is the quorum");
    }
  });
});

describe("the degenerate quorums refuse identically in both spellings", () => {
  it("1/3 is a copy, not a quorum — in ceremonyIssues' own words", () => {
    for (const src of [
      "random 32 | sss.split 1/3 | out $set",
      "random 32 | sss.split threshold=1 shares=3 | out $set",
    ]) {
      const msgs = refusals(src);
      expect(msgs.join(" "), src).toContain(COPY_NOT_A_QUORUM);
    }
    // One constant, two consumers: the Sheet's stepper refuses with the same
    // sentence, so the two surfaces cannot drift apart.
    expect(ceremonyIssues({ threshold: 1, shares: 3 }).join(" ")).toContain(
      COPY_NOT_A_QUORUM
    );
  });

  it("4/3 is unrecoverable by construction", () => {
    for (const src of [
      "random 32 | sss.split 4/3 | out $set",
      "random 32 | sss.split threshold=4 shares=3 | out $set",
    ]) {
      const msgs = refusals(src);
      expect(msgs.join(" "), src).toContain(
        "threshold (4) cannot exceed shares (3)"
      );
    }
  });

  it("more than 16 shares refuses through the registry bound", () => {
    const msgs = refusals("random 32 | sss.split 17 | out $set");
    expect(msgs.join(" ")).toContain("shares must be ≤ 16");
  });

  it("3/3 is legal, and the picker notes the missing redundancy", () => {
    expect(canonical("random 32 | sss.split 3/3 | out $set")).toContain(
      "sss.split 3/3"
    );
    const notes = ceremonyNotes({ threshold: 3, shares: 3 });
    expect(notes).toHaveLength(1);
    expect(notes[0]).toContain("no redundancy");
    // A quorum with slack gets no note, and an impossible one gets issues
    // rather than a note qualifying a thing that cannot exist.
    expect(ceremonyNotes({ threshold: 2, shares: 3 })).toEqual([]);
    expect(ceremonyNotes({ threshold: 4, shares: 3 })).toEqual([]);
  });
});
