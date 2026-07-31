/**
 * The key-exposure trace (§26c).
 *
 * `agent.unlock` hands a private key to the pipeline. The chip that does it
 * is not the only place the key is live, and a mark that stopped there
 * would answer the wrong question: what a reader of someone else's recipe
 * needs to know is not "where did a key come out" but "where is it still in
 * play". These pin the propagation, both along a pipe and across cells.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, recipeChains } from "../lib/toolkit/recipe.js";
import { exposureTrace } from "../lib/toolkit/slot-graph.js";

const trace = (src) => {
  const { ast, validation } = compileRecipe(src);
  expect(validation.ok, (validation.errors || []).map((e) => e.message).join(" · ")).toBe(
    true
  );
  const chains = recipeChains(ast);
  const { slots, steps } = exposureTrace(chains);
  /** Was the step at cell/index marked? Walks the same order the trace does. */
  const marked = (cell, index) => {
    const flat = [];
    const walk = (list) => {
      for (const st of list || []) {
        flat.push(st);
        walk(st.body || []);
        for (const br of st.branches || []) walk(br.body || []);
      }
    };
    walk(chains[cell]?.steps || []);
    return steps.has(flat[index]);
  };
  return { slots, steps, marked };
};

const FPR = "AABBCCDDEEFF00112233445566778899AABBCCDD";

describe("along the pipe", () => {
  it("marks the exposing step and everything after it in that chain", () => {
    const { slots, marked } = trace(`agent.unlock ${FPR} | out @me`);
    // agent.unlock is step 0, `out @me` step 1 — both handle the key.
    expect(marked(0, 0)).toBe(true);
    expect(marked(0, 1)).toBe(true);
    expect(slots.has("me")).toBe(true);
  });

  it("leaves steps before the exposure alone", () => {
    const { marked } = trace(`"hello" | utf8 | out @plain

agent.unlock ${FPR} | out @me`);
    expect(marked(0, 0)).toBe(false);
    expect(marked(0, 1)).toBe(false);
    expect(marked(1, 0)).toBe(true);
  });
});

describe("across cells", () => {
  it("follows the slot into every later consumer", () => {
    const { slots, marked } = trace(`agent.unlock ${FPR} | out @me

"sign me" | utf8 | gpg.sign key=@me | out @sig`);
    expect(slots.has("me")).toBe(true);
    // The signing cell reads @me: its chips carry the mark too.
    expect(marked(1, 2)).toBe(true);
  });

  it("reaches a second hop through an intermediate slot", () => {
    const { slots } = trace(`agent.unlock ${FPR} | out @me

in @me | out @copy

in @copy | out @again`);
    expect(slots.has("me")).toBe(true);
    expect(slots.has("copy")).toBe(true);
    expect(slots.has("again")).toBe(true);
  });

  it("does not mark a cell that reads an unrelated slot", () => {
    const { marked } = trace(`agent.unlock ${FPR} | out @me

"other" | utf8 | out @other

in @other | utf8 | out @tail`);
    expect(marked(1, 0)).toBe(false);
    expect(marked(2, 0)).toBe(false);
  });
});

describe("the boundary ops are not marked", () => {
  it("leaves agent.sign clean — the key never enters the pipeline", () => {
    // This asymmetry is the design (§26c): mark the leak, not the safe path.
    const { steps, slots } = trace(`"sign me" | utf8 | agent.sign ${FPR} | out @sig`);
    expect(steps.size).toBe(0);
    expect(slots.size).toBe(0);
  });

  it("marks nothing at all in a recipe that never exports a key", () => {
    const { steps, slots } = trace(`genkey ed25519 | out @kp

"x" | utf8 | sign key=@kp | out @sig`);
    expect(steps.size).toBe(0);
    expect(slots.size).toBe(0);
  });
});

describe("what it is honest about", () => {
  it("keeps marking downstream rather than guessing at laundering", () => {
    // A signature is not key material, so marking @sig is conservative.
    // Narrowing it would mean deciding which transforms launder a key — a
    // judgement the type system cannot make and a warning must not guess.
    // Over-marking says "the key was in play on this path"; under-marking
    // would be a false all-clear.
    const { slots } = trace(`agent.unlock ${FPR} | out @me

"m" | utf8 | gpg.sign key=@me | out @sig`);
    expect(slots.has("sig")).toBe(true);
  });

  it("is driven by the registry field, not by op names", () => {
    const { steps } = trace(`agent.unlock ${FPR} | out @me`);
    expect(steps.size).toBeGreaterThan(0);
    // Nothing in the module mentions agent.unlock by name.
    expect(exposureTrace.toString()).not.toMatch(/agent\.unlock/);
  });

  it("terminates on a recipe whose slots reference each other", () => {
    const { slots } = trace(`agent.unlock ${FPR} | out @a

in @a | out @b

in @b | out @a2`);
    expect(slots.has("a2")).toBe(true);
  });
});
