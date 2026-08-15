/**
 * The `length` refinement on shares (LANGUAGE.md migration step 5).
 *
 * `LIST_TYPES` has said all along that `length` counts elements for `shares`,
 * and the slot was empty. `sss.split` now stamps N (a literal in the text —
 * what keeps the output type knowable before the run), `blip39` carries it
 * through the retype in both directions, and `at` consumes it: an index past
 * the split refuses at compile time. The consumer is wired in the same pass as
 * the producer because a refinement nothing reads is this repo's signature
 * defect — and the plan-time `scatter` count check this enables is a *future*
 * consumer, deliberately not built here.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";
import { matchOverload, resolveStepType, typeOf } from "../lib/toolkit/types.js";

const errorsOf = (src) =>
  compileRecipe(src).validation.errors.map((e) => e.message);

describe("sss.split stamps the share count and blip39 carries it", () => {
  it("stamps length N on the shares output", () => {
    const spec = getStep("sss.split");
    const ov = matchOverload(
      spec.overloads,
      typeOf("bytes", { kind: "master", length: 32 }),
      {}
    );
    expect(ov).toBeTruthy();
    expect(ov.output(typeOf("bytes"), { threshold: 2, shares: 3 })).toEqual({
      base: "shares",
      kind: "raw",
      length: 3,
    });
    // A count the params cannot honestly state stamps nothing rather than
    // something false — reachable only from a hand-built AST, since parsing
    // bounds shares to 1..16.
    expect(ov.output(typeOf("bytes"), { shares: 99 }).length).toBeUndefined();
  });

  it("carries the count through the mnemonic retype, both directions", () => {
    const blip39 = getStep("blip39");
    const encoded = resolveStepType(
      blip39,
      typeOf("shares", { kind: "raw", length: 3 }),
      {}
    );
    expect(encoded.ok).toBe(true);
    expect(encoded.output).toEqual({ base: "shares", kind: "mnemonic", length: 3 });
    const decoded = resolveStepType(blip39, encoded.output, { decode: true });
    expect(decoded.ok).toBe(true);
    expect(decoded.output).toEqual({ base: "shares", kind: "raw", length: 3 });
  });
});

describe("at refuses an index the split cannot serve", () => {
  it("refuses N one past the count — the exact boundary", () => {
    // One past, not far past: an off-by-one in the bound would wave `at 4`
    // of three shares through, and that is the mistake a person actually
    // makes after removing a holder.
    const msgs = errorsOf(
      "random 32 | sss.split 2/3 | blip39 | at 4 | out $x"
    );
    expect(msgs.join(" ")).toContain(
      '"at 4" of a 3-share split selects nothing'
    );
  });

  it("accepts the last share", () => {
    expect(
      errorsOf("random 32 | sss.split 2/3 | blip39 | at 3 | out $x")
    ).toEqual([]);
  });

  it("fires on raw shares straight off the split too", () => {
    const msgs = errorsOf("random 32 | sss.split 2/3 | at 5 | out $x");
    expect(msgs.join(" ")).toContain(
      '"at 5" of a 3-share split selects nothing'
    );
  });

  it("reaches through a slot, which is how the room ceremony writes it", () => {
    // `$set | at N | quorum.send to=…` is the generated deal cell's shape;
    // the slot registry copies the refined type, so the count crosses the
    // chain boundary with it.
    const msgs = errorsOf(
      "random 32 | sss.split 2/3 | blip39 | out $set\n\n$set | at 4 | out $x"
    );
    expect(msgs.join(" ")).toContain(
      '"at 4" of a 3-share split selects nothing'
    );
    expect(
      errorsOf(
        "random 32 | sss.split 2/3 | blip39 | out $set\n\n$set | at 2 | out $x"
      )
    ).toEqual([]);
  });

  it("refuses a slice that starts past the last share, and counts the rest", () => {
    expect(
      errorsOf("random 32 | sss.split 2/3 | blip39 | at 4:5 | out $x").join(" ")
    ).toContain('"at 4:5" of a 3-share split selects nothing');
    // A legal slice re-states its own count rather than parroting the
    // split's: `2:3` of three shares is two shares, and `at` on the slice
    // uses the slice's numbering.
    const sliced = errorsOf(
      "random 32 | sss.split 2/3 | blip39 | at 2:3 | at 3 | out $x"
    );
    expect(sliced.join(" ")).toContain(
      '"at 3" of a 2-share split selects nothing'
    );
  });

  it("stays silent when the count is only knowable at run time", () => {
    // `shares` collects however many mnemonics the tray holds; refusing an
    // index against a count nobody has yet would be a refusal naming a state
    // that is not knowably true.
    expect(
      errorsOf("shares | at 9 | out $x")
    ).toEqual([]);
  });
});
