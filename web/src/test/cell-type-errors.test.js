/**
 * Type-error banner logic (§33c) — the part that can be wrong on its own.
 *
 * The banner's rendering is not covered here (this suite runs in node, with no
 * React renderer configured). What *is* covered is the fix suggestion, because
 * that is the piece that can mislead: it reads a type out of prose and then
 * claims an op produces it.
 */
import { describe, expect, it } from "vitest";
import { expectedTypeFrom } from "../lib/toolkit/type-error-hints.js";
import { producersOf } from "../lib/toolkit/type-registry.js";
import { PRESETS, compileRecipe, parseRecipe } from "../lib/toolkit/recipe.js";
import { cellErrorsForChains } from "../toolkit/useNotebook";

describe("expectedTypeFrom", () => {
  it("reads the wanted type out of the registry's real phrasings", () => {
    expect(
      expectedTypeFrom('"sss.split" does not accept text/opaque (accepted: bytes/master/16B)')
    ).toBe("bytes");
    expect(expectedTypeFrom('"digest" expects DER bytes')).toBe("bytes");
  });

  it("defers to a fix the validator already named", () => {
    // The generic suggestion comes from the producer list in registry order,
    // so for `bytes` it proposes `aes-cbc` — a real producer and terrible
    // advice next to "add export pkcs8". Silence beats a second worse answer.
    expect(expectedTypeFrom('"digest" expects DER bytes — add export pkcs8')).toBeNull();
    expect(expectedTypeFrom("shares/raw needs blip39 -d — use blip39.decode")).toBeNull();
  });

  it("returns null rather than guessing", () => {
    // A miss costs a suggestion; a wrong hit sends the user to an op that
    // cannot help. Prefer silence.
    expect(expectedTypeFrom("something went wrong")).toBeNull();
    expect(expectedTypeFrom("")).toBeNull();
  });

  it("only names types the registry can actually produce", () => {
    for (const msg of [
      '"digest" expects DER bytes',
      '"sss.split" does not accept text (accepted: bytes/master)',
    ]) {
      const t = expectedTypeFrom(msg);
      expect(t, msg).toBeTruthy();
      // The banner only offers a fix when this list is non-empty, so a parsed
      // type that nothing produces simply yields no suggestion.
      expect(producersOf(t).length, `${t} producers`).toBeGreaterThan(0);
    }
  });
});

describe("validator errors stay parseable", () => {
  it("still carries stepIndex, which anchors the banner to a chip", () => {
    const { validation } = compileRecipe("genkey ec/p256 | digest");
    expect(validation.ok).toBe(false);
    const err = validation.errors[0];
    expect(err.stepIndex).toBe(1);
    // This particular error already names its own fix, so the banner shows the
    // message alone. Pinned because the *reason* matters: if the wording ever
    // drops the "add export pkcs8" clause, a generic hint would reappear and
    // this assertion is what surfaces that.
    expect(err.message).toMatch(/add export/);
    expect(expectedTypeFrom(err.message)).toBeNull();
  });
});

/**
 * The banner used to cry wolf. `cellErrors` validated each cell on its own,
 * which discards the slot table the cells above it build, so every shipped
 * multi-cell template opened under a wall of red — `in @kp: unknown slot` and
 * the cascade behind it — before a single run, and still after a successful
 * one. The fix validates the notebook whole and deals the errors back out.
 *
 * The failure mode to guard against is the *over*-correction: suppressing
 * unknown-slot errors outside the first cell would swap a false positive for a
 * false negative, which is worse. Both directions are pinned here.
 */
describe("cellErrorsForChains", () => {
  const chainsOf = (src) => parseRecipe(src).ast.chains || [];

  it("resolves a slot written by an earlier cell", () => {
    const chains = chainsOf(`genkey ec/p256 | out @kp

@kp | export pkcs8 | pem | out @private`);
    expect(chains).toHaveLength(2);
    expect(cellErrorsForChains(chains)).toEqual([[], []]);
  });

  it("leaves every shipped multi-cell template silent on load", () => {
    // The user-visible claim, checked against the actual shipped text rather
    // than a hand-copied excerpt of it.
    const noisy = [];
    for (const p of PRESETS) {
      const chains = chainsOf(p.recipe);
      if (chains.length < 2) continue;
      const errs = cellErrorsForChains(chains).flat();
      if (errs.length) noisy.push(`${p.id}: ${errs.map((e) => e.message).join(" · ")}`);
    }
    expect(noisy).toEqual([]);
  });

  it("still reports a slot nothing ever writes, in the same words", () => {
    const chains = chainsOf(`genkey ec/p256 | out @kp

@typo | export pkcs8 | pem | out @private`);
    const cells = cellErrorsForChains(chains);
    expect(cells[0]).toEqual([]);
    expect(cells[1][0].message).toBe(
      "in @typo: unknown slot (register it earlier with out @typo)"
    );
    // …and the cascade behind it is still reported too — the point is that the
    // complaint is true, not that it is short.
    expect(cells[1].length).toBeGreaterThan(1);
  });

  it("does not accept a slot written only *below* the cell that reads it", () => {
    // Order is the whole content of "register it earlier".
    const chains = chainsOf(`@kp | export pkcs8 | pem | out @private

genkey ec/p256 | out @kp`);
    expect(cellErrorsForChains(chains)[0][0].message).toMatch(/unknown slot/);
  });

  it("anchors each error to the offending chip in its own cell", () => {
    // stepIndex is a cell-local index into that cell's `steps` — the banner
    // does `steps[e.stepIndex]` to name the chip. A whole-notebook validation
    // numbers steps continuously, so this is where the rebasing is checked.
    const chains = chainsOf(`genkey ec/p256 | out @kp

@kp | export pkcs8 | pem | out @private

@kp | digest`);
    const cells = cellErrorsForChains(chains);
    expect(cells[0]).toEqual([]);
    expect(cells[1]).toEqual([]);
    expect(cells[2]).toHaveLength(1);
    // `digest` is step 1 of cell [2] — global index 8, and 8 would be off the
    // end of a 2-step cell.
    expect(cells[2][0].stepIndex).toBe(1);
    expect(chains[2].steps[cells[2][0].stepIndex].name).toBe("digest");
  });

  it("anchors errors raised inside a foreach body to the stem chip", () => {
    const chains = chainsOf(`random 32 | sss.split threshold=2 shares=3 | out @sh

@sh | inspect | foreach
  - digest`);
    const cells = cellErrorsForChains(chains);
    expect(cells[1]).not.toHaveLength(0);
    expect(chains[1].steps[cells[1][0].stepIndex].name).toBe("foreach");
  });

  it("returns one array per cell, empty ones included", () => {
    const chains = [{ steps: [] }, ...chainsOf("genkey ed25519 | out @k"), { steps: [] }];
    expect(cellErrorsForChains(chains)).toEqual([[], [], []]);
    expect(cellErrorsForChains([])).toEqual([]);
    expect(cellErrorsForChains([{ steps: [] }])).toEqual([[]]);
  });
});
