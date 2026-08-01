/**
 * A selector branch has to be removable from the chip flow.
 *
 * The reported gap was that `- :public | …` rendered with no × anywhere: the
 * step chips inside a branch could each be deleted, so a branch could be
 * emptied one step at a time, and the user was then left with an orphaned
 * `- :public |` line and nothing to click. Arming a branch by mistake was
 * worse — the armed row is client state with no recipe text behind it, so
 * there was no chip to delete either.
 *
 * The interesting decision here is the last branch of a `tee`. `tee` with
 * neither body nor branches is a hard parse error, so a delete that leaves one
 * behind answers a user's own click with a broken recipe. The rule chosen is
 * that the emptied `tee` goes with its last branch, which is safe because
 * `validateRecipe` leaves the stem type unchanged across a tee: nothing
 * downstream can tell the difference. These tests pin both halves — that the
 * result compiles, and that the alternative would not have.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { stepsWithBranchRemoved } from "../toolkit/useNotebook";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
/**
 * Comments stripped, for assertions about what the render path *does*. The
 * prose around these props explains the affordance and the Escape decision at
 * length, and would otherwise satisfy every regex on its own.
 */
const stripComments = (t) =>
  t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
const FLOW = stripComments(read("../toolkit/widgets/RecipeChipFlow.tsx"));
const SHELL = stripComments(read("../toolkit/ToolkitShell.tsx"));

/** Steps for a cell, parsed from real recipe text rather than hand-built. */
const stepsOf = (src) => {
  const { ast, validation } = compileRecipe(src);
  expect(validation.errors, `fixture should compile: ${src}`).toEqual([]);
  return ast.chains?.[0]?.steps || ast.steps;
};

const recompile = (steps) =>
  compileRecipe(serializeRecipe({ chains: [{ steps }] }));

describe("stepsWithBranchRemoved", () => {
  const two = `genkey ec/p256 | tee
  - :public | inspect
  - :private | inspect`;

  it("removes the named branch and leaves the other one alone", () => {
    const { steps, droppedStem } = stepsWithBranchRemoved(stepsOf(two), 1, 0);
    expect(droppedStem).toBe(false);
    expect(steps[1].name).toBe("tee");
    expect(steps[1].branches.map((b) => b.selector)).toEqual([":private"]);
  });

  it("removes the second branch as readily as the first", () => {
    const { steps } = stepsWithBranchRemoved(stepsOf(two), 1, 1);
    expect(steps[1].branches.map((b) => b.selector)).toEqual([":public"]);
  });

  it("does not mutate the steps it was given", () => {
    const before = stepsOf(two);
    stepsWithBranchRemoved(before, 1, 0);
    expect(before[1].branches.map((b) => b.selector)).toEqual([
      ":public",
      ":private",
    ]);
  });

  it("is a no-op, identity included, when the branch is not there", () => {
    const before = stepsOf(two);
    expect(stepsWithBranchRemoved(before, 1, 7).steps).toBe(before);
    expect(stepsWithBranchRemoved(before, 0, 0).steps).toBe(before);
    expect(stepsWithBranchRemoved(before, 9, 0).steps).toBe(before);
    expect(stepsWithBranchRemoved(before, 1, 7).droppedStem).toBe(false);
  });

  it("keeps the tee when unselected body lines remain", () => {
    const { steps, droppedStem } = stepsWithBranchRemoved(
      stepsOf(`genkey ec/p256 | tee
  - :public | inspect
  - inspect`),
      1,
      0
    );
    expect(droppedStem).toBe(false);
    expect(steps[1].name).toBe("tee");
    expect(steps[1].branches).toEqual([]);
    expect(steps[1].body).toHaveLength(1);
  });
});

describe("the last branch takes the tee with it", () => {
  const one = `genkey ec/p256 | tee
  - :public | inspect`;

  it("drops the stem and says so", () => {
    const { steps, droppedStem } = stepsWithBranchRemoved(stepsOf(one), 1, 0);
    expect(droppedStem).toBe(true);
    expect(steps.map((s) => s.name)).toEqual(["genkey"]);
  });

  it("hands back a recipe that compiles", () => {
    const { steps } = stepsWithBranchRemoved(stepsOf(one), 1, 0);
    expect(recompile(steps).validation.errors).toEqual([]);
  });

  it("leaves the rest of the main chain untouched — tee is transparent", () => {
    // The whole justification for dropping the stem: nothing downstream of a
    // tee can observe it, so removing an emptied one cannot break the chain.
    const steps = stepsOf(`genkey ec/p256 | tee
  - :public | inspect
| export pkcs8 | pem`);
    const teeAt = steps.findIndex((s) => s.name === "tee");
    const after = stepsWithBranchRemoved(steps, teeAt, 0);
    expect(after.droppedStem).toBe(true);
    expect(after.steps.map((s) => s.name)).toEqual([
      "genkey",
      "export",
      "pem",
    ]);
    expect(recompile(after.steps).validation.errors).toEqual([]);
  });

  it("would have been a hard error had the bare tee been left behind", () => {
    // Pins the reason the rule exists rather than the rule itself: if an empty
    // tee ever became legal, the choice deserves revisiting.
    const steps = stepsOf(one).map((s) =>
      s.name === "tee" ? { ...s, branches: [] } : s
    );
    const errors = recompile(steps).validation.errors;
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].message).toMatch(/tee requires a body/);
  });
});

describe("the chip flow offers the ×", () => {
  it("puts one on a landed branch's selector chip", () => {
    expect(FLOW).toMatch(
      /label=\{br\.selector\}[\s\S]{0,400}?onRemove=\{\s*onRemoveBranch \? \(\) => onRemoveBranch\(i, bi\) : undefined\s*\}/
    );
  });

  it("keeps the click that adds to the side chain", () => {
    // × and "add a step here" are two answers to one chip; SuggestChip splits
    // them into separate hit targets, so neither may swallow the other.
    expect(FLOW).toMatch(/onClick=\{\(\) => onBranchHit\(i, bi\)\}/);
  });

  it("says what the × does, the way a placed step chip does", () => {
    expect(FLOW).toMatch(/title="Click to add to this side chain · × to delete the branch"/);
  });

  it("puts one on the armed branch, which cancels it", () => {
    expect(FLOW).toMatch(/onRemove=\{onCancelArmed\}/);
    expect(FLOW).toMatch(/× or Escape to cancel/);
  });

  it("resolves Escape as cancel, one layer at a time", () => {
    expect(FLOW).toMatch(/window\.addEventListener\("keydown", onKey\)/);
    expect(FLOW).toMatch(/window\.removeEventListener\("keydown", onKey\)/);
    expect(FLOW).toMatch(/e\.key !== "Escape" \|\| e\.defaultPrevented/);
    expect(FLOW).toMatch(/role="dialog".*role="alertdialog"/);
  });

  it("leaves the foreach body anchor alone", () => {
    // "↻ each item" is the loop body, not a branch. An × there would have to
    // mean "delete the foreach", which is a different promise than the one the
    // same glyph makes two rows above.
    const anchor = FLOW.slice(
      FLOW.indexOf('label="↻ each item"'),
      FLOW.indexOf('label="↻ each item"') + 400
    );
    expect(anchor).not.toMatch(/onRemove/);
  });
});

describe("the shell wires it to the notebook", () => {
  it("routes the × to removeBranch", () => {
    expect(SHELL).toMatch(/onRemoveBranch=\{\(stem, branch\) => \{/);
    expect(SHELL).toMatch(/nb\.removeBranch\(stem, branch\)/);
  });

  it("cancels the armed branch with client state only", () => {
    expect(SHELL).toMatch(/onCancelArmed=\{\(\) => setArmedBranch\(null\)\}/);
  });

  it("does not delete a tee silently — it says so and offers the undo", () => {
    expect(SHELL).toMatch(
      /note: "Removed the last branch — the empty tee went with it\."/
    );
    expect(SHELL).toMatch(/\{undoSnapshot\.note \|\| "Replaced the notebook with a template\."\}/);
  });
});
