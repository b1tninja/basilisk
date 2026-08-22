/**
 * A blank cell in the middle of a notebook does not move the cells below it.
 *
 * Two files already state this rule and neither could enforce it from where it
 * was written. `plan.js` says an empty chain is "a no-op cell, not a gap: it
 * appears here, in `planRun`'s cells, in the manifest and in the gate's
 * bookkeeping", and notes that filtering it in one place and not another "is
 * what put cell 2 out of step three times running". `placementGate`'s shape
 * argument names the consequence outright: a count that skips blanks "would
 * agree with the plan until the first blank line and then place every cell
 * below it on the wrong peer."
 *
 * It was doing exactly that, through a route neither comment covers. Recipe
 * text has **no spelling for an empty cell** — `parseRecipe` pushes a chain
 * only when it has steps and `serializeRecipe` drops the empty ones — and the
 * notebook derives `source` from `chains` and then planned from a re-parse of
 * that text. So the plan was built without the blanks while the run loop
 * walked `chains` and handed `admit` the index the person is looking at.
 *
 * For a placed run that is not a numbering complaint. `admit(index)` reads
 * `plan.cells[index]` and answers "is this mine"; one row out, and the answer
 * for a peer's cell is read off a row belonging to this machine.
 *
 * A mid-notebook blank is reachable two ways: clear the last step out of a
 * middle cell (`chainsWithCellSteps` keeps the cell), or drag a trailing blank
 * upward (the reorder splice). `addCell` alone only ever appends, which is why
 * this survived — a trailing blank shifts nothing.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { chainsNumberedLikeNotebook, planChains, planRun } from "../lib/toolkit/plan.js";
import { handoffContext } from "../lib/toolkit/handoff-shell.js";

/** The blank line that separates two cells — the join `canonicalNotebookSource` uses. */
const CELL_GAP = String.fromCharCode(10, 10);

const MARA = "A".repeat(40);
const OKAFOR = "B".repeat(40);
const ROSTER = { mara: MARA, okafor: OKAFOR };

/** mara seeds, okafor transforms, mara reads — the handoff fixture's shape. */
const SRC = `@mara
bytes deadbeef | encode hex | out $seed | publish

@okafor
in $seed | decode hex | encode base64 | out $b64 | publish

@mara
in $b64 | decode base64 | encode hex | out $final
`;

/** The notebook as the editor holds it, with a blank cell inserted at `at`. */
function notebookWithBlankAt(at) {
  const real = planChains(compileRecipe(SRC));
  const cells = [...real];
  cells.splice(at, 0, { steps: [] });
  return cells;
}

/** What `useNotebook` builds: plan over the notebook's own cells. */
function planFor(notebook) {
  const compiled = compileRecipe(serializeRecipe({ chains: notebook }));
  return planRun(
    {
      ...compiled,
      ast: {
        ...(compiled.ast || {}),
        chains: chainsNumberedLikeNotebook(compiled.ast?.chains || [], notebook),
      },
    },
    { me: "mara", roster: ROSTER }
  );
}

describe("a blank cell keeps its position in the plan", () => {
  it("finds the notebook it is measuring", () => {
    // An empty sweep passes every assertion below it.
    const plain = planChains(compileRecipe(SRC));
    expect(plain.length, "the fixture stopped having three cells").toBe(3);
    expect(plain.map((c) => c.peer)).toEqual(["mara", "okafor", "mara"]);
  });

  it("gives the plan one cell per notebook cell, blanks included", () => {
    const notebook = notebookWithBlankAt(1);
    const plan = planFor(notebook);
    expect(plan.cells.length, "the plan is a different length from the notebook").toBe(
      notebook.length
    );
  });

  it("leaves every cell below the blank on the peer that owns it", () => {
    const notebook = notebookWithBlankAt(1);
    const plan = planFor(notebook);
    // The whole point: cell 2 is okafor's in the notebook, so it must be
    // okafor's in the plan. Read by index, because that is how `admit` reads it.
    expect(plan.cells.map((c) => c.peer || "")).toEqual([
      "mara",
      "",
      "okafor",
      "mara",
    ]);
    expect(
      plan.cells[2].mine,
      "a cell placed on a peer reads as this machine's, so this machine would perform it"
    ).toBe(false);
  });

  it("does not move anything when the blank is at the end", () => {
    // The `addCell` case, and the reason this went unnoticed.
    const plan = planFor(notebookWithBlankAt(3));
    expect(plan.cells.map((c) => c.peer || "")).toEqual(["mara", "okafor", "mara", ""]);
  });

  it("keeps a leading blank a cell of its own", () => {
    const plan = planFor(notebookWithBlankAt(0));
    expect(plan.cells.map((c) => c.peer || "")).toEqual(["", "mara", "okafor", "mara"]);
  });
});

describe("the splice only ever restores gaps", () => {
  it("returns the parsed chains untouched when there are no blanks", () => {
    // Identity, not equality: substituting the notebook's own chains would
    // change `start`/`end` on thirty of the seventy shipped presets, because
    // those offsets point into the text they were parsed from.
    const parsed = planChains(compileRecipe(SRC));
    const out = chainsNumberedLikeNotebook(parsed, [...parsed]);
    expect(out).toHaveLength(parsed.length);
    for (let i = 0; i < parsed.length; i++) expect(out[i]).toBe(parsed[i]);
  });

  it("keeps the parsed chain objects themselves when it does splice", () => {
    const parsed = planChains(compileRecipe(SRC));
    const out = chainsNumberedLikeNotebook(parsed, notebookWithBlankAt(1));
    expect(out[0]).toBe(parsed[0]);
    expect(out[2]).toBe(parsed[1]);
    expect(out[3]).toBe(parsed[2]);
    expect(out[1].steps).toEqual([]);
  });

  it("refuses to guess when the two disagree about the filled cells", () => {
    // Not one notebook. A splice would invent an alignment, so the parse —
    // which everything else in the plan is derived from — wins.
    const parsed = planChains(compileRecipe(SRC));
    const wrong = [parsed[0], { steps: [] }];
    expect(chainsNumberedLikeNotebook(parsed, wrong)).toBe(parsed);
  });

  it("passes a non-array notebook straight through", () => {
    const parsed = planChains(compileRecipe(SRC));
    expect(chainsNumberedLikeNotebook(parsed, null)).toBe(parsed);
    expect(chainsNumberedLikeNotebook(parsed, undefined)).toBe(parsed);
  });
});

describe("the manifest names the cells the notebook shows", () => {
  it("gives a blank cell a row of its own rather than closing the gap", async () => {
    const notebook = notebookWithBlankAt(1);
    const ctx = await handoffContext({
      source: serializeRecipe({ chains: notebook }),
      me: "mara",
      roster: ROSTER,
      notebook,
    });
    expect(ctx.manifest.cells.map((c) => `${c.index}:${c.peer}`)).toEqual([
      "0:mara",
      "1:",
      "2:okafor",
      "3:mara",
    ]);
    // `offer.cell` is produced from the plan and checked against the manifest,
    // so those two agreeing is the point rather than a coincidence.
    expect(ctx.plan.cells).toHaveLength(ctx.manifest.cells.length);
  });

  it("keeps the notebook digest the digest of its own cells", async () => {
    // The property `handoff-shell` was rewritten for. A blank cell spells `""`,
    // which must not be able to break it.
    const notebook = notebookWithBlankAt(1);
    const ctx = await handoffContext({
      source: serializeRecipe({ chains: notebook }),
      me: "mara",
      roster: ROSTER,
      notebook,
    });
    expect(ctx.manifest.recipeSource).toBe(
      ctx.manifest.cells.map((c) => c.recipe).join(CELL_GAP)
    );
  });

  it("still answers a caller that has only the text", async () => {
    // Four of the five call sites' worth of behaviour before this existed, and
    // the reason `notebook` is optional: a notebook with no blank cell is
    // described identically either way.
    const notebook = planChains(compileRecipe(SRC));
    const source = serializeRecipe({ chains: notebook });
    const withNb = await handoffContext({ source, me: "mara", roster: ROSTER, notebook });
    const textOnly = await handoffContext({ source, me: "mara", roster: ROSTER });
    expect(textOnly.manifest.recipeDigest).toBe(withNb.manifest.recipeDigest);
    expect(textOnly.manifest.cells.map((c) => c.index)).toEqual(
      withNb.manifest.cells.map((c) => c.index)
    );
  });
});
