/**
 * Clicking a chip in one cell must not edit a different cell.
 *
 * The defect: every chip handler in `ToolkitShell` did
 *
 *     nb.setFocusedCell(i);
 *     nb.someMutation(…);
 *
 * `setFocusedCell` is a React state setter — it does not take effect until the
 * next render. The mutation that follows ran inside the *current* render's
 * closure, where `steps` was still `chains[focusedCell]` for the previously
 * focused cell. So with cell [0] focused, clicking the × on the first chip of
 * cell [1] deleted `genkey` from cell [0] and left cell [1] untouched. Observed
 * exactly that in the built page on the `p256-multichain` template.
 *
 * This bug lives in the *seam* between a state setter and a closure, so a pure
 * transform test cannot reach it — the transforms were always correct, they
 * were just handed the wrong cell's steps. Three things are pinned here
 * instead:
 *
 *  1. The mechanism, executably: two models of the same click sequence, one
 *     ambient and one cell-targeted, showing which cell each one edits. If the
 *     ambient shape ever stops corrupting, the fix has stopped being needed and
 *     this file is worth rereading.
 *  2. The hook side — no mutation may close over `focusedCell` at all. That is
 *     the property that makes the bug unrepresentable rather than merely
 *     avoided, and it is checked per callback, not once for the file.
 *  3. The shell side — every mutation call names the cell it means, and the
 *     `setFocusedCell(i); mutate(nb.focusedCell, …)` shape (the same bug with
 *     one more argument) does not appear.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { chainsWithCellSteps } from "../toolkit/useNotebook";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
/**
 * Comments stripped before *any* assertion about what the code does. The prose
 * in both files explains this bug at length and names `focusedCell` and
 * `setFocusedCell` while doing it, so an unstripped source satisfies every
 * regex below on documentation alone.
 */
const stripComments = (t) =>
  t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
const HOOK = stripComments(read("../toolkit/useNotebook.ts"));
const SHELL = stripComments(read("../toolkit/ToolkitShell.tsx"));

/**
 * Every mutation that writes a cell's steps. `insertSlotRef` is in the list
 * because it composes two of the others and so inherits whichever cell they
 * target.
 */
const MUTATIONS = [
  "appendOp",
  "insertOpAt",
  "nestOp",
  "addBranchWithStep",
  "replaceStep",
  "updateNestStepParams",
  "removeNestStep",
  "removeBranch",
  "reorderStem",
  "reorderNest",
  "updateStepParams",
  "removeStep",
  "insertSlotRef",
];

/** The `useCallback(…)` body of one hook mutation, deps array included. */
const callbackSource = (name) => {
  const head = `const ${name} = useCallback(`;
  const start = HOOK.indexOf(head);
  expect(start, `${name} should be a useCallback in useNotebook.ts`).toBeGreaterThan(-1);
  const end = HOOK.indexOf("\n  );", start);
  expect(end, `${name} should close at hook indentation`).toBeGreaterThan(start);
  return HOOK.slice(start, end);
};

/** The dependency array of a `useCallback` — the last `[…]` in its source. */
const depsOf = (src) => {
  const open = src.lastIndexOf("[");
  const close = src.lastIndexOf("]");
  expect(open, "callback should declare a dependency array").toBeGreaterThan(-1);
  return src
    .slice(open + 1, close)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
};

/**
 * A model of what React actually does, small enough to be obviously fair:
 * handlers are built once per render and read that render's snapshot, and state
 * setters do not land until the next render. That is the whole mechanism — no
 * renderer needed to show it, and `environment: "node"` means none is available.
 */
function notebookModel({ ambient }) {
  let chains = [
    { steps: [{ name: "genkey" }, { name: "out" }] },
    { steps: [{ name: "in" }, { name: "select" }, { name: "export" }] },
  ];
  let focusedCell = 0;
  let pendingFocus = null;

  /** One render: handlers close over the state as it is *now*. */
  const render = () => {
    const snapChains = chains;
    const snapFocused = focusedCell;
    return {
      setFocusedCell: (i) => {
        pendingFocus = i;
      },
      /**
       * The two shapes. `ambient` reads the focused cell out of its own
       * closure, so a `setFocusedCell` in the same handler is invisible to it.
       */
      removeStep: (cell, stepIndex) => {
        const target = ambient ? snapFocused : cell;
        chains = chainsWithCellSteps(
          snapChains,
          target,
          (snapChains[target]?.steps || []).filter((_, i) => i !== stepIndex)
        );
      },
    };
  };

  return {
    /** Click the × on `stepIndex` of `cell`, exactly as the shell wires it. */
    clickRemoveIn(cell, stepIndex) {
      const h = render();
      h.setFocusedCell(cell);
      h.removeStep(cell, stepIndex);
      if (pendingFocus != null) focusedCell = pendingFocus;
      pendingFocus = null;
    },
    focus(cell) {
      focusedCell = cell;
    },
    names: () => chains.map((c) => c.steps.map((s) => s.name)),
  };
}

describe("the mechanism: a state setter cannot steer the mutation beside it", () => {
  it("edits the previously focused cell when the mutation reads ambient focus", () => {
    // The before-picture, reproduced in the built page: cell [0] focused, ×
    // clicked on cell [1]'s first chip, and `genkey` disappears from cell [0].
    const nb = notebookModel({ ambient: true });
    nb.focus(0);
    nb.clickRemoveIn(1, 0);
    expect(nb.names()).toEqual([["out"], ["in", "select", "export"]]);
  });

  it("edits the cell that was clicked when the mutation is told which one", () => {
    const nb = notebookModel({ ambient: false });
    nb.focus(0);
    nb.clickRemoveIn(1, 0);
    expect(nb.names()).toEqual([
      ["genkey", "out"],
      ["select", "export"],
    ]);
  });

  it("is not fixed by clicking the cell first — the setter still lags one render", () => {
    // The tempting non-fix ("focus it, then act") is the bug verbatim.
    const nb = notebookModel({ ambient: true });
    nb.focus(0);
    nb.clickRemoveIn(1, 0);
    nb.clickRemoveIn(1, 0);
    // Second click lands correctly only because the first one moved focus.
    expect(nb.names()).toEqual([["out"], ["select", "export"]]);
  });
});

describe("chainsWithCellSteps", () => {
  const chains = [
    { steps: [{ name: "genkey" }] },
    { steps: [{ name: "in" }, { name: "out" }] },
  ];

  it("touches only the named cell", () => {
    const next = chainsWithCellSteps(chains, 1, []);
    expect(next[0].steps.map((s) => s.name)).toEqual(["genkey"]);
    expect(next[1].steps).toEqual([]);
  });

  it("does not mutate the chains it was given", () => {
    chainsWithCellSteps(chains, 0, []);
    expect(chains[0].steps.map((s) => s.name)).toEqual(["genkey"]);
  });

  it("grows the notebook rather than dropping a write past the end", () => {
    const next = chainsWithCellSteps(chains, 3, [{ name: "peek" }]);
    expect(next).toHaveLength(4);
    expect(next[2].steps).toEqual([]);
    expect(next[3].steps.map((s) => s.name)).toEqual(["peek"]);
  });

  it("carries everything about a cell that is not its steps", () => {
    // This seam rebuilt every chain as `{ steps }`, so clicking any chip's ×
    // stripped `peer`, `publish` and `publishSlots` from the *whole* notebook —
    // the defect `applyCellRecipeText` names in its own comment, still live on
    // the chip path. `comments` joined that set when comments started surviving
    // `serializeRecipe`: a sentence that survives the wire and then dies
    // because somebody removed a step is the same loss one layer out.
    //
    // Asserted on the untouched neighbour *and* on the edited cell, because
    // those are two different lines of the function and only one of them was
    // ever the reported symptom.
    const rich = [
      { steps: [{ name: "genkey" }], peer: "mara", publish: true, comments: ["why"] },
      { steps: [{ name: "out" }], peer: "ada", publishSlots: ["a"] },
    ];
    const next = chainsWithCellSteps(rich, 1, [{ name: "peek" }]);
    expect(next[0]).toEqual(rich[0]);
    expect(next[1]).toEqual({
      steps: [{ name: "peek" }],
      peer: "ada",
      publishSlots: ["a"],
    });
  });
});

describe("the hook cannot express an ambiently-targeted mutation", () => {
  it.each(MUTATIONS)("%s takes the cell as its first parameter", (name) => {
    expect(callbackSource(name)).toMatch(
      new RegExp(`const ${name} = useCallback\\(\\s*\\(\\s*cell: number\\s*[,)]`)
    );
  });

  it.each(MUTATIONS)("%s does not close over focusedCell", (name) => {
    const src = callbackSource(name);
    expect(depsOf(src)).not.toContain("focusedCell");
    // Deps alone would pass if the body read `focusedCell` and someone forgot
    // to list it — which is exactly how a stale read gets in.
    expect(src).not.toMatch(/\bfocusedCell\b/);
  });

  it("has no focused-cell steps projection left for a mutation to reach for", () => {
    expect(HOOK).not.toMatch(/const steps = chains\[focusedCell\]/);
    expect(HOOK).not.toMatch(/setCellSteps\(focusedCell/);
  });

  it("reads a named cell's steps through one helper", () => {
    expect(HOOK).toMatch(
      /const stepsAt = useCallback\(\s*\(cell: number\): RecipeStep\[\] => chains\[cell\]\?\.steps \|\| \[\]/
    );
  });
});

describe("the shell names the cell on every mutation", () => {
  /**
   * `i` is the cell being rendered, `*.cell` comes off a chip path, and
   * `nb.focusedCell` is the deliberate "wherever the caret is" choice — read
   * from the current render, so it is a fact rather than a pending setter.
   */
  const CELL_EXPR = /^(i|nb\.focusedCell|[A-Za-z]\w*\.cell)$/;

  it.each(MUTATIONS)("passes a cell expression to every nb.%s call", (name) => {
    const calls = [...SHELL.matchAll(new RegExp(`nb\\.${name}\\(\\s*([^,()\\s]+)`, "g"))];
    expect(calls.length, `nb.${name} should be called from the shell`).toBeGreaterThan(0);
    for (const [, firstArg] of calls) {
      expect(firstArg, `nb.${name}(${firstArg}, …)`).toMatch(CELL_EXPR);
    }
  });

  it("never re-aims a mutation with the setter that caused this", () => {
    // The bug with one more argument: `setFocusedCell(i)` then a mutation on
    // `nb.focusedCell`, which is still the old cell for one more render.
    const names = MUTATIONS.join("|");
    const regression = new RegExp(
      `setFocusedCell\\([^)]*\\)[\\s\\S]{0,800}?nb\\.(${names})\\(\\s*nb\\.focusedCell`
    );
    expect(SHELL).not.toMatch(regression);
  });

  it("keeps the per-cell chip handlers on their own cell", () => {
    // The handlers RecipeChipFlow calls back into, all inside `chains.map((chain, i)`.
    expect(SHELL).toMatch(/nb\.removeStep\(path\.cell, path\.stem\)/);
    expect(SHELL).toMatch(/nb\.removeNestStep\(\s*path\.cell,/);
    expect(SHELL).toMatch(/nb\.insertOpAt\(path\.cell, path\.stem, name, opts\)/);
    expect(SHELL).toMatch(/nb\.reorderStem\(i, from\.stem, to\.stem\)/);
    expect(SHELL).toMatch(/nb\.reorderNest\(\s*i,/);
    expect(SHELL).toMatch(/nb\.replaceStep\(i, stem, "peek"\)/);
    expect(SHELL).toMatch(/nb\.addBranchWithStep\(i, stem, selector, name, opts\)/);
  });
});
