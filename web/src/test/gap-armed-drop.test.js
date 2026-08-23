/**
 * The armed branch's caret is a drop target, and now it says so.
 *
 * `gap-marker.test.js` holds the component half — a `pending` gap with no
 * `onClick` stays a `<span>` under a drag hover and takes
 * `.cell-recipe-gap-caret-drop-active` instead of falling through to a `+` that
 * nothing would answer. This file holds the other half: that the one call site
 * with no `onClick` actually *passes* `active`, which it did not, because doing
 * so used to produce that dead `+`.
 *
 * ## What this can and cannot measure
 *
 * `InsertGap` is stubbed so the props the call site hands it can be read
 * directly — the question is what `RecipeChipFlow` passes, and the real
 * component's answer to those props is already pinned next door.
 *
 * **The `armedDrop` state round trip is not covered here and no unit test in
 * this suite can cover it.** `vitest.config.js` runs in `node` with no DOM, so
 * there is nothing to dispatch a `dragover` at and no renderer to commit the
 * `setArmedDrop` it causes; a server render is one pass. What is pinned is that
 * `active` arrives as a boolean rather than being absent, that a leave handler
 * exists to clear it, and that `onDragOver` still refuses a drag carrying none
 * of the chip MIME types — the guard the accent now rides on, and the one that
 * would make the accent a lie if it were dropped.
 */
import { describe, expect, it, vi } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

const seen = vi.hoisted(() => []);

vi.mock("../toolkit/widgets/InsertGap.tsx", () => ({
  InsertGap: (props) => {
    seen.push(props);
    return React.createElement("span", { "data-stub-gap": "1" });
  },
}));

const { RecipeChipFlow } = await import("../toolkit/widgets/RecipeChipFlow.tsx");

const TEE = [
  {
    step: { name: "tee", label: "tee" },
    hasNest: true,
    nestKind: "tee",
    branches: [],
    body: [],
  },
];

/** Every `InsertGap` the flow rendered, in document order. */
function gaps(props) {
  seen.length = 0;
  renderToStaticMarkup(
    React.createElement(RecipeChipFlow, {
      cell: 0,
      stems: TEE,
      onSelect: () => {},
      onGap: () => {},
      onBranchHit: () => {},
      onReorder: () => {},
      onCancelArmed: () => {},
      armedBranch: { stem: 0, selector: ":public" },
      ...props,
    })
  );
  return seen;
}

/** The armed row's gap — the only one that arrives with no `onClick`. */
function armedGap(props) {
  const all = gaps(props);
  const found = all.filter((p) => !p.onClick);
  expect(found, `expected exactly one unwired gap, saw ${found.length} of ${all.length}`)
    .toHaveLength(1);
  return found[0];
}

const dt = (types) => ({
  dataTransfer: { types, getData: () => "", dropEffect: "" },
  preventDefault: vi.fn(),
  stopPropagation: vi.fn(),
});

describe("the armed caret's drop wiring", () => {
  it("is passed an active flag rather than none at all", () => {
    const gap = armedGap();
    // Presence *and* type. `undefined` is what shipped, and it is also what a
    // typo in the state name would hand back.
    expect(typeof gap.active).toBe("boolean");
    expect(gap.pending).toBe(true);
  });

  it("is passed a leave handler, so the accent has something to clear it", () => {
    expect(typeof armedGap().onDragLeave).toBe("function");
  });

  it("keeps refusing a drag that carries nothing it can accept", () => {
    const gap = armedGap();
    const foreign = dt(["Files"]);
    gap.onDragOver(foreign);
    expect(foreign.preventDefault).not.toHaveBeenCalled();
    // No preventDefault means no drop, so an accent lit here would promise one
    // that cannot land.
    expect(foreign.dataTransfer.dropEffect).toBe("");
  });

  it("accepts a step drag and names the effect a copy", () => {
    const gap = armedGap();
    const step = dt(["application/x-basilisk-step"]);
    gap.onDragOver(step);
    expect(step.preventDefault).toHaveBeenCalled();
    expect(step.dataTransfer.dropEffect).toBe("copy");
  });

  it("leaves the wired gaps wired", () => {
    // The change was scoped to the one site; the other gaps in the same render
    // must still arrive with a press and a leave.
    const wired = gaps().filter((p) => p.onClick);
    expect(wired.length).toBeGreaterThan(0);
    for (const p of wired) {
      expect(typeof p.onDragLeave).toBe("function");
      expect(typeof p.onDrop).toBe("function");
    }
  });
});
