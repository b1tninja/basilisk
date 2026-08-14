/**
 * Deleting a cell, in a browser, because that is the only place it goes wrong.
 *
 * A notebook cell is two things stored apart. Its *text* lives in React state as
 * one entry of `chains`; its *last run* — outputs, status, timing, the reason it
 * failed — lives in the kernel, keyed by the cell's index. Nothing keeps them in
 * step except the mutations that change what an index means, and there are two:
 * opening a different notebook (`loadRecipeText`, fixed at `f990efd` after
 * `placed-journey.e2e.js` step 6 found an adopted cell reading "ran 0s ago ·
 * 293ms") and deleting a cell.
 *
 * The second was still open, and it is the same defect. `deleteCell` cleared the
 * bucket at the deleted index and stopped, so every cell *below* it kept a
 * bucket that now belonged to the cell above it. Deleting cell 0 of a
 * three-cell notebook that had run left the notebook drawing:
 *
 *     [0] never run                      ← its recipe writes $b, and $b exists
 *     [1] ran 0s ago · 7ms   b  cafebabe ← its recipe says `out $c`
 *
 * — the middle cell's answer, under the middle cell's slot name, on a cell whose
 * text says it produces something else, with a timing for a run that never
 * happened there. The third bucket was orphaned at an index the notebook no
 * longer had, so nothing would ever wipe the bytes it owned.
 *
 * ## Why a browser for a one-line fix
 *
 * Because every layer under it was already right and stayed green. `remapCells`
 * has existed in `kernel.js` since the kernel did, with a unit test proving it
 * moves buckets correctly — and no product caller at all. `deleteCell` is a
 * `useCallback` inside a hook, so the seam where the two failed to meet is not
 * reachable from `environment: "node"`, and the failure is silent: a cell that
 * shows the wrong answer looks exactly like a cell that shows the right one.
 * The only witness is a person reading the screen, which is what this is.
 *
 * One browser, no session — nothing here crosses a machine boundary, and the
 * two-peer journeys should not pay for a defect that needs one page.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the notebook-cells suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[notebook-cells.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/**
 * Three cells whose answers cannot be mistaken for one another.
 *
 * Every assertion below is "this cell is showing *that* cell's output", so the
 * values have to be distinguishable at a glance and none may be a substring of
 * another. Hex of three unrelated words is the cheapest thing that is both.
 */
const CELLS = [
  { recipe: "bytes deadbeef | encode hex | out $a", shows: "deadbeef" },
  { recipe: "bytes cafebabe | encode hex | out $b", shows: "cafebabe" },
  { recipe: "bytes f00dface | encode hex | out $c", shows: "f00dface" },
];

/** One notebook cell, by index — the shell renders exactly one `<article>` each. */
const cell = (page, i) => page.locator("article").nth(i);

const cellStatus = (page, i) =>
  cell(page, i).locator("[data-cell-status]").getAttribute("data-cell-status");

/**
 * Type a pipeline into a cell, the way the Source view takes one.
 *
 * **Applies on blur**, so the `blur()` is the act and not a tidy-up — the same
 * correction `placed-journey.e2e.js` carries, for the same reason: without it
 * the text never reaches `chains` and every assertion is about a notebook the
 * shell does not have.
 */
async function writeCell(page, i, text) {
  const art = cell(page, i);
  await art.locator("button").filter({ hasText: /^Source$/ }).click();
  const box = art.locator("textarea");
  await box.waitFor({ state: "visible", timeout: 10000 });
  await box.fill(text);
  await box.blur();
}

/** Whether the run bar is between runs — the only "did it finish" the UI has. */
async function runSettled(page) {
  await expect
    .poll(async () => await page.locator("[data-run-state]").getAttribute("data-run-state"), {
      timeout: 120000,
      intervals: [250],
    })
    .toMatch(/^(idle|blocked)$/);
}

describe.runIf(availability.ok)("deleting a notebook cell", () => {
  /** @type {Awaited<ReturnType<typeof openPeers>>} */
  let mesh;
  /** @type {import("playwright").Page} */
  let page;

  beforeAll(async () => {
    mesh = await openPeers({ count: 1, path: "/toolkit" });
    page = mesh.peers[0].page;
  }, 120000);

  afterAll(async () => {
    await mesh?.close();
  });

  it("moves the cells below it up, and their answers with them", async () => {
    // Composed by pressing, like everything else here: a notebook opens with one
    // cell and the "+ Cell" button is how a person gets three.
    await page.getByRole("button", { name: "Cell", exact: true }).click();
    await page.getByRole("button", { name: "Cell", exact: true }).click();
    for (const [i, c] of CELLS.entries()) await writeCell(page, i, c.recipe);

    await page.getByRole("button", { name: "Run all" }).click();
    await runSettled(page);
    for (const [i, c] of CELLS.entries()) {
      expect(await cell(page, i).innerText()).toContain(c.shows);
    }

    await cell(page, 0).getByRole("button", { name: "Delete cell" }).click();
    expect(await page.locator("article").count()).toBe(2);

    // The two survivors, each still wearing its own answer. Asserted in both
    // directions — that the right value is there *and* that the neighbour's is
    // not — because the defect's whole shape is a value that is present and
    // belongs to somebody else. A one-sided check passes on a notebook showing
    // every output on every cell.
    const [top, bottom] = [await cell(page, 0).innerText(), await cell(page, 1).innerText()];
    expect(top, "the cell that moved up lost its own answer").toContain("cafebabe");
    expect(top, "the deleted cell's answer stayed at index 0").not.toContain("deadbeef");
    expect(bottom, "the last cell lost its answer to the orphaned bucket").toContain("f00dface");
    expect(bottom, "the last cell is wearing the answer of the cell above it").not.toContain(
      "cafebabe"
    );

    // And the status line, which is the other half of the same lie: a cell that
    // ran here says so, and neither of these has stopped being a cell that ran.
    expect(await cellStatus(page, 0), "a cell that ran here reads as never run").toBe("ok");
    expect(await cellStatus(page, 1)).toBe("ok");
  });

  it("keeps the answers of the cells above a deletion where they are", async () => {
    // The other direction, and the one a shift-everything fix would break:
    // deleting from the bottom must move nothing. Two cells are left from the
    // step above (`$b`, `$c`); delete the lower one and the upper is untouched.
    await cell(page, 1).getByRole("button", { name: "Delete cell" }).click();
    expect(await page.locator("article").count()).toBe(1);
    expect(await cell(page, 0).innerText()).toContain("cafebabe");
    expect(await cellStatus(page, 0)).toBe("ok");
  });
});
