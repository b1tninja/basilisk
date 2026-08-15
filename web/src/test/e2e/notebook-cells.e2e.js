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

/**
 * Running one cell, and telling somebody who cannot see the screen.
 *
 * Two changes that share a browser because they share the surface: the cell
 * header grew a second Run, and the run status line grew a voice. Both are
 * only true in a rendered page — the scope has always been a field on the run
 * object, and an `aria-live` attribute is worth nothing until something
 * actually writes into the element carrying it — so node cannot witness
 * either.
 *
 * One page, no session, the same three distinguishable cells as above.
 */
describe.runIf(availability.ok)("running one cell, and saying so out loud", () => {
  /**
   * Three cells where the third **reads a slot the second writes**.
   *
   * That dependency is the whole reason this set differs from `CELLS` above.
   * Before a per-cell control existed, cell 2 could only ever be reached by a
   * run that had already executed cell 1 in the same pass, so "this cell's
   * inputs are not in slots" was a state the notebook could not be put into by
   * pressing anything. It can now, and what it says is under test.
   */
  const RUNS = [
    { recipe: "bytes deadbeef | encode hex | out $a", shows: "deadbeef" },
    { recipe: "bytes cafebabe | encode hex | out $b", shows: "cafebabe" },
    { recipe: "$b | out $c", shows: "cafebabe" },
  ];

  /** @type {Awaited<ReturnType<typeof openPeers>>} */
  let mesh;
  /** @type {import("playwright").Page} */
  let page;

  /** What a screen reader would have been handed, whitespace squeezed. */
  const announced = async (p) =>
    (await p.locator("[data-run-announcer]").innerText()).replace(/\s+/g, " ").trim();

  beforeAll(async () => {
    mesh = await openPeers({ count: 1, path: "/toolkit" });
    page = mesh.peers[0].page;
    await page.getByRole("button", { name: "Cell", exact: true }).click();
    await page.getByRole("button", { name: "Cell", exact: true }).click();
    for (const [i, c] of RUNS.entries()) await writeCell(page, i, c.recipe);
  }, 120000);

  afterAll(async () => {
    await mesh?.close();
  });

  it("offers a second, differently named Run on every runnable cell", async () => {
    // Named, not iconographic. The assertion is `getByRole` with the accessible
    // name and then the visible text, because a control whose difference from
    // the one beside it lives in a `title` is a control most screen readers and
    // every touch device never learn the difference from.
    for (const i of [0, 1, 2]) {
      const only = cell(page, i).getByRole("button", {
        name: `Run only cell ${i}, without the cells below it`,
      });
      await only.waitFor({ state: "visible", timeout: 10000 });
      expect(await only.innerText()).toBe("Only this cell");
    }
    // The live region exists from first paint, before anything has been
    // written into it. A region created at the moment it first has something
    // to say is a region whose first announcement is dropped.
    const region = page.locator("[data-run-announcer]");
    expect(await region.count()).toBe(1);
    expect(await region.getAttribute("aria-live")).toBe("polite");
    expect(await announced(page)).toBe("");
  });

  it("refuses a cell whose inputs are not in slots, and names it", async () => {
    // **First, deliberately.** Nothing has run on this page, so `$b` is in no
    // slot — the state a per-cell run can newly produce, reached here without
    // clearing anything, so the sentence under test is the refusal and not a
    // Clear session narration that arrived after it.
    await cell(page, 2).getByRole("button", { name: /^Run only cell 2/ }).click();
    await expect.poll(async () => await cellStatus(page, 2), { timeout: 60000 }).toBe("error");
    await runSettled(page);

    const said = await announced(page);
    // Named. A reader who cannot see which row went red is told which one did,
    // and `Cell [2] — …` is `startRun`'s own prefix, the same one on screen.
    expect(said, `the live region: ${said}`).toMatch(/^Cell \[2\] — /);
    // And it carries the refusal, not a genre. "Failed" is the status line's
    // word for this state and names nothing anybody can act on; the sentence
    // that names the missing slot is the one worth interrupting for.
    expect(said, `the live region: ${said}`).not.toBe("Failed");
    expect(said, `the live region: ${said}`).toContain("$b");
    // Nothing above it was touched — a refusal that had quietly run cell 1 to
    // satisfy itself would be a different control than the one advertised.
    expect(await cellStatus(page, 1)).toBe("idle");
  });

  it("runs that cell and stops, where Run would have walked to the end", async () => {
    // The reproduction this exists for: pressing Run on cell 1 leaves cells 1
    // *and* 2 with answers. Both directions are asserted — the cell ran, and
    // the one under it did not — because a control that runs nothing at all
    // also satisfies "cell 2 did not run".
    await cell(page, 1).getByRole("button", { name: /^Run only cell 1/ }).click();
    await expect.poll(async () => await cellStatus(page, 1), { timeout: 60000 }).toBe("ok");
    await runSettled(page);
    expect(await cell(page, 1).innerText(), "the cell that was run has no answer").toContain(
      RUNS[1].shows
    );
    expect(
      await cellStatus(page, 2),
      "Only this cell walked on into the cell below it"
    ).toBe("error");

    // Run itself is untouched — the muscle memory the decision protects.
    // From the same cell it still carries on downward, and cell 2 now has
    // what it needs.
    await cell(page, 1).getByRole("button", { name: "Run", exact: true }).click();
    await expect.poll(async () => await cellStatus(page, 2), { timeout: 60000 }).toBe("ok");
    await runSettled(page);
  });

  it("is reached from Run by one Tab, with no pointer anywhere", async () => {
    // The whole point of a *secondary* control is that it is one: in the tab
    // order, and beside the thing it is secondary to rather than somewhere a
    // keyboard has to hunt for.
    await cell(page, 1).getByRole("button", { name: "Run", exact: true }).focus();
    await page.keyboard.press("Tab");
    expect(
      await page.evaluate(() => document.activeElement?.getAttribute("aria-label")),
      "Tab from Run did not land on the per-cell control"
    ).toBe("Run only cell 1, without the cells below it");
    // And it runs from the keyboard, which is the half an `onClick` alone
    // would leave undone.
    await page.keyboard.press("Enter");
    await expect.poll(async () => await cellStatus(page, 1), { timeout: 60000 }).toBe("ok");
    await runSettled(page);
  });

  it("announces the run's outcome and never its per-cell ticker", async () => {
    // **The assertion that makes this a mechanism rather than an attribute.**
    // An `aria-live` div nothing writes to is the dead-mechanism defect in
    // accessibility clothing, so what is pinned is that the element's content
    // *changes*, and changes to the right thing.
    //
    // **Sampled during the run, and this is not a detail.** The first version
    // of this read the region once the run had settled and asserted the ticker
    // was not in it — which is true either way, because by then it holds
    // "Done". Routing `Running cell ${i}…` through `narrate` left that version
    // green: a screen reader would have been interrupted once per cell and the
    // final value would have looked identical. A MutationObserver over the
    // region is the only witness to what was *said*, as opposed to what is
    // left showing.
    await page.evaluate(() => {
      const region = document.querySelector("[data-run-announcer]");
      const said = [];
      const push = () => {
        const t = (region.textContent || "").trim();
        if (t && said[said.length - 1] !== t) said.push(t);
      };
      push();
      const obs = new MutationObserver(push);
      obs.observe(region, { childList: true, subtree: true, characterData: true });
      Object.assign(window, { __said: said, __saidObs: obs });
    });

    await page.getByRole("button", { name: "Run all" }).click();
    await expect.poll(async () => await announced(page), { timeout: 120000 }).toBe("Done");
    await runSettled(page);

    const said = await page.evaluate(() => {
      window.__saidObs.disconnect();
      return window.__said;
    });
    // It spoke, and the last thing it said is the outcome.
    expect(said, `the live region said: ${JSON.stringify(said)}`).toContain("Done");
    // And nothing in the whole sequence was the ticker. Three cells ran; one
    // interruption per cell is exactly what drowns the announcement that
    // matters, which is why it is kept out.
    const transcript = said.join(" · ");
    expect(transcript, "the per-cell ticker reached the live region").not.toMatch(/Running cell/);
    expect(transcript, "the run's opening tick reached the live region").not.toMatch(/Running…/);
    // The line on screen is the *other* half of the split, and it is still
    // there — silencing the ticker must not have blanked it.
    const line = page.locator("[data-run-state]").locator("xpath=following-sibling::p[1]");
    expect((await line.innerText()).trim()).toBe("Done");
  });

  it("says the same word twice when it happens twice", async () => {
    // A live region announces on *change*. Two runs both ending "Done" render
    // byte-identical text, so without the counter the second run is silent —
    // the failure mode that looks exactly like a working feature. What is
    // observable from outside is whether the node carrying the text is new.
    const stamped = () =>
      page.evaluate(() => {
        const span = document.querySelector("[data-run-announcer] span");
        if (!span) return null;
        // If React re-used the node, the stamp survives; if the key changed
        // and it remounted, the stamp is gone with the old element.
        const seen = /** @type {*} */ (span).__seen === true;
        /** @type {*} */ (span).__seen = true;
        return seen;
      });
    expect(await announced(page)).toBe("Done");
    expect(await stamped()).toBe(false);
    await page.getByRole("button", { name: "Run all" }).click();
    await expect.poll(async () => await announced(page), { timeout: 120000 }).toBe("Done");
    await runSettled(page);
    expect(
      await stamped(),
      "the second Done re-used the same node, so a screen reader heard nothing"
    ).toBe(false);
  });
});
