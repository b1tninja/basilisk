/**
 * The planner changes nothing about a recipe that names no peer.
 *
 * `planRun` is new machinery reading declarations that were already there, and
 * the one property that makes it safe to add is that it is *inert* on every
 * recipe written before it existed. A plan is not an opinion about how a
 * notebook should run — it is a reading of what the recipe says — so a recipe
 * that says nothing about peers must read as exactly the single-runner
 * behaviour the engine has always had.
 *
 * Asserted differentially rather than by example, over the three corpora this
 * repo already keeps: every shipped preset, every verb-smoke case (the
 * exhaustive registry sweep), and every fence in `docs/RECIPE.md` that
 * compiles. A hand-picked list of "recipes that still work" proves that
 * somebody picked well; a sweep proves the pass is inert.
 *
 * What "identical to today" means, precisely, and each clause is a way the
 * pass could have gone wrong:
 *
 * - `play: "solo"` — no header anywhere.
 * - every cell `mine`, `runsOn: []` — nothing was placed on anyone.
 * - `refusals: []` — no existing recipe becomes unrunnable.
 * - `asks: []` — no existing recipe starts asking questions. The vault and
 *   keying asks are the ones that would fire here if their gate were wrong,
 *   and both are gated on the notebook being placed at all.
 * - `waits: []` — nothing waits for anybody.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PRESETS, compileRecipe, migrateRecipe, recipeChains } from "../lib/toolkit/recipe.js";
import { planRun, summarizePlan } from "../lib/toolkit/plan.js";
import { listVerbSmokeCases } from "./helpers/verb-smoke.js";

const RECIPE_MD = fileURLToPath(new URL("../../../docs/RECIPE.md", import.meta.url));

/** Every fenced block in the normative grammar doc. */
function docFences() {
  // Newlines normalised before matching. `git checkout` rewrites the working
  // tree to CRLF on Windows, and the fence pattern wants a bare `\n` after the
  // marker — so this returned **zero** fences on a fresh Windows clone and the
  // sweep silently swept nothing. CI runs on Ubuntu, where the checkout is LF,
  // so nothing would have caught it there either. Same shape as the CRLF bug
  // in `otp-code-kind.test.js`: a test that passes on the line endings its
  // author happened to have.
  const text = readFileSync(RECIPE_MD, "utf8").replace(/\r\n/g, "\n");
  /** @type {string[]} */
  const blocks = [];
  const re = /```[a-z]*\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(text))) blocks.push(m[1]);
  return blocks;
}

/** @param {{ ast: * }} compiled */
function hasHeader(compiled) {
  return recipeChains(compiled.ast).some((c) => c.peer);
}

/**
 * The assertion, once. `plan` is compared field by field rather than against a
 * snapshot so a failure names which clause broke.
 * @param {string} label @param {string} src
 */
function expectInert(label, src) {
  const compiled = compileRecipe(src);
  const plan = planRun(compiled);
  expect(plan.play, label).toBe("solo");
  expect(plan.ok, label).toBe(true);
  expect(plan.bound, label).toBe(false);
  expect(plan.peers, label).toEqual([]);
  expect(plan.refusals, label).toEqual([]);
  expect(plan.asks, label).toEqual([]);
  expect(plan.waits, label).toEqual([]);
  expect(plan.counts.solo, label).toBe(plan.cells.length);
  for (const cell of plan.cells) {
    expect(cell.runsOn, `${label} cell ${cell.index}`).toEqual([]);
    expect(cell.mine, `${label} cell ${cell.index}`).toBe(true);
    expect(cell.declared, `${label} cell ${cell.index}`).toBe(false);
    expect(cell.forced, `${label} cell ${cell.index}`).toBe(false);
    expect(cell.basis, `${label} cell ${cell.index}`).toBe("solo");
    expect(cell.kind, `${label} cell ${cell.index}`).toBe("witnessed");
    expect(cell.why, `${label} cell ${cell.index}`).toContain("runs here");
  }
  // The cells the plan lists are the cells the recipe has, numbered by
  // position and none of them dropped — a plan that dropped one would satisfy
  // every clause above and describe a shorter notebook than the one about to
  // run. No corpus entry here has a blank cell (recipe text cannot hold one),
  // so this is also the statement that the numbering did not move under the
  // corpora it was supposed to leave alone.
  expect(plan.cells.map((c) => c.index), label).toEqual(
    recipeChains(compiled.ast).map((_, i) => i)
  );
  return plan;
}

describe("every shipped preset plans exactly as it runs today", () => {
  it("has presets to sweep", () => {
    expect(PRESETS.length).toBeGreaterThan(10);
  });
  for (const preset of PRESETS) {
    it(`${preset.id} is inert`, () => {
      expectInert(preset.id, preset.recipe);
    });
  }
});

describe("every verb-smoke case plans exactly as it runs today", () => {
  const cases = listVerbSmokeCases();
  it("has cases to sweep", () => {
    expect(cases.length).toBeGreaterThan(100);
  });
  it("is inert across the whole registry sweep", () => {
    let planned = 0;
    /** @type {string[]} */
    const headered = [];
    for (const c of cases) {
      const src = migrateRecipe(String(c.recipe || "")).recipe;
      // `hkp.get` cases carry a `__FPR__` placeholder the async catalog fills.
      // A placeholder is not a peer question, so the case is skipped rather
      // than made to depend on a seeded vault.
      if (!src.trim() || src.includes("__FPR__")) continue;
      const compiled = compileRecipe(src);
      if (!compiled.validation.ok) continue;
      if (hasHeader(compiled)) {
        headered.push(c.id);
        continue;
      }
      expectInert(c.id, src);
      planned++;
    }
    expect(planned).toBeGreaterThan(100);
    // Pinned rather than skipped. The sweep's whole value is that a headered
    // recipe cannot enter a corpus unnoticed — if one does, this list names
    // it and somebody has to say what it should plan to.
    expect(headered).toEqual(["run.manifest"]);
  });

  it("plans the one placed case in the sweep", () => {
    const c = listVerbSmokeCases().find((x) => x.id === "run.manifest");
    const plan = planRun(compileRecipe(migrateRecipe(String(c.recipe)).recipe));
    expect(plan.ok).toBe(true);
    expect(plan.play).toBe("placed");
    expect(plan.peers).toEqual(["mara"]);
    // Cell 0 is `@mara publish`; cell 1 has no header and reads only what
    // cell 0 published, so everybody runs it.
    expect(plan.cells.map((x) => [x.kind, x.runsOn])).toEqual([
      ["placed", ["mara"]],
      ["witnessed", []],
    ]);
    expect(plan.asks).toEqual([]);
  });
});

describe("every docs/RECIPE.md fence that compiles plans exactly as it runs today", () => {
  const fences = docFences();
  it("found the fences", () => {
    expect(fences.length).toBeGreaterThan(10);
  });
  it("is inert across the normative grammar doc", () => {
    let planned = 0;
    /**
     * The headered fences, named by their own first header line rather than by
     * their index in the file. An index re-points itself the moment a fence is
     * added above it, which is how a pin like this stops meaning anything.
     * @type {string[]}
     */
    const headered = [];
    for (const [i, block] of fences.entries()) {
      // A fence is prose, EBNF or a recipe, and the doc does not label which.
      // Whether it compiles is the discriminator, and it is the right one:
      // this sweep is about recipes the toolkit accepts.
      const compiled = compileRecipe(block);
      if (!compiled.validation.ok) continue;
      if (hasHeader(compiled)) {
        headered.push(String(block.split("\n").find((l) => l.startsWith("@")) || `fence ${i}`));
        continue;
      }
      expectInert(`RECIPE.md fence ${i}`, block);
      planned++;
    }
    expect(planned).toBeGreaterThanOrEqual(5);
    // Three, and this says which. The second arrived with `publish=$slot`: the
    // doc has to show a dealer publishing one of the three things its cell
    // writes, because that is the case the modifier exists for and a grammar
    // reference that only shows the all-or-nothing form does not document it.
    // The third is the Comments section's example, and it is headered on
    // purpose — the rule it states is *where* a cell's comments go, and "above
    // the header" cannot be shown by an example with no header.
    expect(headered).toEqual([
      "@alice",
      "@mara publish=$commitments",
      "@mara publish",
    ]);
  });

  it("plans the doc's own placement example the way the doc reads it", () => {
    // The doc's example used to end on `@*`, and this asserted it planned
    // clean. It no longer does: a rendezvous is refused, so the example was
    // changed to `@bob` in the same commit — a manual telling you to write a
    // header the planner refuses is worse than no manual. The third cell is now
    // an ordinary placed one, which is exactly what the paragraph beneath the
    // table tells a reader to write instead.
    const block = docFences().find((b) => b.includes("\n@alice publish\n"));
    const plan = planRun(compileRecipe(String(block)));
    expect(plan.ok).toBe(true);
    expect(plan.play).toBe("placed");
    expect(plan.cells.map((c) => [c.kind, c.basis])).toEqual([
      ["placed", "header"],
      ["placed", "secret-locality"],
      ["placed", "header"],
    ]);
    // Cell 1 is the interesting one: it carries `@alice publish` *and* could
    // not have run anywhere else. `declared` and `forced` are separate fields
    // precisely so a redundant header reads as redundant rather than as the
    // reason — the basis is the data, and the header agrees with it.
    expect(plan.cells[1].declared).toBe(true);
    expect(plan.cells[1].forced).toBe(true);
    expect(plan.cells[1].why).toContain("$kpA");
    // Cell 0 is declared and *not* forced: `genkey` reads nothing anyone owns,
    // so `@alice` there is a choice the author made.
    expect(plan.cells[0].declared).toBe(true);
    expect(plan.cells[0].forced).toBe(false);
    expect(plan.counts).toMatchObject({ forced: 1, chosen: 2, rendezvous: 0 });
  });
});

describe("the summary says so too", () => {
  it("names the single runner rather than a play", () => {
    const plan = planRun(compileRecipe("bytes deadbeef | encode hex | out $a"));
    expect(summarizePlan(plan)).toBe(
      "1 cell, one runner — this notebook names no peers"
    );
  });
});
