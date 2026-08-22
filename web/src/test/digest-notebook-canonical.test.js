/**
 * A manifest states a notebook's identity twice, and the two must agree.
 *
 * `buildRunManifest` digests the notebook once whole (`recipeDigest`) and once
 * per cell (`cells[].recipeDigest`). The per-cell digests go through
 * `serializeRecipe`, so a doubled space between two steps changes nothing. The
 * whole was the raw source text, so a doubled space changed everything — three
 * matching cell digests underneath a notebook digest saying two peers held two
 * different notebooks, and `handoff.js` refuses on the coarse one. The fine
 * evidence said the offer was fine and the coarse claim threw it out.
 *
 * `docs/OPEN-FINDINGS.md` §1.2 recorded exactly that, with exactly this
 * fixture. The first test here is that table, asserted.
 *
 * ## What is *not* being conceded
 *
 * `handoffContext` refuses to substitute `serializeRecipe(chains)` for `source`
 * because serializing **drops blank cells**, which renumbers every cell after
 * one — an offer naming cell 4 that the peer's plan calls 3. That argument is
 * correct and this does not touch it. `canonicalCellSources` emits one entry per
 * chain and spells a blank cell `""`, so the chain list that goes in comes out
 * one-for-one. The numbering tests below are the ones that would catch a fix
 * that bought agreement by collapsing cells, which is the failure mode worth
 * more than the bug.
 */
import { describe, expect, it } from "vitest";
import { handoffContext } from "../lib/toolkit/handoff-shell.js";
import {
  canonicalCellSources,
  canonicalNotebookSource,
  compileRecipe,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { planChains, planRun } from "../lib/toolkit/plan.js";
import { digestText } from "../lib/toolkit/receipt.js";

const FPR_M = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_O = "91C7E6D5C4B3A29180716253443526170819AABB";
const ROSTER = { mara: FPR_M, okafor: FPR_O };

/** The `handoff-shell` fixture the finding was measured on. */
const HANDED = `@mara
bytes deadbeef | encode hex | out $seed | publish

@okafor
in $seed | decode hex | encode base64 | out $b64 | publish

@mara
in $b64 | decode base64 | encode hex | out $final
`;

const ctxFor = (source) => handoffContext({ source, me: "mara", roster: ROSTER });

/** Both levels of the manifest's claim, as they would be compared on the wire. */
async function identity(source) {
  const ctx = await ctxFor(source);
  return {
    notebook: ctx.manifest.recipeDigest,
    cells: ctx.manifest.cells.map((c) => c.recipeDigest),
    indices: ctx.manifest.cells.map((c) => c.index),
    recipes: ctx.manifest.cells.map((c) => c.recipe),
    manifest: ctx.manifest,
    plan: ctx.plan,
  };
}

describe("the notebook digest and its own cell digests agree", () => {
  it("survives the doubled space that split them", async () => {
    // OPEN-FINDINGS §1.2's fixture: one extra space, nothing an author would
    // call a different notebook.
    const spaced = HANDED.replace("| out $seed | publish", "|  out $seed | publish");
    expect(spaced).not.toBe(HANDED);

    const a = await identity(HANDED);
    const b = await identity(spaced);

    // The per-cell evidence always agreed. That half was never the bug.
    expect(b.cells).toEqual(a.cells);
    // The coarse claim used to disagree with it. Now it does not.
    expect(b.notebook).toBe(a.notebook);
  });

  it("cannot disagree with itself, whatever the notebook", async () => {
    // Structural, not a sample: the notebook's canonical text *is* the cells'
    // own texts joined, so there is no notebook for which the two levels could
    // differ. A fix that digested some other canonical form would pass the test
    // above and fail this one.
    for (const source of [HANDED, `random 32 | out $a`, `# note\n@*\nbytes ff | out $b`]) {
      const { manifest } = await identity(source);
      expect(manifest.recipeSource).toBe(manifest.cells.map((c) => c.recipe).join("\n\n"));
      expect(manifest.recipeDigest).toBe(await digestText(manifest.recipeSource));
    }
  });

  it("ignores exactly what the cell digests ignore", async () => {
    const base = await identity(HANDED);
    /** Differences `serializeRecipe` normalises away inside a cell. */
    const same = {
      "doubled space": HANDED.replace("| out $seed", "|  out $seed"),
      "space before the pipe": HANDED.replace("encode hex |", "encode hex   |"),
      "no trailing newline": HANDED.trimEnd(),
      "leading blank lines": `\n\n${HANDED}`,
      "trailing blank lines": `${HANDED}\n\n\n`,
      "extra blank lines between cells": HANDED.replace(/\n\n/g, "\n\n\n\n"),
      "trailing spaces on a line": HANDED.replace("| publish\n", "| publish   \n"),
    };
    for (const [why, source] of Object.entries(same)) {
      const got = await identity(source);
      expect(got.cells, why).toEqual(base.cells);
      expect(got.notebook, why).toBe(base.notebook);
    }
  });

  it("notices exactly what the cell digests notice", async () => {
    const base = await identity(HANDED);
    /** Differences that change a cell's canonical text, or the list of them. */
    const different = {
      "a step changed": HANDED.replace("encode base64", "encode hex"),
      "a slot renamed": HANDED.replace(/\$b64/g, "$b64x"),
      "a peer reassigned": HANDED.replace("@okafor", "@*"),
      "a publish dropped": HANDED.replace("out $seed | publish", "out $seed"),
      "a comment added": `# a note\n${HANDED}`,
      "a cell appended": `${HANDED}\n@mara\nbytes cafe | out $extra\n`,
      "the same cells reordered": [
        "@okafor\nin $seed | decode hex | encode base64 | out $b64 | publish",
        "@mara\nbytes deadbeef | encode hex | out $seed | publish",
        "@mara\nin $b64 | decode base64 | encode hex | out $final",
      ].join("\n\n"),
    };
    for (const [why, source] of Object.entries(different)) {
      const got = await identity(source);
      expect(got.notebook, why).not.toBe(base.notebook);
    }
  });
});

describe("canonicalisation moves no cell", () => {
  /**
   * Sources whose blank-line spelling differs and whose cells do not. Recipe
   * *text* has no spelling for an empty cell — the parser flushes a chain only
   * when it has steps — so what "blank cells" means in a source is these.
   */
  const shapes = {
    plain: HANDED,
    leading: `\n\n${HANDED}`,
    trailing: `${HANDED}\n\n\n`,
    widened: HANDED.replace(/\n\n/g, "\n\n\n\n"),
    both: `\n\n\n${HANDED.trimEnd()}\n\n\n`,
  };

  it("numbers every cell the way the plan and the notebook do", async () => {
    for (const [why, source] of Object.entries(shapes)) {
      const { manifest, plan } = await identity(source);
      const chains = planChains(compileRecipe(source));
      expect(manifest.cells.length, why).toBe(chains.length);
      // `cells[i].index === i` is `manifest.js`'s v2 rule, and the number the
      // plan places by. A document where the two differ is malformed.
      expect(manifest.cells.map((c) => c.index), why).toEqual(
        chains.map((_, i) => i)
      );
      expect(plan.cells.map((c) => c.index), why).toEqual(chains.map((_, i) => i));
    }
  });

  it("gives every blank-line shape the same three cells", async () => {
    const base = await identity(HANDED);
    for (const [why, source] of Object.entries(shapes)) {
      const got = await identity(source);
      expect(got.indices, why).toEqual([0, 1, 2]);
      expect(got.cells, why).toEqual(base.cells);
      expect(got.notebook, why).toBe(base.notebook);
    }
  });

  it("keeps a blank cell as a blank cell rather than closing the gap", () => {
    // The chain list is where an empty cell can exist — the editor holds one
    // (`useNotebook`'s `addCell` pushes `{ steps: [] }`), and `serializeRecipe`
    // drops it. `canonicalCellSources` must not: dropping it is what shifts
    // cell 4 to cell 3 and makes an offer name a cell the peer calls something
    // else.
    const chains = compileRecipe(HANDED).ast.chains;
    const withBlank = [chains[0], { steps: [] }, chains[1], chains[2], { steps: [] }];

    const dense = canonicalCellSources(chains);
    const sparse = canonicalCellSources(withBlank);

    expect(sparse).toHaveLength(5);
    expect(sparse[1]).toBe("");
    expect(sparse[4]).toBe("");
    // Every cell after the blank kept its own text at its own position.
    expect(sparse[0]).toBe(dense[0]);
    expect(sparse[2]).toBe(dense[1]);
    expect(sparse[3]).toBe(dense[2]);
    // …and `serializeRecipe`, which is right to drop them, still does.
    expect(serializeRecipe(withBlank).split("\n\n")).toHaveLength(3);
    // A blank cell is part of the notebook's identity: adding one is an edit.
    expect(canonicalNotebookSource(withBlank)).not.toBe(canonicalNotebookSource(chains));
  });

  it("is one entry per chain for every notebook shape", () => {
    for (const source of Object.values(shapes)) {
      const chains = planChains(compileRecipe(source));
      expect(canonicalCellSources(chains)).toHaveLength(chains.length);
    }
  });
});

describe("what the canonical form is, and what it is not", () => {
  it("is the text the shell already hands in, for a notebook it wrote", async () => {
    // The compatibility claim. `useNotebook` derives `source` as
    // `serializeRecipe(chains)` before calling `handoffContext`, so for the
    // app's own caller the canonical form is byte-identical to what it already
    // passed — the digest on the wire does not move for a notebook this build
    // produced. (It does move for text that was not already canonical; see the
    // report on the wire change.)
    const source = serializeRecipe(compileRecipe(HANDED).ast);
    const { manifest } = await identity(source);
    expect(manifest.recipeSource).toBe(source);
    expect(manifest.recipeDigest).toBe(await digestText(source));
  });

  it("keeps the source verbatim when there is no notebook to canonicalise", async () => {
    // A notebook that does not parse has no chains. Recording it as an empty
    // manifest would be a commitment to a notebook nobody has; the honest
    // answer is the text, unread.
    const broken = `nosuchop | out $a`;
    const { manifest } = await identity(broken);
    expect(manifest.cells).toHaveLength(0);
    expect(manifest.recipeSource).toBe(broken);
    expect(manifest.recipeDigest).toBe(await digestText(broken));
  });

  it("still refuses two peers who really are holding different notebooks", async () => {
    // The point of the digest. Canonicalising must not make an edit look like
    // whitespace — `handoff.js`'s `unknown-manifest` has to keep firing.
    const mine = await identity(HANDED);
    const theirs = await identity(`${HANDED}\n@okafor\nbytes cafe | out $extra\n`);
    expect(theirs.notebook).not.toBe(mine.notebook);
    expect(theirs.cells.length).not.toBe(mine.cells.length);
  });

  it("agrees with planRun about how many cells there are", async () => {
    const { manifest } = await identity(HANDED);
    const plan = planRun(compileRecipe(HANDED), { me: "mara", roster: ROSTER });
    expect(manifest.cells.length).toBe(plan.cells.length);
    expect(manifest.cells.map((c) => c.peer)).toEqual(["mara", "okafor", "mara"]);
  });
});
