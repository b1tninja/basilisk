/**
 * The two run documents spell the notebook the same way, and the way their own
 * cells do.
 *
 * `run.receipt` and `run.manifest` each declare a `recipeSource` and digest it,
 * and `manifestHonouredBy` compares those two digests — so the one thing they
 * must never do is spell the notebook differently. They agreed by both taking
 * `bindings.receipt.recipeSource` raw, which kept them equal to each other and
 * unequal to their own contents: every cell in both is
 * `serializeRecipe({ chains: [chain] })`, so a doubled space between two steps
 * moved the notebook digest and no cell digest.
 *
 * That is the contradiction `handoff-shell` was rewritten to remove, and this
 * is the same fix in the other producer. One function builds the text now, so
 * the two ops cannot drift apart.
 *
 * Tolerant per cell on purpose, and that is a real difference from
 * `canonicalCellSources`: a run document is a *record*, so a cell that will not
 * serialize is written as `""` rather than failing the document into
 * non-existence. The handoff path stays strict, because there the same digest
 * is a gate and silently digesting an unreadable cell as empty would be worse
 * than refusing.
 */
import { describe, expect, it } from "vitest";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { parseManifest } from "../lib/toolkit/manifest.js";

/** The blank line between two cells. */
const GAP = String.fromCharCode(10, 10);

/** The context the shell supplies — the same one `run.receipt` reads. */
const notebook = (source, chains) => ({
  receipt: { recipeSource: source, label: "n", ...(chains ? { chains } : {}) },
});

/** Run `src` and hand back the artifacts by filename. */
async function filesOf(src, chains) {
  const { ast } = compileRecipe(src);
  const arts = await runRecipe(ast, notebook(src, chains));
  return new Map(arts.filter((a) => a.filename).map((a) => [a.filename, a.content]));
}

// `publish` needs a peer header, so the first cell carries one — which also
// makes `cells[].peer` a real value rather than "" everywhere.
const BODY =
  "@mara" + String.fromCharCode(10) + "bytes deadbeef | encode hex | out $a | publish" +
  GAP + "in $a | out $b" + GAP;

describe("a run manifest states its notebook the way it states its cells", () => {
  it("finds the document it is measuring", () => {
    // An empty sweep passes every assertion below it.
    const { validation } = compileRecipe(BODY + 'run.manifest "T" | out $manifest');
    expect(validation.errors, "the fixture stopped compiling").toEqual([]);
  });

  it("joins its own cells rather than restating the source", async () => {
    const files = await filesOf(BODY + 'run.manifest "T" | out $manifest');
    const m = parseManifest(files.get("manifest.txt"));
    expect(m.cells).toHaveLength(3);
    expect(m.recipeSource).toBe(m.cells.map((c) => c.recipe).join(GAP));
  });

  it("ignores what its cells ignore", async () => {
    // A doubled space between two steps. Invisible to every cell digest, and
    // it used to change the notebook digest underneath them.
    const plain = BODY + 'run.manifest "T" | out $manifest';
    const spaced = plain.replace("| encode hex", "|  encode hex");
    expect(spaced, "the mutation did not apply").not.toBe(plain);
    const a = parseManifest((await filesOf(plain)).get("manifest.txt"));
    const b = parseManifest((await filesOf(spaced)).get("manifest.txt"));
    expect(b.recipeDigest).toBe(a.recipeDigest);
    expect(b.cells.map((c) => c.recipeDigest)).toEqual(a.cells.map((c) => c.recipeDigest));
  });

  it("notices what its cells notice", async () => {
    // The other half, or the assertion above is satisfied by digesting nothing.
    const plain = BODY + 'run.manifest "T" | out $manifest';
    const changed = plain.replace("encode hex", "encode base64");
    const a = parseManifest((await filesOf(plain)).get("manifest.txt"));
    const b = parseManifest((await filesOf(changed)).get("manifest.txt"));
    expect(b.recipeDigest).not.toBe(a.recipeDigest);
  });
});

describe("the receipt and the manifest describe one notebook", () => {
  it("states the same recipe source in both, so their digests compare", async () => {
    const src =
      "bytes deadbeef |  encode hex | out $a | publish" +
      GAP +
      'run.manifest "T" | out $manifest' +
      GAP +
      "run.receipt | out $receipt";
    const files = await filesOf(src);
    const m = parseManifest(files.get("manifest.txt"));
    const r = JSON.parse(files.get("receipt.json") ?? files.get("receipt.txt") ?? "null");
    expect(r, "no receipt artifact; filenames were " + [...files.keys()].join(",")).toBeTruthy();
    // The comparison `manifestHonouredBy` makes, made here directly: if these
    // two ever spell the notebook differently the check reports a mismatch on
    // two documents about the same run.
    expect(r.recipeSource).toBe(m.recipeSource);
    expect(r.recipeDigest).toBe(m.recipeDigest);
  });
});

describe("a cell the document cannot print is still a cell", () => {
  it("records an unprintable cell as empty rather than dropping it", async () => {
    // Driven through `ctx.chains`, which is how the shell hands the notebook
    // over — the parser cannot produce a chain this broken, so this is the only
    // way to reach the tolerance at all.
    //
    // `[null]` rather than a nameless step, and the difference is the whole
    // test: a nameless step serializes to `""` quite happily and never enters
    // the `catch`, so the first version of this passed while proving nothing —
    // dropping the cell instead of blanking it survived as a mutation.
    const src = BODY + 'run.manifest "T" | out $manifest';
    const { ast } = compileRecipe(src);
    const chains = [...(ast.chains || [])];
    chains.splice(1, 0, { steps: [null] });
    const files = await filesOf(src, chains);
    const m = parseManifest(files.get("manifest.txt"));
    expect(
      m.cells,
      "the unprintable cell was dropped, so the manifest commits to a shorter notebook than the one that ran"
    ).toHaveLength(chains.length);
    expect(m.recipeSource).toBe(m.cells.map((c) => c.recipe).join(GAP));
  });
});
