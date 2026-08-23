/**
 * The share sheet says whether a run honoured its manifest.
 *
 * `manifestHonouredBy` compares a run manifest against the receipt of the run
 * that was supposed to honour it — the recipe digest, the op registry, the
 * receipt envelope, every pinned runtime input and every cell row in order.
 * It appeared **zero times in the built bundle**. Its only callers were its own
 * tests. The app carried a check for "did this run do what its manifest
 * promised" and never asked it.
 *
 * What it had instead: `ToolkitShell`'s `runProof` memo parsed both documents
 * out of the cell outputs, kept `recipeDigest.slice(0, 12).toUpperCase()` from
 * each, and threw the documents away. `ShareSheet` printed
 * `manifest 4F2AC1B39D8E · receipt 4F2AC1B39D8E` beside an Export button, so a
 * reader was shown two truncated hex strings and left to diff them by eye —
 * an answer the code already had every part of.
 *
 * Two halves, tested where each lives:
 *
 * - `readRunProof` turns cell outputs into a verdict. It is exercised against
 *   documents built by `buildRunManifest` and `buildRunReceipt` rather than
 *   hand-written shapes, so a change to either document's fields shows up here
 *   as a failure rather than as a test that agrees with a stale fixture.
 * - `ProofVerdict` turns that verdict into words. It is *rendered*, with
 *   `react-dom/server`, and the assertions read the markup.
 *
 * `ShareSheet` as a whole cannot be rendered here: it is a Radix dialog, the
 * dialog renders through a portal, and `renderToStaticMarkup` returns "" for
 * the entire component under this repo's `node` environment — verified, not
 * assumed. The one claim that therefore rests on source text is that the sheet
 * hands `proof` to `ProofVerdict` at all, and it is called out as such below.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ProofVerdict } from "../toolkit/widgets/ShareSheet.tsx";
import { readRunProof } from "../toolkit/ToolkitShell.tsx";
import { buildRunManifest } from "../lib/toolkit/manifest.js";
import { buildRunReceipt } from "../lib/toolkit/receipt.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SHARE_SRC = read("../toolkit/widgets/ShareSheet.tsx");
const SHELL_SRC = read("../toolkit/ToolkitShell.tsx");

const FPR_A = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_B = "91C7E6D5C4B3A29180716253443526170819AABB";
const SOURCE = "bytes deadbeef | encode hex | out $a\n\nin $a | out $b";
const CELLS = [
  { index: 0, recipe: "bytes deadbeef | encode hex | out $a" },
  { index: 1, recipe: "in $a | out $b" },
];

/** A manifest and a receipt of the same run, as the engine would build them. */
async function agreeingDocs(overrides = {}) {
  const manifest = await buildRunManifest({
    title: "Thursday key ceremony",
    recipeSource: SOURCE,
    cells: CELLS,
    peers: { mara: FPR_A, okafor: FPR_B },
    entropy: { mode: "none" },
    clock: { mode: "pinned", t0: "2026-08-01T00:00:00.000Z" },
    inputs: [{ cell: 0, channel: "text", digest: "a".repeat(64) }],
    ...overrides,
  });
  const receipt = await buildRunReceipt({
    label: "Thursday key ceremony",
    createdAt: "2026-08-02T00:00:00.000Z",
    recipeSource: SOURCE,
    cells: CELLS.map((c) => ({
      ...c,
      startedAt: "2026-08-02T00:00:00.000Z",
      inputs: c.index === 0 ? [{ channel: "text", digest: "a".repeat(64) }] : [],
      outputs: [{ label: `o${c.index}`, digest: "c".repeat(64), length: 4 }],
    })),
  });
  return { manifest, receipt };
}

/** Documents laid out the way the notebook holds them: one tile per cell. */
const outputsOf = (...docs) =>
  docs.map((doc) => [{ content: typeof doc === "string" ? doc : JSON.stringify(doc) }]);

const render = (proof) =>
  renderToStaticMarkup(React.createElement(ProofVerdict, { proof }));

const strip = (html) => html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();

/** The `data-verdict` the component chose, or null if it drew no verdict. */
function verdictOf(html) {
  const m = html.match(/data-verdict="([^"]*)"/);
  return m ? m[1] : null;
}

describe("reading a proof out of the outputs", () => {
  it("finds nothing when the outputs hold no documents", () => {
    expect(readRunProof(undefined)).toBeNull();
    expect(readRunProof([])).toBeNull();
    expect(readRunProof([[{ content: "deadbeef" }], [{ content: "{not json" }]])).toBeNull();
  });

  it("asks manifestHonouredBy, and says the run honoured its manifest", async () => {
    const { manifest, receipt } = await agreeingDocs();
    const proof = readRunProof(outputsOf(manifest, receipt));

    expect(proof.honoured, "no comparison was made at all").not.toBeNull();
    expect(proof.honoured.ok).toBe(true);
    expect(proof.honoured.mismatches).toEqual([]);
    // `checked` counts every question asked. A comparison that asked none
    // would report ok with nothing behind it.
    expect(proof.honoured.checked).toBeGreaterThan(0);
    expect(proof.honoured.summary).toMatch(/manifest honoured/);
    expect(proof.unreadable).toBe("");
    // The digests stay: they are how a reader names which proof this is.
    expect(proof.manifest).toBe(manifest.recipeDigest.slice(0, 12).toUpperCase());
    expect(proof.receipt).toBe(receipt.recipeDigest.slice(0, 12).toUpperCase());
  });

  it("names the field that disagreed when the run did not honour it", async () => {
    const { manifest, receipt } = await agreeingDocs();
    // A receipt of a different recipe than the one committed to — the single
    // most basic thing this comparison exists to catch.
    receipt.recipeDigest = "f".repeat(64);
    const proof = readRunProof(outputsOf(manifest, receipt));

    expect(proof.honoured.ok).toBe(false);
    expect(proof.honoured.mismatches).toContainEqual({
      path: "manifest",
      field: "recipeDigest",
      expected: manifest.recipeDigest,
      actual: "f".repeat(64),
    });
    expect(proof.honoured.summary).toMatch(/not honoured/);
  });

  it("catches a cell that ran something other than what was promised", async () => {
    const { manifest, receipt } = await agreeingDocs();
    receipt.cells[1].recipe = "in $a | encode base64 | out $b";
    const proof = readRunProof(outputsOf(manifest, receipt));

    expect(proof.honoured.ok).toBe(false);
    expect(
      proof.honoured.mismatches.some((m) => m.path === "cell 1" && m.field === "recipe"),
      `no mismatch named cell 1's recipe: ${JSON.stringify(proof.honoured.mismatches)}`
    ).toBe(true);
  });

  it("catches a runtime input the manifest never pinned", async () => {
    const { manifest, receipt } = await agreeingDocs();
    receipt.cells[1].inputs = [{ channel: "text", digest: "b".repeat(64) }];
    const proof = readRunProof(outputsOf(manifest, receipt));

    expect(proof.honoured.ok).toBe(false);
    expect(proof.honoured.mismatches.some((m) => m.field === "undeclared")).toBe(true);
  });

  it("treats a manifest with no receipt as a not-yet, never as a mismatch", async () => {
    const { manifest } = await agreeingDocs();
    const proof = readRunProof(outputsOf(manifest));

    expect(proof, "half a proof is still a proof in progress").not.toBeNull();
    expect(proof.honoured, "a missing receipt was reported as a comparison").toBeNull();
    expect(proof.unreadable).toBe("");
    expect(proof.manifest).not.toBe("");
    expect(proof.receipt).toBe("");
  });

  it("treats a receipt with no manifest the same way", async () => {
    const { receipt } = await agreeingDocs();
    const proof = readRunProof(outputsOf(receipt));
    expect(proof.honoured).toBeNull();
    expect(proof.receipt).not.toBe("");
    expect(proof.manifest).toBe("");
  });

  it("survives a document that carries the right kind and the wrong shape", async () => {
    const { receipt } = await agreeingDocs();
    // An output is whatever a cell printed. Nothing stops a reader typing this.
    const bogus = { kind: "basilisk.run-manifest", recipeDigest: "aa", cells: "not a list" };
    let proof;
    expect(() => {
      proof = readRunProof(outputsOf(bogus, receipt));
    }, "a malformed document threw during what is a render in the app").not.toThrow();
    expect(proof.honoured, "an uncomparable pair was scored as a comparison").toBeNull();
    expect(proof.unreadable, "the failure to compare was silent").not.toBe("");
  });
});

describe("the verdict, in words", () => {
  it("says honoured, and how much was checked", async () => {
    const { manifest, receipt } = await agreeingDocs();
    const html = render(readRunProof(outputsOf(manifest, receipt)));
    expect(verdictOf(html)).toBe("honoured");
    expect(strip(html)).toMatch(/manifest honoured/);
    expect(strip(html)).toMatch(/\d+ facts matched/);
  });

  it("lists what a re-run will not reproduce, even when the run was honest", async () => {
    // Honoured and non-reproducible are both true at once, and the second is
    // the one that costs the recipient something.
    const { manifest, receipt } = await agreeingDocs({ clock: { mode: "free" } });
    const proof = readRunProof(outputsOf(manifest, receipt));
    expect(proof.honoured.ok, "this fixture stopped being an honoured run").toBe(true);
    expect(proof.honoured.declared.length).toBeGreaterThan(0);

    const text = strip(render(proof));
    expect(verdictOf(render(proof))).toBe("honoured");
    for (const reason of proof.honoured.declared) {
      expect(text, `a declared non-reproducible dependency went unsaid: ${reason}`).toContain(
        reason
      );
    }
  });

  it("says not honoured, and names the field, the promise and the run", async () => {
    const { manifest, receipt } = await agreeingDocs();
    receipt.recipeDigest = "f".repeat(64);
    const proof = readRunProof(outputsOf(manifest, receipt));
    const html = render(proof);
    const text = strip(html);

    expect(verdictOf(html)).toBe("not-honoured");
    expect(text).toMatch(/not honoured/);
    // The whole point: the reader is told *what* disagreed, not just that
    // something did. Without this the sheet is back to two hex strings.
    expect(text, "the failing field was not named").toContain("recipeDigest");
    expect(text, "the manifest's side was not shown").toContain(
      manifest.recipeDigest.slice(0, 12)
    );
    expect(text, "the run's side was not shown").toContain("ffffffffffff");
    // And what to do about it.
    expect(text, "a red verdict with no next move").toMatch(/Run the notebook again/);
  });

  it("shows every disagreement it can, and counts the ones it cannot", async () => {
    const { manifest, receipt } = await agreeingDocs();
    receipt.recipeDigest = "f".repeat(64);
    receipt.registry = "not-the-registry";
    receipt.cells[0].recipe = "bytes cafe | out $a";
    receipt.cells[1].recipe = "in $a | encode base64 | out $b";
    receipt.cells[1].inputs = [{ channel: "text", digest: "b".repeat(64) }];
    const proof = readRunProof(outputsOf(manifest, receipt));
    expect(proof.honoured.mismatches.length).toBeGreaterThan(4);

    const html = render(proof);
    const shown = (html.match(/data-mismatch\b/g) || []).length;
    expect(shown, "the list showed nothing").toBeGreaterThan(0);
    const rest = proof.honoured.mismatches.length - shown;
    expect(strip(html)).toContain(`and ${rest} more`);
  });

  it("shows a changed recipe whole and a changed digest by its head", async () => {
    // Two kinds of value, read for two reasons. A digest is an identifier and
    // twelve characters name it; a recipe is text and the reader is looking
    // for the word that changed, so `in $a | enco…` names the disagreement and
    // then hides it. One truncation rule for both did exactly that.
    const { manifest, receipt } = await agreeingDocs();
    receipt.recipeDigest = "f".repeat(64);
    receipt.cells[1].recipe = "in $a | encode base64 | out $b";
    const text = strip(render(readRunProof(outputsOf(manifest, receipt))));

    expect(text, "the changed recipe was cut before the change").toContain(
      "in $a | encode base64 | out $b"
    );
    expect(text, "a 64-character digest was printed in full").not.toContain("f".repeat(20));
  });

  it("is muted about half a proof, and names the half that is missing", async () => {
    const { manifest } = await agreeingDocs();
    const html = render(readRunProof(outputsOf(manifest)));
    const text = strip(html);

    expect(verdictOf(html)).toBe("incomplete");
    expect(text, "an ordinary not-yet was painted as an error").not.toMatch(
      /--error|not honoured/
    );
    expect(text, "the missing half was not named").toContain("run.receipt");
  });

  it("says it could not compare, rather than accusing the run", async () => {
    const { receipt } = await agreeingDocs();
    const bogus = { kind: "basilisk.run-manifest", recipeDigest: "aa", cells: "not a list" };
    const html = render(readRunProof(outputsOf(bogus, receipt)));
    const text = strip(html);

    expect(verdictOf(html)).toBe("unreadable");
    expect(text).toMatch(/could not be compared/);
    expect(text, "not comparable was reported as not honoured").not.toMatch(/not honoured/);
    expect(text, "no next move").toMatch(/running the notebook again/);
    // The thrown message is a JavaScript type error naming an expression no
    // reader of a share sheet has ever seen. It reached the surface once.
    expect(text, "a raw exception message reached the reader").not.toMatch(
      /is not a function|TypeError|intermediate value/
    );
  });

  it("keeps its colour off the element and on the stylesheet's tokens", () => {
    // House rule: nothing that could be a stylesheet declaration is written as
    // an inline style. Asserted on source because a `style=` attribute is
    // exactly what would *not* show up as a rendering difference here.
    const proofSection = SHARE_SRC.slice(SHARE_SRC.indexOf("function ProofVerdict"));
    expect(proofSection).not.toMatch(/style=\{\{/);
    expect(SHARE_SRC, "an inline style entered this component").not.toMatch(/style=\{\{/);
  });
});

describe("the check is wired to the surface, not merely present", () => {
  // The defect being closed is a finished mechanism with no consumer, so the
  // call site is the thing worth holding down. Source text, and deliberately:
  // `readRunProof` is exercised for real above, but the memo that calls it and
  // the sheet that displays it both sit inside components this repo's `node`
  // environment cannot mount — `ShareSheet` renders to "" because a Radix
  // dialog portals, and `ToolkitShell` needs a browser outright.
  const code = (src) =>
    src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

  it("calls manifestHonouredBy from the shell, not only from a test", () => {
    const shell = code(SHELL_SRC);
    expect(shell, "the import went away").toMatch(
      /import \{[^}]*manifestHonouredBy[^}]*\} from "\.\.\/lib\/toolkit\/manifest\.js"/
    );
    expect(shell, "`manifestHonouredBy` is back to having no caller").toMatch(
      /manifestHonouredBy\(/
    );
    expect(shell, "the memo stopped reading the proof").toMatch(
      /readRunProof\(nb\.cellOutputs\)/
    );
  });

  it("hands the proof to the verdict, not just to a digest line", () => {
    const share = code(SHARE_SRC);
    expect(share, "the tier stopped drawing a verdict").toMatch(
      /verdict=\{proof \? <ProofVerdict proof=\{proof\} \/> : null\}/
    );
    expect(share, "`Tier` stopped rendering the slot").toMatch(/\{verdict\}/);
  });

  it("still shows the two digests beside the verdict", () => {
    // The verdict replaces the *comparison*, not the identifiers. A reader who
    // wants to go and look at the documents needs to know which ones.
    expect(code(SHARE_SRC)).toMatch(/manifest \$\{proof\.manifest\} · receipt \$\{proof\.receipt\}/);
  });

  it("leaves an unhonoured proof exportable", () => {
    // Judged, not inherited: the mismatch is the evidence, and refusing to
    // export destroys the only artifact documenting it. The recipient runs the
    // same comparison on the same documents and gets the same answer.
    const share = code(SHARE_SRC);
    const button = share.slice(share.indexOf("Export proof") - 400, share.indexOf("Export proof"));
    expect(button, "Export proof grew a reason to refuse beyond the absence of a proof").toMatch(
      /disabledReason=\{proof \? undefined : NO_PROOF_YET\}/
    );
    expect(button).not.toMatch(/honoured/);
  });
});
