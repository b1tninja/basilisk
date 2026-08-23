/**
 * Export proof hands over the two documents, byte for byte.
 *
 * `ShareSheet` declared `onExportProof`, destructured it and hung it on a
 * `<Button>`, and no caller ever passed it — so the button rendered enabled
 * whenever a proof existed and clicking it did nothing. That is the same defect
 * `session-flow.test.js` records for its sibling `onStartSession`, which is why
 * that file asserts against it; the assertion just never covered this prop.
 *
 * ## Why the bytes are the whole test
 *
 * A manifest's `recipeDigest` is taken over its own `recipeSource`, and
 * `manifestDigest` over the document itself. Re-serialising on the way out is
 * therefore not a formatting choice: it produces a document whose bytes no
 * longer match the digest inside it, handed to somebody whose only job is to
 * check exactly that. The exported text must contain the original strings
 * untouched, and the assertions below are about substrings for that reason
 * rather than about a shape.
 *
 * ## Why there is no wrapper
 *
 * There is no `basilisk.run-proof` kind and this does not invent one. A wrapper
 * would be a schema nothing in the app parses, and each document already names
 * its own `kind` on its first line. The separators are for a person copying one
 * document out to paste it back in — which is why they are labelled and why
 * nothing between them is touched.
 */
import { describe, expect, it } from "vitest";
import { proofFileText, scanProofOutputs } from "../toolkit/ToolkitShell";

const NL = String.fromCharCode(10);

/** A document with awkward-but-legal formatting, to catch a reformat. */
const MANIFEST = `{"kind":"basilisk.run-manifest",` + NL + `  "v": 2,  "recipeDigest": "aa11" }`;
const RECEIPT = `{"kind":"basilisk.run-receipt","v":1,"recipeDigest":"aa11"}`;

/** The shape `nb.cellOutputs` has: cells, each holding output tiles. */
const outputs = (...texts) => texts.map((t) => [{ content: t }]);

describe("the proof file carries the documents unchanged", () => {
  it("finds the documents it is measuring", () => {
    // An empty sweep passes every assertion below it.
    const seen = scanProofOutputs(outputs(MANIFEST, RECEIPT));
    expect(seen.manifestDoc, "the manifest was not recognised").toBeTruthy();
    expect(seen.receiptDoc, "the receipt was not recognised").toBeTruthy();
  });

  it("keeps each document's exact bytes", () => {
    const text = proofFileText(MANIFEST, RECEIPT);
    expect(text).toContain(MANIFEST);
    expect(text).toContain(RECEIPT);
  });

  it("does not reformat a document that is awkwardly spaced", () => {
    // The failure this guards is silent: `JSON.stringify(JSON.parse(x))` gives
    // a document that still parses, still says the right `kind`, and no longer
    // hashes to the digest it carries.
    const text = proofFileText(MANIFEST, RECEIPT);
    expect(text, "the manifest was re-serialised on the way out").not.toContain(
      JSON.stringify(JSON.parse(MANIFEST))
    );
  });

  it("names each document so a reader can tell them apart", () => {
    const text = proofFileText(MANIFEST, RECEIPT);
    expect(text).toContain("--- basilisk.run-manifest ---");
    expect(text).toContain("--- basilisk.run-receipt ---");
    // The manifest first, because it is the promise and the receipt answers it.
    expect(text.indexOf("run-manifest")).toBeLessThan(text.indexOf("run-receipt"));
  });

  it("writes only the half that exists", () => {
    // A notebook being built up has a manifest and no receipt. The file is
    // still worth having, and must not carry an empty labelled section
    // implying a document that was never produced.
    const text = proofFileText(MANIFEST, "");
    expect(text).toContain(MANIFEST);
    expect(text).not.toContain("run-receipt ---");
  });

  it("carries no recipe, no keys, and nothing else", () => {
    // `saveNotebookFile`'s claim is "the recipe text and nothing else"; this is
    // the mirror of it, and the two are kept separate so both stay simple.
    const text = proofFileText(MANIFEST, RECEIPT);
    const stripped = text
      .replace(MANIFEST, "")
      .replace(RECEIPT, "")
      .replace(/--- basilisk\.run-(manifest|receipt) ---/g, "")
      .trim();
    expect(stripped, `the file carries something besides the two documents: ${stripped}`).toBe("");
  });
});

describe("the scan reads the outputs once for both callers", () => {
  it("returns the parsed document and its text together", () => {
    const seen = scanProofOutputs(outputs(MANIFEST, RECEIPT));
    expect(seen.manifestText).toBe(MANIFEST);
    expect(seen.receiptText).toBe(RECEIPT);
    expect(seen.manifestDoc.recipeDigest).toBe("aa11");
  });

  it("ignores an output that merely starts with a brace", () => {
    const seen = scanProofOutputs(outputs("{not json at all", MANIFEST));
    expect(seen.manifestText).toBe(MANIFEST);
    expect(seen.receiptText).toBe("");
  });

  it("takes the last of a kind, which is the one the run just wrote", () => {
    const older = `{"kind":"basilisk.run-manifest","recipeDigest":"old"}`;
    const seen = scanProofOutputs(outputs(older, MANIFEST));
    expect(seen.manifestText).toBe(MANIFEST);
  });

  it("finds nothing in an empty notebook", () => {
    const seen = scanProofOutputs(undefined);
    expect(seen.manifestDoc).toBeNull();
    expect(seen.manifestText).toBe("");
  });
});
