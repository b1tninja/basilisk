/**
 * The delivery report has one reader, and it is the sentence.
 *
 * `useNotebook` returned two shapes of the same fact: `notebookDelivery`, the
 * structure `{ wrote, reached, unconfirmed }`, and `notebookDeliveryNote`, the
 * sentence `describeNotebookDelivery` builds from it. **Only the sentence was
 * ever read** — measured over the whole of `src/`, not sampled: the structure
 * appeared in its own memo, in the memo that turns it into the sentence, and in
 * the returned object, and nowhere else in the tree.
 *
 * It is now unexported, and the argument is not merely "nothing read it". The
 * panel's slot is one string, shared with `notebookShareNote` — the answer to a
 * press — so the two cannot both occupy it; and the rule argued at that call
 * site is that arrival is reported in exactly one sentence, amended in place and
 * never joined by a second line, because an acknowledgment moves nothing on this
 * machine and a second line would report that it had. A structured surface
 * would *be* that second line. So the structure keeps its job as the input to
 * one sentence and stops being offered as a feature nobody wired.
 *
 * Two of the three claims here are source scans, which is deliberate and worth
 * naming: "who consumes this" is a question about the whole tree, and a rendered
 * component cannot answer it — a consumer that does not exist renders exactly
 * like one that was never asked for. The sweep counts every match rather than
 * taking the first few, because a truncated grep is what put a false version of
 * this finding in the findings file. The third claim is the sentence itself,
 * rendered.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describeNotebookDelivery } from "../lib/toolkit/notebook-share.js";
import { NotebookShare } from "../toolkit/widgets/NotebookShare.tsx";

const SRC = fileURLToPath(new URL("../", import.meta.url));
const HOOK = readFileSync(SRC + "toolkit/useNotebook.ts", "utf8");

/** Every source file under `src/`, except the hook itself and this suite. */
function sources(dir = "", out = new Map()) {
  for (const entry of readdirSync(SRC + dir, { withFileTypes: true })) {
    const rel = `${dir}${entry.name}`;
    if (entry.isDirectory()) {
      if (rel === "test") continue;
      sources(`${rel}/`, out);
    } else if (/\.(ts|tsx|js|jsx)$/.test(entry.name) && rel !== "toolkit/useNotebook.ts") {
      out.set(rel, readFileSync(SRC + rel, "utf8"));
    }
  }
  return out;
}

const FPR_A = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_B = "91C7E6D5C4B3A29180716253443526170819AABB";

describe("the structured delivery report", () => {
  it("is read nowhere outside the hook that builds it", () => {
    // `\b` after the name is what keeps `notebookDeliveryNote` out of this: the
    // note is the reader, and finding it here would be the sweep matching a
    // prefix rather than an identifier.
    const hits = [];
    for (const [rel, text] of sources()) {
      const lines = text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (/\bnotebookDelivery\b/.test(lines[i])) hits.push(`${rel}:${i + 1}`);
      }
    }
    expect(hits, `${hits.length} reader(s) of the structure:\n  ${hits.join("\n  ")}`)
      .toEqual([]);
  });

  it("is not on the hook's returned object, and the sentence still is", () => {
    expect(HOOK).toMatch(/const notebookDelivery = useMemo/);
    expect(HOOK).toMatch(/const notebookDeliveryNote = useMemo/);
    // The whole returned object, not one line of it. Asserting the absence of a
    // `^    notebookDelivery,$` line would be satisfied by any re-export spelled
    // differently — `peerCellRows, notebookDelivery,` on one line passes that
    // and ships the export back. This reads the object literal the hook hands
    // its caller and asks whether the identifier is anywhere in it.
    // The *last* `return {` at the hook's own indentation is `useNotebook`'s —
    // the pure helpers above it return at the same depth, and a greedy match
    // from the first one swallows the file.
    const at = HOOK.lastIndexOf("\n  return {");
    expect(at, "the hook's returned object is not where this test thinks it is")
      .toBeGreaterThan(0);
    const returned = HOOK.slice(at);
    expect(returned).toMatch(/^\s{4}notebookDeliveryNote,$/m);
    expect(returned).not.toMatch(/\bnotebookDelivery\b/);
    // The slice really is the object and not a tail of something else.
    expect(returned).toMatch(/^\s{4}chains,$/m);
    expect(returned.trimEnd().endsWith("};\n}") || returned.trimEnd().endsWith("};\r\n}")).toBe(
      true
    );
    // And the memo still feeds the sentence — unexported is not unused, and a
    // mutation that deleted the memo outright would otherwise pass the line
    // above by making the export unnecessary rather than unneeded.
    expect(HOOK).toMatch(/describeNotebookDelivery\(\{ \.\.\.notebookDelivery, clock:/);
  });
});

describe("the sentence that is the surface", () => {
  const note = () =>
    describeNotebookDelivery({
      wrote: 2,
      reached: [{ fpr: FPR_A, at: 1_700_000_000_000 }],
      unconfirmed: [FPR_B],
      clock: () => "just now",
    });

  it("carries every part of the structure a reader needs", () => {
    const said = note();
    expect(said).toMatch(/written to 2 open channels/);
    expect(said).toMatch(/reached .+'s session just now/);
    expect(said).toMatch(/unconfirmed/);
  });

  it("names peers by whole fingerprint", () => {
    const said = note();
    expect(said).toContain(FPR_A);
    expect(said).toContain(FPR_B);
    expect(said).not.toMatch(/…/);
  });

  it("reaches the panel that draws it", () => {
    const out = renderToStaticMarkup(
      React.createElement(NotebookShare, {
        live: true,
        hasNotebook: true,
        proposed: null,
        note: note(),
        onShare: () => {},
        onAdopt: () => {},
        onDismiss: () => {},
      })
    );
    expect(out).toContain(FPR_A);
    expect(out).toContain(FPR_B);
    expect(out).toMatch(/written to 2 open channels/);
  });
});
