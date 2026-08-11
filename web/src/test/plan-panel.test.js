/**
 * The plan panel's contract, asserted against its source.
 *
 * The suite is `environment: "node"`, so nothing here can mount a component —
 * and these are not rendering assertions anyway. They pin the three rules that
 * make the panel a *display* of `planRun` rather than a second opinion about
 * placement, each of which is a property of the code rather than of one render:
 * the plan's sentences go out verbatim, the plan's indices go out unchanged,
 * and the slot sigil comes from the parser.
 *
 * Source assertions because each defect they catch was invisible in a passing
 * render. The panel drew a perfectly reasonable "cell 2" directly beneath a
 * refusal reading "Cell 1 says `@okafor`" — two numbering schemes on one
 * screen, both plausible, neither flagged by anything that renders.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SRC = readFileSync(
  fileURLToPath(new URL("../toolkit/widgets/PlanPanel.tsx", import.meta.url)),
  "utf8"
);

/** Comments explain the rules; only code can break them. */
const CODE = SRC.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

describe("PlanPanel renders the plan rather than restating it", () => {
  it("prints the plan's cell indices with no arithmetic", () => {
    // `index + 1` reads as a kindness to the reader and is the whole bug: the
    // planner writes "cell 0" and "cell 1" into its own refusals and `why`
    // sentences, which this panel renders verbatim, so a display that shifts
    // the numbers puts two schemes for one cell on one screen.
    const shifted = [...CODE.matchAll(/(index|\.cell|\.on)\s*\+\s*1/g)].map((m) => m[0]);
    expect(shifted).toEqual([]);
  });

  it("renders the plan's own sentences, not its own wording", () => {
    // Each of these is a sentence `plan.js` composed, naming its own remedy.
    // Paraphrasing here would make the panel a second opinion about placement,
    // and two opinions eventually disagree.
    expect(CODE).toContain("{cell.why}");
    expect(CODE).toContain("{r.message}");
    expect(CODE).toContain("{a.question}");
  });

  it("takes both sigils from the parser rather than spelling them", () => {
    // The @ -> $ migration is exactly the change a hardcoded sigil survives
    // without noticing, leaving a widget writing a language the parser no
    // longer reads.
    expect(CODE).toContain("SLOT_SIGIL");
    expect(CODE).toContain("PEER_SIGIL");
    const literal = [...CODE.matchAll(/["'`]\$\{?[A-Za-z]/g)].filter(
      (m) => !m[0].includes("${")
    );
    expect(literal).toEqual([]);
  });

  it("prints labels with their sigils, because the plan's own sentences do", () => {
    // `why` reads "runs on `@mara` because it reads $a", rendered verbatim
    // right beside these labels — a bare `mara` on the same line is two
    // spellings of one name.
    expect(CODE).toContain("cell.runsOn.map(peer)");
    expect(CODE).toContain("cell.produces.map(slot)");
    expect(CODE).toContain("plan.unknownPeers.map(peer)");
  });
});
