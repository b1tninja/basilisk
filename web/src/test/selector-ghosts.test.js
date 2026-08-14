/**
 * Selector grammar behaviors (design turn 47), the pure layer.
 *
 * Two properties under test: ghost chips come from the closed projector table
 * fit-checked against the tip (never a registry field to author), and nested
 * carets never see tee/foreach — the parser rejects nesting, so the ops are
 * absent from suggestions and fit, not dimmed.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  PROJECTOR_SELECTORS,
  selectorGhostsFor,
  suggestedNextSteps,
  tipFitFor,
} from "../lib/toolkit/suggest.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { typeOf, tNone } from "../lib/toolkit/types.js";

describe("selectorGhostsFor", () => {
  it("offers keypair halves on a keypair tip", () => {
    expect(selectorGhostsFor(typeOf("keypair", { alg: "ec/p256" }))).toEqual([
      ":public",
      ":private",
    ]);
  });

  it("offers :key/:value on an item tip", () => {
    expect(selectorGhostsFor(typeOf("item", { kind: "mnemonic" }))).toEqual([
      ":key",
      ":value",
    ]);
  });

  it("offers nothing on tips no projector fits", () => {
    expect(selectorGhostsFor(typeOf("bytes", {}))).toEqual([]);
    expect(selectorGhostsFor(typeOf("text", {}))).toEqual([]);
    expect(selectorGhostsFor(tNone())).toEqual([]);
    expect(selectorGhostsFor(null)).toEqual([]);
  });

  it("draws only from the closed table — no iteration views, no index forms", () => {
    // :items/:keys/:values are foreach's own modifier; [n]/[n:m] are `at`
    // stem stages. Neither may ever appear as a branch ghost.
    for (const sel of PROJECTOR_SELECTORS) {
      expect(sel).toMatch(/^:(public|private|key|value)$/);
    }
    // shares would accept :items as a tee member in the type system, but the
    // ghost list must still not offer it (RECIPE.md's projector table rules).
    expect(selectorGhostsFor(typeOf("shares", { kind: "mnemonic" }))).toEqual([]);
  });

  it("every ghost is a selector value, never a dot member", () => {
    // The *values* keep their colon: they are what goes into a `select` step's
    // `selector` param, which is the AST spelling and did not change.
    for (const sel of PROJECTOR_SELECTORS) expect(sel.startsWith(":")).toBe(true);
  });

  it("labels a keypair half the way the notebook will write it", () => {
    // The chip's caption is not the AST value. A keypair half is a step now,
    // so the notebook writes `public`, and a control that offered `+ :public`
    // and produced `public` is the drift between two views of one cell that
    // `CellAssign` exists to avoid — one layer down, and just as invisible.
    //
    // A source assertion because the suite is `environment: "node"`: the
    // chips live in a component this file cannot mount, and the defect would
    // be a caption, which no rendering of the correct output would catch.
    const FLOW = readFileSync(
      fileURLToPath(new URL("../toolkit/widgets/RecipeChipFlow.tsx", import.meta.url)),
      "utf8"
    );
    expect(FLOW).toContain(
      'const token = sel === ":public" || sel === ":private" ? sel.slice(1) : sel;'
    );
    expect(FLOW).toContain("label={`+ ${token}`}");
    // And the insert it arms still carries the selector value, so the two
    // halves of the control cannot disagree about which projection it is.
    expect(FLOW).toContain("onArmBranch?.(i, sel)");
    // What that insert produces, in the library layer: the same step the text
    // produces, so a branch inserted from the menu and one typed into Source
    // are the same cell.
    const HOOK = readFileSync(
      fileURLToPath(new URL("../toolkit/useNotebook.ts", import.meta.url)),
      "utf8"
    );
    expect(HOOK).toContain('const folded = selector === ":public" || selector === ":private";');
    expect(HOOK).toContain('body: [{ name: "select", params: { selector } }, step]');
  });
});

describe("nested carets never offer tee/foreach", () => {
  const sharesTip = typeOf("shares", { kind: "mnemonic" });

  it("a stem caret on shares still offers foreach", () => {
    const names = suggestedNextSteps(sharesTip).map((s) => s.name);
    expect(names).toContain("foreach");
  });

  it("the same tip inside a body offers neither container", () => {
    const names = suggestedNextSteps(sharesTip, { nested: true }).map((s) => s.name);
    expect(names).not.toContain("foreach");
    expect(names).not.toContain("tee");
  });

  it("nested fit excludes them too, so the shelf cannot light them up", () => {
    const { tipFit } = tipFitFor(sharesTip, { nested: true });
    expect(tipFit.has("foreach")).toBe(false);
    expect(tipFit.has("tee")).toBe(false);
    // Sanity: the same tip un-nested does fit foreach.
    expect(tipFitFor(sharesTip).tipFit.has("foreach")).toBe(true);
  });
});

describe("branch-with-step lands as valid recipe text", () => {
  it("a selector branch with one step parses; the armed (empty) form does not", () => {
    const ok = compileRecipe(
      "genkey ec/p256 | tee\n  - :public | export spki\n| out $kp"
    );
    expect(ok.validation.errors.map((e) => e.message)).toEqual([]);
    // What the armed state would serialize to if it were committed too early.
    const early = compileRecipe("genkey ec/p256 | tee\n  - :public |\n| out $kp");
    expect(early.validation.ok).toBe(false);
  });
});
