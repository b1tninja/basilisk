/**
 * A cell's `@peer` header survives being edited.
 *
 * The header is the only way to assign a cell to somebody, and every layer
 * around it already worked: the grammar reads it (`chain.peer`),
 * `serializeChain` writes it back, `planRun` places cells by it and
 * `placementGate` enforces it. `applyCellRecipeText` rebuilt the chain from
 * `steps` alone, so the header parsed cleanly and was thrown away between the
 * parse and the state — making a `@peer` header impossible to write anywhere
 * in the product, with no error to explain it.
 *
 * Two halves, tested where each can be tested. The library round trip is real
 * behaviour and runs. The hook's assignment cannot be mounted here — the suite
 * is `environment: "node"` — so it is pinned as a source assertion, which is
 * also the right shape for it: the defect was a *missing* field, and no
 * rendering of the correct output would have caught it.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";

describe("a chain carries its peer header through parse and serialize", () => {
  it("keeps @peer and publish across a round trip", () => {
    const src = "@mara publish\nbytes deadbeef | encode hex | out $a";
    const { ast } = compileRecipe(src);
    const chain = ast.chains[0];
    expect(chain.peer).toBe("mara");
    expect(chain.publish).toBe(true);
    expect(serializeRecipe(ast)).toBe(src);
  });

  it("keeps a bare @peer with no publish modifier", () => {
    const src = "@okafor\nbytes deadbeef | encode hex | out $d";
    const { ast } = compileRecipe(src);
    expect(ast.chains[0].peer).toBe("okafor");
    expect(ast.chains[0].publish).toBeFalsy();
    expect(serializeRecipe(ast)).toBe(src);
  });

  it("leaves an unheaded chain unheaded", () => {
    const { ast } = compileRecipe("bytes deadbeef | encode hex | out $a");
    expect(ast.chains[0].peer == null).toBe(true);
  });
});

describe("the cell editor carries the header into state", () => {
  it("assigns peer and publish alongside steps, not steps alone", () => {
    // `next[cellIndex] = { steps: [...] }` is the bug: it drops two fields the
    // parser had just populated. Asserting the fields are carried, rather than
    // asserting the absence of that literal, keeps the test true if the
    // assignment is rewritten in some other shape.
    const src = readFileSync(
      fileURLToPath(new URL("../toolkit/useNotebook.ts", import.meta.url)),
      "utf8"
    );
    const start = src.indexOf("const applyCellRecipeText");
    expect(start).toBeGreaterThan(-1);
    // To the callback's own close, not a guessed character count — a fixed
    // window silently shrinks the assertion the moment someone adds a comment.
    const end = src.indexOf("}, []);", start);
    expect(end).toBeGreaterThan(start);
    const body = src.slice(start, end);
    expect(body).toContain("chain.peer");
    expect(body).toContain("chain.publish");
  });
});
