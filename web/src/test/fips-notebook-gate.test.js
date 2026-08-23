/**
 * FIPS mode on the run path the notebook actually uses.
 *
 * The defect this file closes (OPEN-FINDINGS §1.1): `assertRecipeAllowedUnderFips`
 * was real, correct and unreachable. It fires for a caller that sets
 * `bindings.fipsMode`, and the only one was `executeToolkitRun` — the
 * crypto-worker's `toolkit-run` arm, which nothing in the app ever posted. The
 * notebook runs through `createKernel`, which never set the flag, so the switch
 * flagged and never refused.
 *
 * That caller no longer exists: the arm and `toolkit-run.js` have both been
 * deleted, so the notebook is not merely the gated path, it is the only path
 * the app has into the engine at all.
 *
 * So these tests deliberately go through `createKernel().runCell` rather than
 * calling `runRecipe` directly: the thing that was broken was *which callers
 * arrive at the gate*, and a test that calls the gate itself would have passed
 * the whole time the switch did nothing.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createKernel } from "../lib/toolkit/kernel.js";
import {
  fipsRefusalFor,
  fipsRefusalForCells,
  fipsRefusalText,
  runRecipe,
} from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

/** `digest` is a webcrypto-toolbox step, so this recipe reaches the webcrypto suite. */
const WEBCRYPTO_RECIPE = "random 16 | digest | encode hex";

const ALL_VERIFIED = { openpgp: "verified", webcrypto: "verified", sss: "verified" };
const WEBCRYPTO_UNVERIFIED = {
  openpgp: "verified",
  webcrypto: "unverified",
  sss: "verified",
};

/** @param {string} src */
function chainOf(src) {
  const { ast, validation } = compileRecipe(src);
  expect(validation.ok).toBe(true);
  return ast.chains[0];
}

/** @param {string} src */
function astOf(src) {
  const { ast, validation } = compileRecipe(src);
  expect(validation.ok).toBe(true);
  return ast;
}

describe("FIPS gate reaches the createKernel run path", () => {
  it("refuses a cell whose suite is unverified, with FIPS on", async () => {
    const kernel = createKernel();
    await expect(
      kernel.runCell(0, chainOf(WEBCRYPTO_RECIPE), {
        fipsMode: true,
        suiteStatus: WEBCRYPTO_UNVERIFIED,
      })
    ).rejects.toThrow(/FIPS mode/i);
  });

  it("refuses before executing: no outputs, no timing entry, no run-log row", async () => {
    const kernel = createKernel();
    await kernel
      .runCell(0, chainOf(WEBCRYPTO_RECIPE), {
        fipsMode: true,
        suiteStatus: WEBCRYPTO_UNVERIFIED,
      })
      .catch(() => {});
    // "Refused before it executes, not flagged after" is the whole requirement,
    // and these three are what "did not execute" looks like from outside.
    expect(kernel.getCellOutputs(0)).toEqual([]);
    expect(kernel.getCellStatus(0)).toBe("error");
    expect(kernel.getRunLog()).toEqual([]);
    expect(kernel.slotCount()).toBe(0);
  });

  it("names the unverified suite, not just 'not allowed'", async () => {
    const kernel = createKernel();
    const err = await kernel
      .runCell(0, chainOf(WEBCRYPTO_RECIPE), {
        fipsMode: true,
        suiteStatus: WEBCRYPTO_UNVERIFIED,
      })
      .then(() => null, (e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toMatch(/webcrypto/);
    // The step that reaches it, so the reader knows where to look.
    expect(err.message).toMatch(/digest/);
  });

  it("tells the reader their next move", async () => {
    const kernel = createKernel();
    const err = await kernel
      .runCell(0, chainOf(WEBCRYPTO_RECIPE), {
        fipsMode: true,
        suiteStatus: WEBCRYPTO_UNVERIFIED,
      })
      .then(() => null, (e) => e);
    // Both remedies, because a refusal that only says "no" is a defect here.
    expect(err.message).toMatch(/turn FIPS mode off/i);
    expect(err.message).toMatch(/verified suite/i);
  });

  it("runs the same cell when every suite it uses is verified", async () => {
    const kernel = createKernel();
    const artifacts = await kernel.runCell(0, chainOf(WEBCRYPTO_RECIPE), {
      fipsMode: true,
      suiteStatus: ALL_VERIFIED,
    });
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0].content).toMatch(/^[0-9a-f]{64}$/);
    expect(kernel.getCellStatus(0)).toBe("ok");
  });

  it("assumes nothing verified when FIPS is on and no status is supplied", async () => {
    const kernel = createKernel();
    await expect(
      kernel.runCell(0, chainOf(WEBCRYPTO_RECIPE), { fipsMode: true })
    ).rejects.toThrow(/FIPS mode/i);
  });
});

describe("the switch off changes nothing", () => {
  it("runs an unverified-suite recipe exactly as before, with FIPS off", async () => {
    const kernel = createKernel();
    const artifacts = await kernel.runCell(0, chainOf(WEBCRYPTO_RECIPE), {
      fipsMode: false,
      suiteStatus: WEBCRYPTO_UNVERIFIED,
    });
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0].content).toMatch(/^[0-9a-f]{64}$/);
    expect(kernel.getCellStatus(0)).toBe("ok");
    expect(kernel.getRunLog()).toHaveLength(1);
  });

  it("runs when the flag is simply absent — every pre-existing caller", async () => {
    const kernel = createKernel();
    const artifacts = await kernel.runCell(0, chainOf(WEBCRYPTO_RECIPE), {});
    expect(artifacts).toHaveLength(1);
    expect(kernel.getCellStatus(0)).toBe("ok");
  });

  it("runRecipe with no bindings at all still runs an unverified suite", async () => {
    const artifacts = await runRecipe(astOf(WEBCRYPTO_RECIPE));
    expect(artifacts).toHaveLength(1);
  });
});

describe("fipsRefusalFor / fipsRefusalText", () => {
  it("returns the empty string when the recipe may run", async () => {
    expect(await fipsRefusalFor(astOf(WEBCRYPTO_RECIPE), ALL_VERIFIED)).toBe("");
  });

  it("returns a refusal naming suite and steps when it may not", async () => {
    const text = await fipsRefusalFor(astOf(WEBCRYPTO_RECIPE), WEBCRYPTO_UNVERIFIED);
    expect(text).toMatch(/webcrypto/);
    expect(text).toMatch(/digest/);
    expect(text).toMatch(/turn FIPS mode off/i);
  });

  it("does not refuse a recipe that reaches no CAST suite", async () => {
    // `toolboxToSuite` returns null for non-crypto toolboxes, so there is
    // nothing for FIPS to have an opinion about.
    expect(await fipsRefusalFor(astOf("random 16 | encode hex"), WEBCRYPTO_UNVERIFIED)).toBe(
      ""
    );
  });

  it("says 'suite' for one and 'suites' for several", () => {
    expect(fipsRefusalText(["webcrypto"], ["digest"])).toMatch(/webcrypto suite/);
    expect(fipsRefusalText(["webcrypto", "sss"], ["digest"])).toMatch(
      /webcrypto, sss suites/
    );
  });

  it("carries the suite name and both remedies in every refusal it builds", () => {
    const text = fipsRefusalText(["openpgp"], ["pgp.encrypt"]);
    expect(text).toMatch(/openpgp/);
    expect(text).toMatch(/pgp\.encrypt/);
    expect(text).toMatch(/turn FIPS mode off/i);
    expect(text).toMatch(/replace .* with steps from a verified suite/i);
  });
});

/**
 * The whole-run pre-check — the thing that makes this a refusal rather than a
 * report on a run already half done.
 *
 * `useNotebook.startRun` calls exactly this, with the switch's reader and the
 * self-test's reader, over the cells the run is scoped to.
 */
describe("fipsRefusalForCells (the notebook's pre-run question)", () => {
  const ON = () => true;
  const OFF = () => false;
  const UNVERIFIED = () => WEBCRYPTO_UNVERIFIED;
  const VERIFIED = () => ALL_VERIFIED;

  it("refuses a multi-cell run because a LATER cell reaches an unverified suite", async () => {
    const cells = [chainOf("random 16 | encode hex"), chainOf(WEBCRYPTO_RECIPE)];
    const text = await fipsRefusalForCells(cells, ON, UNVERIFIED);
    // The point of asking before the loop: cell 0 is innocent and would have
    // run already if the only gate were the per-cell one.
    expect(text).toMatch(/webcrypto/);
    expect(text).toMatch(/digest/);
  });

  it("returns '' with the switch off, whatever the suites say", async () => {
    const cells = [chainOf(WEBCRYPTO_RECIPE)];
    expect(await fipsRefusalForCells(cells, OFF, UNVERIFIED)).toBe("");
  });

  it("returns '' when every suite the scope reaches is verified", async () => {
    const cells = [chainOf(WEBCRYPTO_RECIPE)];
    expect(await fipsRefusalForCells(cells, ON, VERIFIED)).toBe("");
  });

  it("judges only the scope it is given, not the whole notebook", async () => {
    // A one-cell run of an innocent cell is not refused because some other
    // cell in the notebook is unverified — that cell is simply not in scope.
    const innocent = [chainOf("random 16 | encode hex")];
    expect(await fipsRefusalForCells(innocent, ON, UNVERIFIED)).toBe("");
  });

  it("returns '' for an empty scope rather than throwing", async () => {
    expect(await fipsRefusalForCells([], ON, UNVERIFIED)).toBe("");
    expect(await fipsRefusalForCells([undefined], ON, UNVERIFIED)).toBe("");
  });

  it("does not consult the suite status at all when the switch is off", async () => {
    let reads = 0;
    const counted = () => {
      reads += 1;
      return WEBCRYPTO_UNVERIFIED;
    };
    await fipsRefusalForCells([chainOf(WEBCRYPTO_RECIPE)], OFF, counted);
    expect(reads).toBe(0);
  });
});

/**
 * The wiring itself, asserted on the source.
 *
 * `useNotebook.ts` is a React hook and the unit config runs in `node` with no
 * renderer, so its behaviour cannot be driven here — but the defect was never
 * behavioural inside the hook, it was that the hook never told the engine FIPS
 * was on. That is a fact about the text of the file, and asserting it is what
 * makes "somebody quietly removes the two lines again" a failing test rather
 * than a silent regression to exactly the state §1.1 recorded.
 */
describe("useNotebook supplies the flag the gate waits for", () => {
  const source = readFileSync(
    fileURLToPath(new URL("../toolkit/useNotebook.ts", import.meta.url)),
    "utf8"
  );

  it("sets fipsMode and suiteStatus in buildBindings", () => {
    expect(source).toMatch(/bindings\.fipsMode\s*=\s*getFipsMode\(\)/);
    expect(source).toMatch(/bindings\.suiteStatus\s*=\s*getSuiteStatus\(\)/);
  });

  it("asks the gate about the whole run before the cell loop starts", () => {
    // Anchored inside `startRun`: the scope is computed, then FIPS is asked,
    // then the run begins. Anything that moved the question after `setBusy` or
    // after the loop would be flagging a run instead of refusing one.
    const scope = source.indexOf("const runnable = cellsInScope(");
    expect(scope).toBeGreaterThan(-1);
    const at = source.indexOf("fipsRefusalForCells(", scope);
    const busy = source.indexOf("setBusy(true)", scope);
    const loop = source.indexOf("await kernelRef.current.runCell(i, chains[i]", scope);
    expect(at).toBeGreaterThan(-1);
    expect(busy).toBeGreaterThan(-1);
    expect(loop).toBeGreaterThan(-1);
    expect(at).toBeLessThan(busy);
    expect(at).toBeLessThan(loop);
  });

  it("passes the run's own scope and the live readers, not a snapshot", () => {
    const at = source.indexOf("fipsRefusalForCells(");
    const call = source.slice(at, at + 200);
    expect(call).toMatch(/runnable\.map\(\(i\) => chains\[i\]\)/);
    // The functions, uncalled — a snapshot taken earlier could be stale by the
    // time the run starts.
    expect(call).toMatch(/getFipsMode,/);
    expect(call).toMatch(/getSuiteStatus/);
  });

  it("acts on the refusal: announces it and returns without running", () => {
    const at = source.indexOf("fipsRefusalForCells(");
    const window = source.slice(at, at + 400);
    // A refusal that is computed and then ignored is the same defect in a new
    // place, so the branch and the early return are both asserted.
    expect(window).toMatch(/if \(fipsRefusal\) \{/);
    expect(window).toMatch(/refuse\(fipsRefusal\)/);
    expect(window).toMatch(/return;/);
  });
});
