/**
 * A cell that is not mine does not run here, and the run says so.
 *
 * This is the first thing in the placement stack that changes what a machine
 * *does*. Everything under it — the grammar's `@peer` header, the manifest,
 * the entropy declaration, the plan — reads text and produces descriptions. A
 * notebook that computes a beautiful plan and then runs every cell locally has
 * assigned nothing, so this file is where the plan stops being a description.
 *
 * **Every gate test here has a control that shows the gate failing.** A test
 * that asserts "the foreign cell produced nothing" passes just as happily
 * against a gate that refuses everything, against a gate that runs nothing,
 * and — worst — against an engine where the cell threw for an unrelated
 * reason. So each case runs the same recipe twice against the same corpus of
 * bindings: once with no `placement` (the gate removed, which is exactly what
 * every caller predating it does) and once with one. The first run is required
 * to produce the artifact, the slot, or the plausible wrong answer; the second
 * is required not to. Only the pair says anything.
 *
 * The three properties, in the order they matter:
 *
 * 1. A cell the plan placed on somebody else is not executed here, and is
 *    reported with the peer it waits on and why.
 * 2. The run continues past it — a later independent cell still runs — but a
 *    later cell that *depended* on it stops the run with a sentence naming the
 *    slot, the cell that writes it and the peer that holds it. Never an
 *    absent slot, and never a value quietly taken from somewhere else.
 * 3. A run with no placement is the run this engine has always performed. The
 *    differential at the bottom asserts that over every shipped preset and
 *    every `docs/RECIPE.md` fence, by running each one both ways.
 */
import { describe, expect, it } from "vitest";
import { PRESETS, compileRecipe, migrateRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { planRun } from "../lib/toolkit/plan.js";
import { parseRecipeSource } from "../lib/toolkit/recipe-parse.js";
import { placementGate } from "../lib/toolkit/placement.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { createKernel } from "../lib/toolkit/kernel.js";
import { manifestHonouredBy, parseManifest, summarizeHonour } from "../lib/toolkit/manifest.js";
import { buildRunReceipt } from "../lib/toolkit/receipt.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const FPR_M = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_O = "91C7E6D5C4B3A29180716253443526170819AABB";
const ROSTER = { mara: FPR_M, okafor: FPR_O };

/** Two cells, one each, neither reading anything of the other's. */
const TWO_CELLS = `@mara
bytes deadbeef | encode hex | out $m

@okafor
bytes cafebabe | encode hex | out $o
`;

/** `@mara` writes a value into the room; the next cell, anybody's, reads it. */
const PUBLISHED = `@mara publish
bytes deadbeef | encode hex | out $seed

in $seed | decode hex | encode base64 | out $b64
`;

/** @param {string} src */
const compile = (src) => compileRecipe(migrateRecipe(src).recipe);

/**
 * The two cells of a notebook that has a blank one between them.
 *
 * Built rather than parsed, because recipe *text* has no spelling for an empty
 * cell — `serializeRecipe` drops one and the parser never produces one, so a
 * blank cell exists only in the notebook a person is editing. That is precisely
 * why the numbering had to be settled: the notebook and its own source text do
 * not have the same number of cells.
 */
const BLANK_MIDDLE_TEXT = `@okafor
bytes 00 | encode hex | out $first

@mara
bytes 11 | encode hex | out $mine
`;

/** @type {*} */
const BLANK_MIDDLE = (() => {
  const chains = /** @type {*} */ (compile(BLANK_MIDDLE_TEXT).ast).chains;
  return {
    chains: [chains[0], { steps: [] }, chains[1]],
    steps: chains[0].steps,
    source: "",
  };
})();

/**
 * The manifest `run.manifest` emits for a notebook, through the op rather than
 * beside it — the shell hands the notebook over as `receipt.chains` for the
 * reason `currentRunManifest` gives, and this is that path.
 * @param {*} notebook
 */
async function manifestOf(notebook) {
  const arts = await runRecipe(
    compile("run.manifest | out $m").ast,
    {
      receipt: {
        // What the shell passes: the text, serialised from these same chains —
        // so it holds two cells where the notebook holds three.
        recipeSource: serializeRecipe({ chains: notebook.chains }),
        chains: notebook.chains,
      },
    },
    {}
  );
  return parseManifest(String(arts[0].content));
}

/**
 * @param {string} src @param {string} me
 * @param {(s: import("../lib/toolkit/placement.js").SkippedCell) => void} [onSkip]
 */
function placementFor(src, me, onSkip) {
  const plan = planRun(compile(src), { me, roster: ROSTER });
  expect(plan.ok, plan.refusals.map((r) => r.message).join(" · ")).toBe(true);
  return { plan, ...(onSkip ? { onSkip } : {}) };
}

/** Artifact identity that survives a second run of a recipe that draws randomness. */
const shape = (/** @type {*[]} */ arts) =>
  arts.map((a) => ({
    label: a.label,
    filename: a.filename,
    role: a.role ?? null,
    stepIndex: a.stepIndex ?? null,
    stepName: a.stepName ?? null,
    sensitive: !!a.sensitive,
    disposition: a.disposition ?? null,
  }));

describe("a cell placed on another peer does not run here", () => {
  it("runs both cells with the gate removed — the control this file rests on", async () => {
    const registry = createSlotRegistry();
    const arts = await runRecipe(compile(TWO_CELLS).ast, {}, { slotRegistry: registry });
    expect(registry.has("m")).toBe(true);
    expect(registry.has("o")).toBe(true);
    expect(arts.length).toBe(2);
  });

  it("performs mine and leaves theirs alone", async () => {
    /** @type {import("../lib/toolkit/placement.js").SkippedCell[]} */
    const skipped = [];
    const registry = createSlotRegistry();
    const arts = await runRecipe(
      compile(TWO_CELLS).ast,
      {},
      {
        slotRegistry: registry,
        placement: placementFor(TWO_CELLS, "mara", (s) => skipped.push(s)),
      }
    );
    expect(registry.has("m")).toBe(true);
    // The whole unit, in one line: the value okafor's cell would have produced
    // is not here, and the only difference between this run and the control
    // above is the placement.
    expect(registry.has("o")).toBe(false);
    expect(arts.length).toBe(1);
    expect(skipped).toEqual([
      {
        cell: 1,
        waitingOn: "okafor",
        runsOn: ["okafor"],
        why: expect.stringContaining("the header says so"),
        produces: ["o"],
      },
    ]);
  });

  it("is the same gate from the other side — okafor performs the other one", async () => {
    const registry = createSlotRegistry();
    await runRecipe(
      compile(TWO_CELLS).ast,
      {},
      { slotRegistry: registry, placement: placementFor(TWO_CELLS, "okafor") }
    );
    expect(registry.has("m")).toBe(false);
    expect(registry.has("o")).toBe(true);
  });

  it("accepts this peer's fingerprint as readily as their label", async () => {
    const registry = createSlotRegistry();
    await runRecipe(
      compile(TWO_CELLS).ast,
      {},
      { slotRegistry: registry, placement: placementFor(TWO_CELLS, FPR_O) }
    );
    expect(registry.has("o")).toBe(true);
    expect(registry.has("m")).toBe(false);
  });

  it("keeps going past a foreign cell to a later independent one", async () => {
    const src = `@okafor
bytes 00 | encode hex | out $first

@mara
bytes 11 | encode hex | out $mine

in $mine | out $after
`;
    const registry = createSlotRegistry();
    const arts = await runRecipe(
      compile(src).ast,
      {},
      { slotRegistry: registry, placement: placementFor(src, "mara") }
    );
    expect(registry.has("first")).toBe(false);
    expect(registry.has("mine")).toBe(true);
    // The cell after the foreign one, and the cell after that, both ran: a gate
    // that aborted at the first cell it declined would satisfy every assertion
    // above this one.
    expect(registry.has("after")).toBe(true);
    expect(arts.length).toBeGreaterThan(1);
  });

  it("numbers the steps it did not run — a later artifact keeps its place", async () => {
    const src = `@okafor
bytes 00 | encode hex | out $first

@mara
bytes 11 | encode hex | out $mine
`;
    const plain = await runRecipe(compile(src).ast, {});
    const gated = await runRecipe(
      compile(src).ast,
      {},
      { placement: placementFor(src, "mara") }
    );
    // Cell 1's tile is step 6 of the notebook whether or not cell 0 ran on this
    // machine. A gate that let the ordinal slide would renumber every chip
    // after a foreign cell.
    expect(gated.map((a) => a.stepIndex)).toEqual([plain[1].stepIndex]);
  });

  it("refuses a rendezvous cell rather than running it alone", async () => {
    // This test used to assert the opposite, under the title "`@*` is
    // everybody, and everybody includes me". The premise is true and the
    // conclusion was not: everybody does include me, but running it *because*
    // it includes me performs the one thing the header does not mean. `@*`
    // says the participants enter together, nothing makes them, and a cell
    // that ran anyway would have this peer enter alone while believing the
    // room entered with it — the failure `buildOfferFor` refuses a rendezvous
    // handoff to avoid, reached by pressing Run.
    //
    // So the plan refuses it, and `placementGate` turns a refused plan into a
    // stop. Flipped rather than deleted: the old behaviour is the bug, and the
    // test that pinned it is where that is easiest to see.
    const src = `@mara
bytes 00 | encode hex | out $m

@*
bytes 11 | encode hex | out $both
`;
    const registry = createSlotRegistry();
    // `placementFor` asserts the plan is clean, which this one is not — the
    // point of the test is that it refuses. So the plan is handed to the gate
    // directly, exactly as the shell would hand it over.
    const plan = planRun(compile(src), {
      me: "okafor",
      roster: { mara: "A".repeat(40), okafor: "B".repeat(40) },
    });
    expect(plan.ok).toBe(false);
    await expect(
      runRecipe(compile(src).ast, {}, { slotRegistry: registry, placement: { plan } })
    ).rejects.toThrow(/refused the run/);
    // And nothing ran: not the rendezvous cell, and not the cell above it.
    expect(registry.has("both")).toBe(false);
    expect(registry.has("m")).toBe(false);
  });

  it("refuses it at compile time, which is the gate every run passes", () => {
    // **Where** the refusal lives is the load-bearing part. A plan-level one
    // would have been routed around: `useNotebook` builds a placement only
    // when a plan is `ok` and `placed`, so a refused plan is dropped and the
    // notebook runs *ungated* — the refusal would have been read by the panel
    // and ignored by the runner. A compile error is on every path: the editor
    // shows it, Run is blocked, and a recipe arriving from a peer is refused
    // on the way in.
    const src = `@*
bytes 11 | encode hex | out $both
`;
    const { validation } = compile(src);
    expect(validation.ok).toBe(false);
    const message = validation.errors.map((e) => e.message).join(" ");
    expect(message).toMatch(/can describe one but not perform one/);
    expect(message).toMatch(/enter alone while believing the room entered with you/);
    // The remedy, because a refusal that names no alternative is a dead end.
    expect(message).toMatch(/one cell per participant/);
    expect(message).toMatch(/ordinary mirrored cell/);
  });

  it("still lets the planner say what a rendezvous means", () => {
    // The reading is kept rather than deleted. `planRun` places a rendezvous
    // from any AST it is handed — which is how a plan from another build
    // arrives, and why the handoff guards behind it stay reachable. It will
    // also be what performs one, the day anything can.
    const src = "@*\nbytes 11 | encode hex | out $both\n";
    const plan = planRun(parseRecipeSource(src).ast, {
      me: "okafor",
      roster: { mara: "A".repeat(40), okafor: "B".repeat(40) },
    });
    expect(plan.cells[0].kind).toBe("rendezvous");
    expect(plan.cells[0].basis).toBe("rendezvous");
    expect(plan.waits).toContainEqual({
      cell: 0,
      on: 0,
      peer: "*",
      slot: "",
      reason: "rendezvous",
    });
  });
});

describe("a cell whose input was never produced here does not guess", () => {
  it("produces a perfectly plausible answer with the gate removed", async () => {
    const registry = createSlotRegistry();
    const arts = await runRecipe(compile(PUBLISHED).ast, {}, { slotRegistry: registry });
    // This is the wrong answer the gate exists to prevent: `$seed` was made on
    // this machine by a cell belonging to `@mara`, and `$b64` looks exactly
    // like the value the notebook promised.
    expect(registry.has("b64")).toBe(true);
    expect(arts.some((a) => String(a.content).includes("3q2+7w=="))).toBe(true);
  });

  it("stops the run, naming the slot, the cell and the peer", async () => {
    const registry = createSlotRegistry();
    const err = await runRecipe(
      compile(PUBLISHED).ast,
      {},
      { slotRegistry: registry, placement: placementFor(PUBLISHED, "okafor") }
    ).then(
      () => null,
      (e) => e
    );
    expect(err).toBeInstanceOf(Error);
    const msg = String(err.message);
    expect(msg).toContain("$seed");
    expect(msg).toContain("cell 0");
    expect(msg).toContain("@mara");
    // Not the sentence the slot registry would have produced. That one blames
    // the author for forgetting an `out` when the value exists and is simply
    // somewhere else, and it is the reason this check runs before the cell
    // rather than inside it.
    expect(msg).not.toContain("unknown slot");
    expect(err.basiliskWithheld).toEqual({
      cell: 1,
      slot: "seed",
      from: 0,
      peer: "mara",
    });
    // Nothing plausible was left behind on the way out.
    expect(registry.has("b64")).toBe(false);
    expect(registry.has("seed")).toBe(false);
  });

  it("runs the moment the value is actually here", async () => {
    // The seam the handoff unit delivers through: a registry that already
    // holds `$seed` is a registry where the value arrived, and the gate has
    // nothing to say about a value it can see. No edit to the gate will be
    // needed to make this work — this is that test, written now.
    const registry = createSlotRegistry();
    registry.register("$seed", {
      type: "text",
      data: "deadbeef",
      meta: {},
    });
    const arts = await runRecipe(
      compile(PUBLISHED).ast,
      {},
      { slotRegistry: registry, placement: placementFor(PUBLISHED, "okafor") }
    );
    expect(registry.has("b64")).toBe(true);
    expect(arts.some((a) => String(a.content).includes("3q2+7w=="))).toBe(true);
  });
});

describe("a placement is complete or it is refused", () => {
  it("is not a gate at all when absent", () => {
    expect(placementGate(undefined, { cells: 2, first: 0, count: 2 })).toBe(null);
    expect(placementGate(null, { cells: 2, first: 0, count: 2 })).toBe(null);
  });

  it("refuses a placement with no plan in it", async () => {
    await expect(
      runRecipe(compile(TWO_CELLS).ast, {}, { placement: /** @type {*} */ ({}) })
    ).rejects.toThrow(/plan\.cells/);
  });

  it("refuses a plan that does not know which peer this is", async () => {
    // The trap this unit was warned about, in its most ordinary form: a plan
    // built before the session knew who was holding it. Every placed cell
    // reads as somebody else's, so the notebook would run *nothing* and report
    // success — a defaulting gate's silence, arriving from the other side.
    const plan = planRun(compile(TWO_CELLS), { roster: ROSTER });
    await expect(
      runRecipe(compile(TWO_CELLS).ast, {}, { placement: { plan } })
    ).rejects.toThrow(/does not know which peer you are/);
  });

  it("refuses a plan that refused", async () => {
    const src = `@mara
genkey x25519 | out $kp

@okafor
in $kp | export spki | out $pub
`;
    const plan = planRun(compile(src), { me: "okafor", roster: ROSTER });
    expect(plan.ok).toBe(false);
    await expect(
      runRecipe(compile(src).ast, {}, { placement: { plan } })
    ).rejects.toThrow(/a refused plan/);
  });

  it("refuses a plan for a different notebook", async () => {
    const plan = planRun(compile(TWO_CELLS), { me: "mara", roster: ROSTER });
    const other = compile(`@mara\nbytes 00 | encode hex | out $a\n`);
    await expect(
      runRecipe(other.ast, {}, { placement: { plan } })
    ).rejects.toThrow(/describes 2 cells and this run has 1/);
  });

  it("refuses a plan that stops short of the cells this run walks", async () => {
    const plan = planRun(compile(TWO_CELLS), { me: "mara", roster: ROSTER });
    // A plan truncated after its first cell, offered for a two-cell run. The
    // partial case: without this, cell 1 runs here because nothing said not to.
    const partial = { ...plan, cells: plan.cells.slice(0, 1) };
    await expect(
      runRecipe(compile(TWO_CELLS).ast, {}, {
        placement: { plan: /** @type {*} */ (partial), firstCell: 0 },
      })
    ).rejects.toThrow(/the plan stops at 0/);
  });

  it("refuses a plan whose cells are not the cells they say they are", async () => {
    const plan = planRun(compile(TWO_CELLS), { me: "mara", roster: ROSTER });
    const shuffled = {
      ...plan,
      cells: [plan.cells[0], { ...plan.cells[1], index: 5 }],
    };
    await expect(
      runRecipe(compile(TWO_CELLS).ast, {}, { placement: { plan: /** @type {*} */ (shuffled) } })
    ).rejects.toThrow(/no plan for cell 1/);
  });

  it("places a single-cell run by the index it has in the plan", async () => {
    // What a caller that runs one cell at a time hands over: the AST is that
    // one chain, so the chain's own index is 0 and the only thing that knows
    // it is cell 1 of the notebook is `firstCell`.
    const { ast } = compile(TWO_CELLS);
    const chains = /** @type {*} */ (ast).chains;
    const plan = planRun(compile(TWO_CELLS), { me: "mara", roster: ROSTER });
    const one = { chains: [chains[1]], steps: chains[1].steps, source: "" };
    const registry = createSlotRegistry();
    await runRecipe(one, {}, {
      slotRegistry: registry,
      placement: { plan, firstCell: 1 },
    });
    expect(registry.has("o")).toBe(false);
    // …and the same chain under `firstCell: 0` would be read as mara's own
    // cell 0 and run. The offset is load-bearing, not decoration.
    const asZero = createSlotRegistry();
    await runRecipe(one, {}, {
      slotRegistry: asZero,
      placement: { plan, firstCell: 0 },
    });
    expect(asZero.has("o")).toBe(true);
  });

  it("spends a plan index on a blank cell, because the notebook does", async () => {
    // The cell after the blank one is cell 2 everywhere, or this run is
    // performing somebody else's work. A plan built from the blank-free *text*
    // numbers it 1 — that is the mistake a caller makes by planning the wrong
    // list, and the gate refuses it rather than running mara's cell as okafor's.
    const registry = createSlotRegistry();
    await expect(
      runRecipe(BLANK_MIDDLE, {}, {
        slotRegistry: registry,
        placement: placementFor(BLANK_MIDDLE_TEXT, "mara"),
      })
    ).rejects.toThrow(/describes 2 cells and this run has 3/);
    expect(registry.has("mine")).toBe(false);
  });
});

/**
 * A blank cell in the middle, and the four things that have to call it cell 1.
 *
 * This is the case that used to break all four differently: `planRun` filtered
 * the blank chain and numbered what was left, `runRecipe` filtered it too but
 * only for the gate's arithmetic, `run.manifest` skipped it and kept the raw
 * number anyway, and the kernel numbered every cell the way the notebook does.
 * One index space means one answer, and the answer is the notebook's, because
 * the notebook's is the one on screen — `ToolkitShell` labels each cell `[i]`
 * from `nb.chains.map((chain, i) => …)`, blank cells included.
 */
describe("a blank cell in the middle is cell 1 to everything that counts", () => {
  it("agrees across the plan, the manifest, the gate and the kernel", async () => {
    const plan = planRun(BLANK_MIDDLE, { me: "mara", roster: ROSTER });

    // 1 · The plan. Three cells, and the blank one is placed nowhere rather
    // than described as a cell every participant runs.
    expect(plan.ok, plan.refusals.map((r) => r.message).join(" · ")).toBe(true);
    expect(plan.cells.map((c) => [c.index, c.basis])).toEqual([
      [0, "header"],
      [1, "empty"],
      [2, "header"],
    ]);
    expect(plan.cells[1].why).toContain("this cell is empty");
    expect(plan.counts.empty).toBe(1);
    // Every cell is in exactly one bucket, so a blank one cannot go missing
    // from the summary by being counted nowhere.
    const { solo, forced, chosen, witnessed, rendezvous, empty } = plan.counts;
    expect(solo + forced + chosen + witnessed + rendezvous + empty).toBe(plan.cells.length);

    // 2 · The gate. okafor's cell 0 is declined *as cell 0*, and mara's cell 2
    // runs. The blank cell is neither run nor skipped: there is nothing in it
    // to do either to.
    /** @type {import("../lib/toolkit/placement.js").SkippedCell[]} */
    const skipped = [];
    const registry = createSlotRegistry();
    await runRecipe(BLANK_MIDDLE, {}, {
      slotRegistry: registry,
      placement: { plan, onSkip: (s) => skipped.push(s) },
    });
    expect(skipped.map((s) => s.cell)).toEqual([0]);
    expect(registry.has("first")).toBe(false);
    expect(registry.has("mine")).toBe(true);

    // 3 · The manifest. A row per cell, each calling itself by its own
    // position, and the blank one carrying no text rather than being left out.
    const manifest = await manifestOf(BLANK_MIDDLE);
    expect(manifest.cells.map((c) => c.index)).toEqual([0, 1, 2]);
    expect(manifest.cells[1].recipe).toBe("");
    expect(manifest.cells[2].recipe).toContain("$mine");

    // 4 · The kernel, which is where the numbers on screen come from. It ran
    // two cells, and it calls the second of them cell 2.
    const kernel = createKernel();
    await kernel.runAll(/** @type {*} */ (BLANK_MIDDLE).chains, {});
    expect(kernel.getRunLog().map((c) => c.index)).toEqual([0, 2]);
    expect(kernel.getCellOutputs(2).length).toBeGreaterThan(0);
    expect(kernel.getCellOutputs(1)).toEqual([]);
    expect(kernel.getCellStatus(1)).toBe("idle");

    // And the four agree with each other, which is the whole property: cell 2
    // is the same cell in the plan, in the manifest and in the run log.
    expect(plan.cells[2].index).toBe(manifest.cells[2].index);
    expect(kernel.getRunLog()[1].index).toBe(manifest.cells[2].index);
    expect(kernel.getRunLog()[1].recipe).toBe(manifest.cells[2].recipe);
  });

  it("checks the run against a manifest that carries a cell nothing ran", async () => {
    // The other half: a receipt has no row for a blank cell, because nothing
    // was performed in it. That is the one place the two documents legitimately
    // count differently, and it must not read as a run that skipped a cell.
    const kernel = createKernel();
    await kernel.runAll(/** @type {*} */ (BLANK_MIDDLE).chains, {});
    const manifest = await manifestOf(BLANK_MIDDLE);
    const receipt = await buildRunReceipt({
      recipeSource: manifest.recipeSource,
      cells: kernel.getRunLog(),
    });
    const honoured = manifestHonouredBy(manifest, receipt);
    expect(honoured.ok, summarizeHonour(honoured)).toBe(true);
  });
});

/**
 * The guarantee everything above rests on: a run that was never placed is the
 * run this engine performed before the gate was written.
 *
 * Asserted by running each corpus entry twice in the same process — once with
 * no `placement`, once with the placement a `planRun` of that same recipe
 * produces — and comparing what came back. A recipe that names no peer plans
 * as `solo`, so the second run exercises the gate's admit path on every cell
 * and must come out where the first one did, artifact for artifact and failure
 * for failure.
 */
describe("an unplaced run is the run it always was", () => {
  /** @param {string} label @param {string} src */
  async function bothWays(label, src) {
    const compiled = compile(src);
    const plan = planRun(compiled);
    expect(plan.play, label).toBe("solo");
    /** @param {*} [placement] */
    const once = async (placement) => {
      try {
        return { ok: true, arts: shape(await runRecipe(compiled.ast, {}, placement ? { placement } : {})) };
      } catch (err) {
        return { ok: false, message: String(/** @type {*} */ (err)?.message) };
      }
    };
    const plain = await once();
    const gated = await once({ plan });
    expect(gated, label).toEqual(plain);
    return plain;
  }

  it("holds over every shipped preset", async () => {
    let swept = 0;
    for (const preset of PRESETS) {
      const compiled = compile(preset.recipe);
      if (!compiled.validation.ok) continue;
      await bothWays(preset.id, preset.recipe);
      swept++;
    }
    expect(swept).toBeGreaterThan(10);
  }, 120_000);

  it("holds over every docs/RECIPE.md fence that compiles", async () => {
    // `.replace(/\r\n/g, "\n")` because the fence pattern wants a bare `\n`
    // after the marker, and a Windows checkout writes CRLF — without it this
    // matched nothing and the sweep reported success having swept zero fences.
    // `swept` below is the guard against exactly that, and it is why the count
    // is asserted rather than just the outcomes.
    const md = readFileSync(
      fileURLToPath(new URL("../../../docs/RECIPE.md", import.meta.url)),
      "utf8"
    ).replace(/\r\n/g, "\n");
    const re = /```[a-z]*\n([\s\S]*?)```/g;
    let m;
    let i = -1;
    let swept = 0;
    while ((m = re.exec(md))) {
      i++;
      const compiled = compileRecipe(m[1]);
      if (!compiled.validation.ok) continue;
      // The doc's placement example names peers on purpose; it is planned by
      // `run-plan-differential.test.js` and is not part of the inert corpus.
      if (planRun(compiled).play !== "solo") continue;
      await bothWays(`RECIPE.md fence ${i}`, m[1]);
      swept++;
    }
    expect(swept).toBeGreaterThanOrEqual(5);
  }, 120_000);
});
