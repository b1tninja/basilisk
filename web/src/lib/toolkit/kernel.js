/**
 * Notebook session kernel — live $slots + per-cell outputs across Runs.
 */

import { runRecipe } from "./engine.js";
import { createSlotRegistry } from "./slot-registry.js";
import { recipeChains, serializeRecipe } from "./recipe.js";
import { digestArtifact, digestInputs } from "./receipt.js";

/**
 * Best-effort wipe of artifact tiles (owned bytes + inspect snapshots).
 * @param {import("./engine.js").ToolkitArtifact|null|undefined} art
 */
function wipeArtifact(art) {
  if (!art) return;
  try {
    if (art.bytes instanceof Uint8Array && art.bytes.byteLength > 0) {
      art.bytes.fill(0);
    }
  } catch (_) {
    /* ignore */
  }
  if (typeof art.content === "string") art.content = "";
  const snap = art.inspectSnapshot;
  if (snap) {
    try {
      if (snap.bytes instanceof Uint8Array && snap.bytes.byteLength > 0) {
        snap.bytes.fill(0);
      }
    } catch (_) {
      /* ignore */
    }
    if (typeof snap.text === "string") snap.text = "";
    if (snap.shares?.mnemonics) {
      snap.shares.mnemonics = snap.shares.mnemonics.map(() => "");
    }
    const kp = snap.keypair;
    if (kp) {
      try {
        if (kp.raw instanceof Uint8Array && kp.raw.byteLength > 0) kp.raw.fill(0);
      } catch (_) {
        /* ignore */
      }
      if (kp.privateJwk && typeof kp.privateJwk === "object") {
        for (const k of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
          if (k in kp.privateJwk) kp.privateJwk[k] = "";
        }
      }
      kp.privateJwk = undefined;
    }
  }
  art.inspectSnapshot = undefined;
}

/**
 * @param {import("./engine.js").ToolkitArtifact[]} list
 */
function wipeArtifacts(list) {
  if (!Array.isArray(list)) return;
  for (const a of list) wipeArtifact(a);
}

/**
 * @typedef {"idle"|"running"|"ok"|"error"|"stale"} CellStatus
 */

/**
 * @typedef {object} CellRunError
 * @property {string} message  The thrown message, verbatim.
 * @property {number} stepIndex  Index of the failing step *within this cell*, or -1.
 * @property {string} stepName  Name of the op that threw, or "".
 */

/**
 * Read a throw as the row a cell can render (§33c, runtime half).
 *
 * `runCell` used to keep only the *fact* of a failure — `setCellStatus("error")`
 * — and re-throw the reason to whoever called `runAll`, where it surfaced once
 * in the run bar, roughly 130px above the cell that failed and outside it.
 * `rtc-live-diagnostics` was the worked example: three empty cells and one red
 * line at the top, none of it attached to `rtc.state`, which is the op that
 * threw and the op whose message names both ways to fix it.
 *
 * Pure and exported because `vitest.config.js` is `environment: "node"`: this
 * is the part that can be *wrong* — the anchor, the fallback wording — and it
 * is pinnable without a renderer, the same seam `cellErrorsForChains` uses.
 *
 * The message is copied byte for byte. `requireLinks` and its neighbours spend
 * real care naming the remedy ("open one with peer.offer / peer.answer, or a
 * mesh with quorum.offer / quorum.join"); a layout that needed those words
 * shortened would be the wrong layout.
 *
 * Anchoring comes from the engine, not from a guess here. `basiliskStep` (the
 * op name) has existed since the CLI needed it and had no consumer in `src/`;
 * `basiliskStepIndex` is its index, numbered the way `validateRecipe` numbers
 * compile errors. `runCell` runs one chain, so the engine's continuous
 * numbering starts at 0 for this cell and the index is already cell-relative —
 * the same number `cellErrorsForChains` deals back after rebasing, so the two
 * channels light the same chip.
 *
 * @param {unknown} err
 * @returns {CellRunError}
 */
export function cellRunErrorFrom(err) {
  const raw = err instanceof Error ? err.message : String(err ?? "");
  const anchor = /** @type {*} */ (err)?.basiliskStepIndex;
  const name = /** @type {*} */ (err)?.basiliskStep;
  return {
    // A throw with no message at all still has to say something; "Run failed"
    // is the honest floor, and it is never preferred over a real message.
    message: raw || "Run failed",
    stepIndex: Number.isInteger(anchor) && anchor >= 0 ? anchor : -1,
    stepName: typeof name === "string" ? name : "",
  };
}

/**
 * @typedef {object} ToolkitKernel
 * @property {ReturnType<typeof createSlotRegistry>} slots
 * @property {(i: number) => import("./engine.js").ToolkitArtifact[]} getCellOutputs
 * @property {(i: number) => CellStatus} getCellStatus
 * @property {(i: number) => { ranAt: number, durationMs: number }|null} getCellTiming
 * @property {(i: number) => CellRunError|null} getCellRunError
 * @property {(i: number, status: CellStatus) => void} setCellStatus
 * @property {(i: number) => void} clearCellOutputs
 * @property {(fromIndex: number) => void} invalidateFrom
 * @property {() => number[]} staleCellIndices
 * @property {(cellIndex: number, chain: import("./recipe.js").RecipeChain|import("./recipe.js").RecipeStep[], bindings?: import("./engine.js").RuntimeBindings, placement?: { plan: import("./plan.js").RunPlan, onSkip: (s: import("./placement.js").SkippedCell) => void }) => Promise<import("./engine.js").ToolkitArtifact[]>} runCell
 * @property {(chains: import("./recipe.js").RecipeChain[], bindings?: import("./engine.js").RuntimeBindings, opts?: { from?: number }) => Promise<import("./engine.js").ToolkitArtifact[][]>} runAll
 * @property {() => void} clearSensitive
 * @property {() => void} lockSensitive
 * @property {(mapFn: (oldIndex: number) => number|null) => void} remapCells
 * @property {() => void} markAllWithOutputsStale
 * @property {() => void} destroy
 * @property {() => import("./slot-registry.js").SlotMeta[]} listSlots
 * @property {() => number} slotCount
 * @property {() => import("./receipt.js").ReceiptCell[]} getRunLog
 */

/**
 * @returns {ToolkitKernel}
 */
export function createKernel() {
  const slots = createSlotRegistry();
  /** @type {Map<number, import("./engine.js").ToolkitArtifact[]>} */
  const cellOutputs = new Map();
  /** @type {Map<number, CellStatus>} */
  const cellStatus = new Map();
  /** @type {Map<number, { ranAt: number, durationMs: number }>} Last successful run, for the readiness/status line. */
  const cellTimings = new Map();
  /**
   * Why the last run of a cell failed, for the banner inside that cell.
   *
   * Held beside `cellStatus` rather than derived from it because `"error"` is
   * a fact about the cell and the message is a fact about *one run of it*:
   * they are written and cleared together, which is the whole staleness rule.
   * @type {Map<number, CellRunError>}
   */
  const cellRunErrors = new Map();
  /**
   * Digested log of the cells run this session, in execution order — the prior
   * half of what `run.receipt` reports.
   *
   * Kept here rather than derived from `cellOutputs` because a receipt is about
   * *the run*, not about the current state of the tiles: re-running cell 1
   * replaces its outputs, and the receipt should record that both runs
   * happened. Cleared by Clear sensitive along with everything else, since a
   * digest of a share is still a fact about a ceremony the user asked to
   * forget.
   * @type {import("./receipt.js").ReceiptCell[]}
   */
  let runLog = [];

  /**
   * @param {number} i
   */
  const getCellOutputs = (i) => cellOutputs.get(i) || [];

  /**
   * @param {number} i
   * @returns {CellStatus}
   */
  const getCellStatus = (i) => cellStatus.get(i) || "idle";

  /**
   * @param {number} i
   * @returns {{ ranAt: number, durationMs: number } | null}
   */
  const getCellTiming = (i) => cellTimings.get(i) || null;

  /**
   * @param {number} i
   * @returns {CellRunError | null}
   */
  const getCellRunError = (i) => cellRunErrors.get(i) || null;

  /**
   * @param {number} i
   * @param {CellStatus} status
   */
  const setCellStatus = (i, status) => {
    cellStatus.set(i, status);
  };

  /**
   * @param {number} i
   */
  const clearCellOutputs = (i) => {
    wipeArtifacts(cellOutputs.get(i) || []);
    cellOutputs.delete(i);
    cellTimings.delete(i);
    // A cell reset to `idle` has no last run, so it has no reason for one.
    cellRunErrors.delete(i);
    if (getCellStatus(i) !== "idle") setCellStatus(i, "idle");
  };

  /**
   * Mark cells at/after fromIndex as stale if they had outputs.
   *
   * Run errors are deliberately *not* swept here. Staleness says "what you are
   * looking at was computed from something that has since changed", which only
   * applies to a cell holding outputs; a failed cell holds none, and its
   * message is a report of the last thing that happened in it, which an
   * upstream re-run does not undo. It clears when this cell runs again — see
   * `runCell` — and not before, because clearing it earlier would leave a red
   * status dot with nothing beside it, which is the defect this fixed.
   *
   * @param {number} fromIndex
   */
  const invalidateFrom = (fromIndex) => {
    for (const [i, arts] of cellOutputs) {
      if (i >= fromIndex && arts.length) {
        setCellStatus(i, "stale");
      }
    }
  };

  const staleCellIndices = () =>
    [...cellStatus.entries()]
      .filter(([, s]) => s === "stale")
      .map(([i]) => i)
      .sort((a, b) => a - b);

  /**
   * Record one executed cell as digests.
   *
   * A `run.receipt` tile is itself an output of the cell that minted it, and
   * including it would make the log self-referential — the receipt would have
   * to contain the digest of a document that contains that digest. Dropped
   * here, which also keeps a later `run.verify` re-run comparable: its own
   * receipt tile is dropped on the same rule.
   *
   * @param {number} cellIndex
   * @param {string} cellRecipe
   * @param {number} startedAt
   * @param {import("./engine.js").RuntimeBindings} bindings
   * @param {import("./engine.js").ToolkitArtifact[]} artifacts
   */
  const appendRunLog = async (cellIndex, cellRecipe, startedAt, bindings, artifacts) => {
    try {
      const outputs = [];
      for (const a of artifacts) {
        if (a?.role === "receipt") continue;
        outputs.push(await digestArtifact(a));
      }
      runLog.push({
        index: cellIndex,
        recipe: cellRecipe,
        startedAt: new Date(startedAt).toISOString(),
        durationMs: Date.now() - startedAt,
        inputs: await digestInputs(bindings?.inputs),
        outputs,
      });
    } catch (_) {
      // Receipt bookkeeping must never turn a successful run into a failure.
    }
  };

  /**
   * @param {number} cellIndex
   * @param {import("./recipe.js").RecipeChain|import("./recipe.js").RecipeStep[]} chainOrSteps
   * @param {import("./engine.js").RuntimeBindings} [bindings]
   * @param {{ plan: import("./plan.js").RunPlan,
   *   onSkip: (s: import("./placement.js").SkippedCell) => void }} [placement]
   *   Who runs what. Absent, the gate is never built and this runs exactly what
   *   it ran before — `placement.js` is explicit that no placement and a
   *   permissive one are different things, and defaulting one to the other is
   *   how a partly-filled plan silently runs somebody else's cell here.
   *
   *   `firstCell` is the cell's index *in the plan*: this runs one chain at a
   *   time against a one-chain AST, so the chain's own index is always 0 and
   *   the gate has to be told which cell that actually is.
   */
  const runCell = async (cellIndex, chainOrSteps, bindings = {}, placement = undefined) => {
    const chain = Array.isArray(chainOrSteps)
      ? { steps: chainOrSteps }
      : chainOrSteps;
    if (!chain?.steps?.length) {
      throw new Error("Empty cell");
    }
    setCellStatus(cellIndex, "running");
    // The previous failure stops being the answer the moment this cell is
    // running again: it clears here, on entry, rather than on success, so a
    // re-run never shows a spinner next to the reason the *last* one died.
    cellRunErrors.delete(cellIndex);
    const startedAt = Date.now();
    let cellRecipe = "";
    try {
      cellRecipe = serializeRecipe({ chains: [chain] });
    } catch (_) {
      /* a receipt should never be the reason a run fails */
    }
    // `run.receipt` inside this cell needs the cells that came before it, plus
    // enough context to name this one. Passed through bindings — the same
    // runtime channel `input`/`shares` use — so none of it can leak into the
    // recipe text or a share link.
    const receiptCtx = {
      runLog: [...runLog],
      cellIndex,
      cellRecipe,
      // No cast: `receipt` is declared on RuntimeBindings now. The casts were
      // here because it was not, which is the only thing that made reaching
      // through `bindings` for it look unsafe.
      recipeSource: bindings?.receipt?.recipeSource || cellRecipe,
      label: bindings?.receipt?.label || "",
      startedAt: new Date(startedAt).toISOString(),
    };
    try {
      const artifacts = await runRecipe(
        { chains: [chain], steps: chain.steps, source: "" },
        { ...bindings, receipt: receiptCtx },
        {
          slotRegistry: slots,
          allowReplaceSlots: true,
          ...(placement
            ? { placement: { ...placement, firstCell: cellIndex } }
            : {}),
        }
      );
      cellOutputs.set(cellIndex, artifacts);
      setCellStatus(cellIndex, "ok");
      cellTimings.set(cellIndex, { ranAt: Date.now(), durationMs: Date.now() - startedAt });
      await appendRunLog(cellIndex, cellRecipe, startedAt, bindings, artifacts);
      invalidateFrom(cellIndex + 1);
      return artifacts;
    } catch (err) {
      setCellStatus(cellIndex, "error");
      cellTimings.set(cellIndex, { ranAt: Date.now(), durationMs: Date.now() - startedAt });
      // Keep the reason where the failure happened. Re-thrown unchanged: the
      // run bar still answers "did the notebook run", and `runFrom` still
      // stops the loop on it — this records *why*, it does not swallow.
      cellRunErrors.set(cellIndex, cellRunErrorFrom(err));
      throw err;
    }
  };

  /**
   * @param {import("./recipe.js").RecipeChain[]} chains
   * @param {import("./engine.js").RuntimeBindings} [bindings]
   * @param {{ from?: number, placement?: { plan: import("./plan.js").RunPlan,
   *   onSkip: (s: import("./placement.js").SkippedCell) => void } }} [opts]
   */
  const runAll = async (chains, bindings = {}, opts = {}) => {
    const { placement } = opts;
    const list = recipeChains(chains);
    const from = opts.from ?? 0;
    /** @type {import("./engine.js").ToolkitArtifact[][]} */
    const all = [];
    for (let i = from; i < list.length; i++) {
      if (!list[i]?.steps?.length) {
        all.push([]);
        continue;
      }
      all.push(await runCell(i, list[i], bindings, placement));
    }
    return all;
  };

  const clearSensitive = () => {
    for (const arts of cellOutputs.values()) wipeArtifacts(arts);
    cellOutputs.clear();
    cellStatus.clear();
    cellTimings.clear();
    // A failure message names ops, slots and sometimes a key id — it goes with
    // the statuses it belongs to, not after them.
    cellRunErrors.clear();
    runLog = [];
    slots.clear();
    // A live quorum exchange is session state too — tear it down and zeroize
    // its keys. Dynamic import so WebRTC never enters the base bundle; if the
    // module was never loaded there is nothing to close.
    void import("./quorum-ops.js")
      .then((q) => q.closeQuorumExchange("closed"))
      .catch(() => {});
  };

  /**
   * Evict private/sensitive slots and wipe all cell outputs (Lock-all).
   * Keeps public recipients / public-key slots.
   */
  const lockSensitive = () => {
    for (const arts of cellOutputs.values()) wipeArtifacts(arts);
    cellOutputs.clear();
    cellStatus.clear();
    cellTimings.clear();
    cellRunErrors.clear();
    runLog = [];
    slots.evictSensitive();
  };

  const destroy = () => {
    clearSensitive();
  };

  /**
   * Remap per-cell output/status buckets after insert/delete/reorder.
   * `mapFn(oldIndex)` → new index, or `null` to drop that bucket.
   * @param {(oldIndex: number) => number|null} mapFn
   */
  const remapCells = (mapFn) => {
    /** @type {Map<number, import("./engine.js").ToolkitArtifact[]>} */
    const nextOut = new Map();
    /** @type {Map<number, CellStatus>} */
    const nextStatus = new Map();
    /** @type {Map<number, { ranAt: number, durationMs: number }>} */
    const nextTimings = new Map();
    /** @type {Map<number, CellRunError>} */
    const nextRunErrors = new Map();
    for (const [i, arts] of cellOutputs) {
      const ni = mapFn(i);
      if (ni == null || ni < 0) continue;
      nextOut.set(ni, arts);
    }
    for (const [i, st] of cellStatus) {
      const ni = mapFn(i);
      if (ni == null || ni < 0) continue;
      nextStatus.set(ni, st === "running" ? "idle" : st);
    }
    for (const [i, t] of cellTimings) {
      const ni = mapFn(i);
      if (ni == null || ni < 0) continue;
      nextTimings.set(ni, t);
    }
    // Moved with the status it explains. A message left behind would sit in a
    // cell that never ran — the misattribution `dealByCell` exists to prevent
    // on the compile side, arriving through the runtime one.
    for (const [i, e] of cellRunErrors) {
      const ni = mapFn(i);
      if (ni == null || ni < 0) continue;
      nextRunErrors.set(ni, e);
    }
    cellOutputs.clear();
    cellStatus.clear();
    cellTimings.clear();
    cellRunErrors.clear();
    for (const [i, arts] of nextOut) cellOutputs.set(i, arts);
    for (const [i, st] of nextStatus) cellStatus.set(i, st);
    for (const [i, t] of nextTimings) cellTimings.set(i, t);
    for (const [i, e] of nextRunErrors) cellRunErrors.set(i, e);
  };

  /** After reorder, keep tiles but mark every cell that has outputs as stale. */
  const markAllWithOutputsStale = () => {
    for (const [i, arts] of cellOutputs) {
      if (arts.length) setCellStatus(i, "stale");
    }
  };

  return {
    slots,
    getCellOutputs,
    getCellStatus,
    getCellTiming,
    getCellRunError,
    setCellStatus,
    clearCellOutputs,
    invalidateFrom,
    staleCellIndices,
    runCell,
    runAll,
    clearSensitive,
    lockSensitive,
    destroy,
    remapCells,
    markAllWithOutputsStale,
    listSlots: () => slots.listMetas(),
    slotCount: () => slots.size(),
    /** Digested per-cell log of this session's runs (see `runLog`). */
    getRunLog: () => runLog.map((c) => ({ ...c })),
  };
}

/**
 * Run a single chain against a preseeded registry (test helper).
 * @param {import("./recipe.js").RecipeChain|import("./recipe.js").RecipeStep[]} chain
 * @param {import("./engine.js").RuntimeBindings} [bindings]
 * @param {ReturnType<typeof createSlotRegistry>} [slotRegistry]
 */
export async function runChain(chain, bindings = {}, slotRegistry) {
  const registry = slotRegistry || createSlotRegistry();
  const c = Array.isArray(chain) ? { steps: chain } : chain;
  const artifacts = await runRecipe(
    { chains: [c], steps: c.steps || [], source: "" },
    bindings,
    { slotRegistry: registry, allowReplaceSlots: true }
  );
  return { artifacts, slots: registry };
}
