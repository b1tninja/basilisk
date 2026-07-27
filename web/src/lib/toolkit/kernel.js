/**
 * Notebook session kernel — live @slots + per-cell outputs across Runs.
 */

import { runRecipe } from "./engine.js";
import { createSlotRegistry } from "./slot-registry.js";
import { recipeChains } from "./recipe.js";

/**
 * @typedef {"idle"|"running"|"ok"|"error"|"stale"} CellStatus
 */

/**
 * @typedef {object} ToolkitKernel
 * @property {ReturnType<typeof createSlotRegistry>} slots
 * @property {(i: number) => import("./engine.js").ToolkitArtifact[]} getCellOutputs
 * @property {(i: number) => CellStatus} getCellStatus
 * @property {(i: number, status: CellStatus) => void} setCellStatus
 * @property {(i: number) => void} clearCellOutputs
 * @property {(fromIndex: number) => void} invalidateFrom
 * @property {() => number[]} staleCellIndices
 * @property {(cellIndex: number, chain: import("./recipe.js").RecipeChain|import("./recipe.js").RecipeStep[], bindings?: import("./engine.js").RuntimeBindings) => Promise<import("./engine.js").ToolkitArtifact[]>} runCell
 * @property {(chains: import("./recipe.js").RecipeChain[], bindings?: import("./engine.js").RuntimeBindings, opts?: { from?: number }) => Promise<import("./engine.js").ToolkitArtifact[][]>} runAll
 * @property {() => void} clearSensitive
 * @property {() => void} destroy
 * @property {() => import("./slot-registry.js").SlotMeta[]} listSlots
 * @property {() => number} slotCount
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
   * @param {CellStatus} status
   */
  const setCellStatus = (i, status) => {
    cellStatus.set(i, status);
  };

  /**
   * @param {number} i
   */
  const clearCellOutputs = (i) => {
    cellOutputs.delete(i);
    if (getCellStatus(i) !== "idle") setCellStatus(i, "idle");
  };

  /**
   * Mark cells at/after fromIndex as stale if they had outputs.
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
   * @param {number} cellIndex
   * @param {import("./recipe.js").RecipeChain|import("./recipe.js").RecipeStep[]} chainOrSteps
   * @param {import("./engine.js").RuntimeBindings} [bindings]
   */
  const runCell = async (cellIndex, chainOrSteps, bindings = {}) => {
    const chain = Array.isArray(chainOrSteps)
      ? { steps: chainOrSteps }
      : chainOrSteps;
    if (!chain?.steps?.length) {
      throw new Error("Empty cell");
    }
    setCellStatus(cellIndex, "running");
    try {
      const artifacts = await runRecipe(
        { chains: [chain], steps: chain.steps, source: "" },
        bindings,
        {
          slotRegistry: slots,
          allowReplaceSlots: true,
        }
      );
      cellOutputs.set(cellIndex, artifacts);
      setCellStatus(cellIndex, "ok");
      invalidateFrom(cellIndex + 1);
      return artifacts;
    } catch (err) {
      setCellStatus(cellIndex, "error");
      throw err;
    }
  };

  /**
   * @param {import("./recipe.js").RecipeChain[]} chains
   * @param {import("./engine.js").RuntimeBindings} [bindings]
   * @param {{ from?: number }} [opts]
   */
  const runAll = async (chains, bindings = {}, opts = {}) => {
    const list = recipeChains(chains);
    const from = opts.from ?? 0;
    /** @type {import("./engine.js").ToolkitArtifact[][]} */
    const all = [];
    for (let i = from; i < list.length; i++) {
      if (!list[i]?.steps?.length) {
        all.push([]);
        continue;
      }
      all.push(await runCell(i, list[i], bindings));
    }
    return all;
  };

  const clearSensitive = () => {
    slots.clear();
    cellOutputs.clear();
    cellStatus.clear();
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
    cellOutputs.clear();
    cellStatus.clear();
    for (const [i, arts] of nextOut) cellOutputs.set(i, arts);
    for (const [i, st] of nextStatus) cellStatus.set(i, st);
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
    setCellStatus,
    clearCellOutputs,
    invalidateFrom,
    staleCellIndices,
    runCell,
    runAll,
    clearSensitive,
    destroy,
    remapCells,
    markAllWithOutputsStale,
    listSlots: () => slots.listMetas(),
    slotCount: () => slots.size(),
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
