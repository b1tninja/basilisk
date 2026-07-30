/**
 * Notebook session kernel — live @slots + per-cell outputs across Runs.
 */

import { runRecipe } from "./engine.js";
import { createSlotRegistry } from "./slot-registry.js";
import { recipeChains } from "./recipe.js";

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
  /** @type {Map<number, { ranAt: number, durationMs: number }>} Last successful run, for the readiness/status line. */
  const cellTimings = new Map();

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
    const startedAt = Date.now();
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
      cellTimings.set(cellIndex, { ranAt: Date.now(), durationMs: Date.now() - startedAt });
      invalidateFrom(cellIndex + 1);
      return artifacts;
    } catch (err) {
      setCellStatus(cellIndex, "error");
      cellTimings.set(cellIndex, { ranAt: Date.now(), durationMs: Date.now() - startedAt });
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
    for (const arts of cellOutputs.values()) wipeArtifacts(arts);
    cellOutputs.clear();
    cellStatus.clear();
    cellTimings.clear();
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
    cellOutputs.clear();
    cellStatus.clear();
    cellTimings.clear();
    for (const [i, arts] of nextOut) cellOutputs.set(i, arts);
    for (const [i, st] of nextStatus) cellStatus.set(i, st);
    for (const [i, t] of nextTimings) cellTimings.set(i, t);
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
