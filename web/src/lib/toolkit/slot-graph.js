/**
 * Cross-cell slot dependency analysis — which of a cell's runtime needs are
 * "wired" to an earlier cell's outputs rather than genuinely missing.
 *
 * The gate bug this exists for: a companion pair like "Split P-256 scalar" /
 * "Rebuild P-256 key" loads as two cells, the second starts with the `shares`
 * panel op, and the old gating blocked the whole notebook on the second
 * cell's empty paste panel — so the first cell, which *produces* those
 * shares, could never run. The graph below distinguishes "this input will
 * exist by the time the cell runs" (wired — run up to it, pause there if it
 * still isn't) from "nothing in this notebook can produce it" (a real
 * blocker).
 *
 * Pure and syntactic-plus-types: producers come from walking the recipe, not
 * from hand-maintained lists, so they cannot claim an op that no longer
 * exists.
 * @module lib/toolkit/slot-graph
 */

import { getStep } from "./registry.js";
import { walkPipelineTypes } from "./types.js";
import { slotLabelKey } from "./recipe-parse.js";

/** @typedef {import("./recipe.js").RecipeStep} RecipeStep */

/**
 * @param {RecipeStep[]} steps
 * @param {(label: string) => void} add
 */
function collectOutLabels(steps, add) {
  for (const step of steps || []) {
    if (step.name === "out") {
      const label = slotLabelKey(String(step.params?.name || ""));
      if (label) add(label);
    }
    for (const b of step.body || []) {
      if (b.name === "out") {
        const label = slotLabelKey(String(b.params?.name || ""));
        if (label) add(label);
      }
    }
    for (const br of step.branches || []) {
      collectOutLabels(br.body || [], add);
    }
  }
}

/**
 * @param {RecipeStep[]} steps
 * @param {(label: string) => void} add
 */
function collectSlotRefs(steps, add) {
  for (const step of steps || []) {
    if (step.name === "in") {
      const ref = String(step.params?.ref || "");
      if (!/^\d+$/.test(ref)) {
        const label = slotLabelKey(ref);
        if (label) add(label);
      }
    }
    const spec = getStep(step.name);
    for (const p of spec?.params || []) {
      // `out @x`'s name param *defines* the slot — it consumes nothing.
      if (step.name === "out" && p.name === "name") continue;
      const raw = String(step.params?.[p.name] ?? "");
      if (raw.startsWith("@")) {
        const label = slotLabelKey(raw);
        if (label) add(label);
      }
    }
    for (const b of step.body || []) collectSlotRefs([b], add);
    for (const br of step.branches || []) collectSlotRefs(br.body || [], add);
  }
}

/**
 * Whether a cell emits *indexed share slots*: a `foreach` over a shares tip
 * whose body writes `out`. That is exactly what the `shares` panel op can
 * draw from at run time when nothing was pasted.
 * @param {RecipeStep[]} steps
 * @returns {boolean}
 */
export function producesShareSlots(steps) {
  if (!steps?.length) return false;
  const { edges } = walkPipelineTypes(steps, { getStep }, new Map());
  return steps.some((step, i) => {
    if (step.name !== "foreach") return false;
    if (edges[i]?.input?.base !== "shares") return false;
    return (step.body || []).some((b) => b.name === "out");
  });
}

/**
 * @typedef {object} CellSlotIO
 * @property {Set<string>} produces  labeled slots this cell writes
 * @property {Set<string>} consumes  labeled slots this cell reads
 * @property {boolean} producesShares indexed share slots (foreach out over shares)
 */

/**
 * @param {{ steps?: RecipeStep[] }} chain
 * @returns {CellSlotIO}
 */
export function cellSlotIO(chain) {
  /** @type {Set<string>} */
  const produces = new Set();
  /** @type {Set<string>} */
  const consumes = new Set();
  const steps = chain?.steps || [];
  collectOutLabels(steps, (l) => produces.add(l));
  collectSlotRefs(steps, (l) => consumes.add(l));
  return { produces, consumes, producesShares: producesShareSlots(steps) };
}

/**
 * Which of `cellIndex`'s runtime input needs are wired to an earlier cell.
 *
 * "Wired" is a promise about *this notebook*, not about current state: the
 * value does not exist yet, but running the cells above materializes it. The
 * caller treats a wired need as "run up to here, then re-check" (checkpoint
 * semantics) instead of refusing to run anything.
 *
 * @param {Array<{ steps?: RecipeStep[] }>} chains
 * @param {number} cellIndex
 * @returns {{ wiredNeeds: Set<string>, wiredSlots: Set<string> }}
 */
export function wiredForCell(chains, cellIndex) {
  /** @type {Set<string>} */
  const producedAbove = new Set();
  let sharesAbove = false;
  for (let i = 0; i < cellIndex; i++) {
    const io = cellSlotIO(chains[i] || {});
    for (const l of io.produces) producedAbove.add(l);
    if (io.producesShares) sharesAbove = true;
  }
  const here = cellSlotIO(chains[cellIndex] || {});
  /** @type {Set<string>} */
  const wiredSlots = new Set();
  for (const l of here.consumes) {
    if (producedAbove.has(l)) wiredSlots.add(l);
  }
  /** @type {Set<string>} */
  const wiredNeeds = new Set();
  // The `shares` paste panel is satisfiable from indexed share slots an
  // earlier cell emits (the engine falls back to them when nothing is
  // pasted), so an upstream split wires the need.
  const usesSharesPanel = (chains[cellIndex]?.steps || []).some(
    (s) => s.name === "shares"
  );
  if (usesSharesPanel && sharesAbove) wiredNeeds.add("shares");
  return { wiredNeeds, wiredSlots };
}
