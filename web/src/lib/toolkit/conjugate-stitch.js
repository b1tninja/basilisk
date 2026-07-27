/**
 * Companion preset stitching — explicit @slots only (no new pipe grammar).
 *
 * Modes:
 * - as-is: reverse already consumes a forward out slot
 * - slot: rewrite reverse `input` → `in @bridge` (ensure forward ends with out)
 * - inputs: reverse starts with shares / gpg.decrypt — runtime Inputs panel
 */

import { normalizeSlotRef } from "./recipe-parse.js";
import {
  PRESETS,
  canonicalizeRecipe,
  migrateRecipe,
  recipeChains,
  serializeRecipe,
} from "./recipe.js";

/**
 * @typedef {typeof PRESETS[number]} ToolkitPreset
 */

/**
 * @typedef {"as-is"|"slot"|"inputs"} StitchMode
 */

/**
 * @typedef {object} StitchResult
 * @property {string} recipe
 * @property {StitchMode} mode
 * @property {string|null} bridge
 * @property {string[]} [errors]
 * @property {ToolkitPreset} forward
 * @property {ToolkitPreset} reverse
 */

/**
 * Short UI copy for a stitch mode (Templates gallery + status toast).
 * @param {StitchMode|string} mode
 * @param {string|null} [bridge]
 * @returns {{ badge: string, hint: string, toast: string }}
 */
export function bridgeModeMeta(mode, bridge = null) {
  const slot = bridge && String(bridge).startsWith("@") ? String(bridge) : "@slot";
  switch (mode) {
    case "slot":
      return {
        badge: "Slot bridge",
        hint: `Run all top→bottom so ${slot} feeds the inverse cell.`,
        toast: `Added companion cells (slot bridge ${slot}) — Run all top→bottom.`,
      };
    case "inputs":
      return {
        badge: "Shares panel",
        hint: "After the split cell, paste mnemonics into the inverse cell’s Shares Inputs.",
        toast:
          "Added companion cells — run the split cell, then paste share tiles into the inverse Inputs.",
      };
    case "as-is":
    default:
      return {
        badge: "Linked slots",
        hint: "Already wired with out / in — Run all top→bottom.",
        toast: "Added companion cells — Run all top→bottom so slots feed the inverse cell.",
      };
  }
}

/**
 * Stable @slot label from a pair id (must match normalizeSlotRef rules).
 * @param {string} pairId
 * @returns {string}
 */
export function bridgeSlotName(pairId) {
  let bare = String(pairId || "bridge")
    .replace(/[^A-Za-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!bare) bare = "bridge";
  if (!/^[A-Za-z]/.test(bare)) bare = `p_${bare}`;
  return `@${bare}`;
}

/**
 * Group PRESETS by `pair` (forward = first in list order, reverse = second).
 * @param {ToolkitPreset[]} [presets]
 * @returns {{ id: string, forward: ToolkitPreset, reverse: ToolkitPreset }[]}
 */
export function listPresetPairs(presets = PRESETS) {
  /** @type {Map<string, { id: string, forward: ToolkitPreset|null, reverse: ToolkitPreset|null }>} */
  const map = new Map();
  for (const p of presets) {
    const id = p.pair;
    if (!id) continue;
    let cur = map.get(id);
    if (!cur) {
      cur = { id, forward: null, reverse: null };
      map.set(id, cur);
    }
    if (!cur.forward) cur.forward = p;
    else if (!cur.reverse && p.id !== cur.forward.id) cur.reverse = p;
  }
  return [...map.values()].filter(
    (p) => p.forward && p.reverse
  );
}

/**
 * @param {string} pairId
 * @param {ToolkitPreset[]} [presets]
 * @returns {{ id: string, forward: ToolkitPreset, reverse: ToolkitPreset }|null}
 */
export function resolvePresetPair(pairId, presets = PRESETS) {
  const id = String(pairId || "");
  if (!id) return null;
  return listPresetPairs(presets).find((p) => p.id === id) || null;
}

/**
 * @param {import("./recipe.js").RecipeStep[]|undefined} steps
 * @param {(s: import("./recipe.js").RecipeStep) => void} fn
 */
function walkSteps(steps, fn) {
  for (const s of steps || []) {
    fn(s);
    if (s.body?.length) walkSteps(s.body, fn);
    for (const br of s.branches || []) {
      if (br.body?.length) walkSteps(br.body, fn);
    }
  }
}

/**
 * @param {import("./recipe.js").RecipeAst|null} ast
 * @returns {Set<string>}  canonical `@label` outs
 */
export function collectOutLabels(ast) {
  /** @type {Set<string>} */
  const labels = new Set();
  for (const c of recipeChains(ast)) {
    walkSteps(c.steps, (s) => {
      if (s.name !== "out") return;
      const n = normalizeSlotRef(String(s.params?.name || "@output"), {
        allowIndex: false,
      });
      if (n.ok) labels.add(n.ref);
    });
  }
  return labels;
}

/**
 * Slots consumed via `in`/`from` or `@`-valued params (`key=@cek`, `to=@alices`).
 * @param {import("./recipe.js").RecipeAst|null} ast
 * @returns {Set<string>}
 */
export function collectConsumedSlots(ast) {
  /** @type {Set<string>} */
  const refs = new Set();
  for (const c of recipeChains(ast)) {
    walkSteps(c.steps, (s) => {
      if (s.name === "in" || s.name === "from") {
        const n = normalizeSlotRef(String(s.params?.ref || ""), {
          allowIndex: true,
        });
        if (n.ok && String(n.ref).startsWith("@")) refs.add(n.ref);
      }
      for (const [k, v] of Object.entries(s.params || {})) {
        if (k === "name" || k === "ref") continue;
        const sv = String(v ?? "").trim();
        if (!sv.startsWith("@")) continue;
        const n = normalizeSlotRef(sv, { allowIndex: false });
        if (n.ok) refs.add(n.ref);
      }
    });
  }
  return refs;
}

/**
 * @param {import("./recipe.js").RecipeAst|null} ast
 * @returns {string}
 */
function firstSourceName(ast) {
  const chains = recipeChains(ast);
  for (const c of chains) {
    if (c.steps?.length) return String(c.steps[0].name || "");
  }
  return "";
}

/**
 * Final `out @label` on the last non-empty chain tip, or null.
 * @param {import("./recipe.js").RecipeAst|null} ast
 * @returns {string|null}
 */
export function lastChainFinalOut(ast) {
  const chains = recipeChains(ast);
  for (let i = chains.length - 1; i >= 0; i--) {
    const steps = chains[i]?.steps || [];
    if (!steps.length) continue;
    const last = steps[steps.length - 1];
    if (last.name !== "out") return null;
    const n = normalizeSlotRef(String(last.params?.name || "@output"), {
      allowIndex: false,
    });
    return n.ok ? n.ref : null;
  }
  return null;
}

/**
 * Deep-clone steps for AST mutation.
 * @param {import("./recipe.js").RecipeStep} s
 * @returns {import("./recipe.js").RecipeStep}
 */
function cloneStep(s) {
  /** @type {Record<string, *>} */
  const params = Object.create(null);
  for (const [k, v] of Object.entries(s.params || {})) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
    params[k] = v;
  }
  /** @type {import("./recipe.js").RecipeStep} */
  const out = {
    name: s.name,
    params,
    start: s.start || 0,
    end: s.end || 0,
  };
  if (s.body?.length) out.body = s.body.map(cloneStep);
  if (s.branches?.length) {
    out.branches = s.branches.map((br) => ({
      ...br,
      body: (br.body || []).map(cloneStep),
    }));
  }
  return out;
}

/**
 * @param {import("./recipe.js").RecipeAst} ast
 * @returns {import("./recipe.js").RecipeAst}
 */
function cloneAst(ast) {
  const chains = recipeChains(ast).map((c) => ({
    steps: (c.steps || []).map(cloneStep),
  }));
  return {
    chains,
    steps: chains[0]?.steps || [],
    source: ast.source || "",
  };
}

/**
 * @param {import("./recipe.js").RecipeAst} ast
 * @param {string} bridge  `@label`
 * @returns {import("./recipe.js").RecipeAst}
 */
function appendOutToLastChain(ast, bridge) {
  const next = cloneAst(ast);
  const chains = next.chains;
  let idx = chains.length - 1;
  while (idx >= 0 && !(chains[idx].steps || []).length) idx -= 1;
  if (idx < 0) {
    chains.push({
      steps: [
        {
          name: "out",
          params: { name: bridge },
          start: 0,
          end: 0,
        },
      ],
    });
  } else {
    chains[idx].steps.push({
      name: "out",
      params: { name: bridge },
      start: 0,
      end: 0,
    });
  }
  next.steps = chains[0]?.steps || [];
  return next;
}

/**
 * Replace first chain’s leading `input`/`paste`/`cat` with `in @bridge`.
 * @param {import("./recipe.js").RecipeAst} ast
 * @param {string} bridge
 * @returns {import("./recipe.js").RecipeAst}
 */
function replaceFirstSourceWithIn(ast, bridge) {
  const next = cloneAst(ast);
  const chain = next.chains.find((c) => c.steps?.length);
  if (!chain?.steps?.length) return next;
  const head = String(chain.steps[0].name || "");
  if (head !== "input" && head !== "paste" && head !== "cat") return next;
  chain.steps[0] = {
    name: "in",
    params: { ref: bridge },
    start: 0,
    end: 0,
  };
  next.steps = next.chains[0]?.steps || [];
  return next;
}

/**
 * Rename reverse `out @label` that collide with forward outs so a joined
 * multi-chain recipe validates (and notebook Run all can register both).
 * @param {import("./recipe.js").RecipeAst} revAst
 * @param {Set<string>} occupied  canonical `@label` from forward
 * @returns {import("./recipe.js").RecipeAst}
 */
function dedupeReverseOuts(revAst, occupied) {
  if (!occupied.size) return revAst;
  const next = cloneAst(revAst);
  /** @type {Set<string>} */
  const used = new Set(occupied);
  walkSteps(
    recipeChains(next).flatMap((c) => c.steps || []),
    (s) => {
      if (s.name !== "out") return;
      const n = normalizeSlotRef(String(s.params?.name || "@output"), {
        allowIndex: false,
      });
      if (!n.ok || !occupied.has(n.ref)) return;
      let bare = n.ref.slice(1);
      let candidate = `@${bare}_rev`;
      let i = 2;
      while (used.has(candidate)) {
        candidate = `@${bare}_rev${i}`;
        i += 1;
      }
      used.add(candidate);
      s.params = { ...(s.params || {}), name: candidate };
    }
  );
  return next;
}

/**
 * @param {import("./recipe.js").RecipeAst} fwd
 * @param {import("./recipe.js").RecipeAst} rev
 * @returns {string}
 */
function joinRecipes(fwd, rev) {
  const outs = collectOutLabels(fwd);
  const revSafe = dedupeReverseOuts(rev, outs);
  return serializeRecipe({
    chains: [...recipeChains(fwd), ...recipeChains(revSafe)],
    steps: [],
    source: "",
  });
}

/**
 * Stitch a companion preset pair into one multi-chain recipe.
 * @param {ToolkitPreset} forwardPreset
 * @param {ToolkitPreset} reversePreset
 * @returns {StitchResult}
 */
export function stitchPresetPair(forwardPreset, reversePreset) {
  const pairId =
    forwardPreset?.pair || reversePreset?.pair || forwardPreset?.id || "bridge";
  const defaultBridge = bridgeSlotName(pairId);

  const fwdSrc = migrateRecipe(String(forwardPreset?.recipe || "")).recipe;
  const revSrc = migrateRecipe(String(reversePreset?.recipe || "")).recipe;
  const fwdCanon = canonicalizeRecipe(fwdSrc);
  const revCanon = canonicalizeRecipe(revSrc);
  /** @type {string[]} */
  const errors = [];
  if (fwdCanon.errors?.length) {
    errors.push(...fwdCanon.errors.map((e) => e.message));
  }
  if (revCanon.errors?.length) {
    errors.push(...revCanon.errors.map((e) => e.message));
  }
  if (!fwdCanon.ast || !revCanon.ast || errors.length) {
    return {
      recipe: [fwdSrc, revSrc].filter(Boolean).join("\n\n"),
      mode: "as-is",
      bridge: null,
      errors,
      forward: forwardPreset,
      reverse: reversePreset,
    };
  }

  const outs = collectOutLabels(fwdCanon.ast);
  const consumed = collectConsumedSlots(revCanon.ast);
  const overlap = [...outs].filter((o) => consumed.has(o));
  if (overlap.length) {
    return {
      recipe: joinRecipes(fwdCanon.ast, revCanon.ast),
      mode: "as-is",
      bridge: overlap[0],
      forward: forwardPreset,
      reverse: reversePreset,
    };
  }

  const first = firstSourceName(revCanon.ast);
  if (first === "shares" || first === "gpg.decrypt") {
    return {
      recipe: joinRecipes(fwdCanon.ast, revCanon.ast),
      mode: "inputs",
      bridge: null,
      forward: forwardPreset,
      reverse: reversePreset,
    };
  }

  if (first === "input" || first === "paste" || first === "cat") {
    let fwdAst = fwdCanon.ast;
    let bridge = lastChainFinalOut(fwdAst);
    if (!bridge) {
      bridge = defaultBridge;
      fwdAst = appendOutToLastChain(fwdAst, bridge);
    }
    const revAst = replaceFirstSourceWithIn(revCanon.ast, bridge);
    return {
      recipe: joinRecipes(fwdAst, revAst),
      mode: "slot",
      bridge,
      forward: forwardPreset,
      reverse: reversePreset,
    };
  }

  return {
    recipe: joinRecipes(fwdCanon.ast, revCanon.ast),
    mode: "as-is",
    bridge: null,
    forward: forwardPreset,
    reverse: reversePreset,
  };
}
