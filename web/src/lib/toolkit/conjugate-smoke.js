/**
 * Vitest smoke helpers for companion presets / self-contained roundtrips.
 * Not CAST — full runRecipe / kernel paths only.
 */

import { runRecipe } from "./engine.js";
import { createKernel } from "./kernel.js";
import {
  listPresetPairs,
  stitchPresetPair,
} from "./conjugate-stitch.js";
import {
  PRESETS,
  canonicalizeRecipe,
  compileRecipe,
  migrateRecipe,
  recipeChains,
} from "./recipe.js";
import { validateShareMnemonic } from "../slip39/blip39.js";

/**
 * @typedef {typeof PRESETS[number]} ToolkitPreset
 */

/** Presets that already encode encrypt⇄decrypt or sign⇄verify across chains. */
export const SELF_ROUNDTRIP_IDS = [
  "rsa-oaep-roundtrip",
  "aes-cbc-roundtrip",
  "aes-ctr-roundtrip",
  "gpg-sign-verify",
  "hmac-sign-verify",
];

/**
 * @param {ToolkitPreset[]} [presets]
 * @returns {{ id: string, forward: ToolkitPreset, reverse: ToolkitPreset }[]}
 */
export function listPresetPairsForSmoke(presets = PRESETS) {
  return listPresetPairs(presets);
}

/**
 * @param {ToolkitPreset[]} [presets]
 * @returns {ToolkitPreset[]}
 */
export function listSelfRoundtrips(presets = PRESETS) {
  const allow = new Set(SELF_ROUNDTRIP_IDS);
  return presets.filter((p) => allow.has(p.id));
}

/**
 * @param {string} source
 */
function compileOk(source) {
  const migrated = migrateRecipe(String(source || "")).recipe;
  const { ast, validation } = compileRecipe(migrated);
  if (!ast || !validation.ok) {
    const msg = (validation.errors || [])
      .map((e) => e.message)
      .join(" · ");
    throw new Error(msg || "compile failed");
  }
  return ast;
}

/**
 * Run stitched slot-bridge pair via kernel (shared @slots).
 * @param {ToolkitPreset} forward
 * @param {ToolkitPreset} reverse
 * @param {import("./engine.js").RuntimeBindings} [bindings]
 * @returns {Promise<{ stitch: import("./conjugate-stitch.js").StitchResult, cellArts: import("./engine.js").ToolkitArtifact[][] }>}
 */
export async function runSlotBridgePair(forward, reverse, bindings = {}) {
  const stitch = stitchPresetPair(forward, reverse);
  if (stitch.mode === "inputs") {
    throw new Error("runSlotBridgePair: pair uses inputs bridge, not slots");
  }
  const ast = compileOk(stitch.recipe);
  const kernel = createKernel();
  try {
    const chains = recipeChains(ast);
    const cellArts = await kernel.runAll(chains, bindings);
    /** @type {Record<string, string>} */
    const slotTexts = {};
    const reg = kernel.slots;
    for (const key of reg.labels()) {
      const ref = String(key).startsWith("@") ? String(key) : `@${key}`;
      try {
        const v = reg.resolve(ref);
        if (v?.type === "text") slotTexts[ref] = String(v.data);
      } catch {
        /* skip */
      }
    }
    return { stitch, cellArts, slots: slotTexts };
  } finally {
    kernel.destroy();
  }
}

/**
 * Extract BLIP39 mnemonic strings from share tiles.
 * @param {import("./engine.js").ToolkitArtifact[]} arts
 * @returns {string[]}
 */
export function extractShareMnemonics(arts) {
  /** @type {string[]} */
  const out = [];
  for (const a of arts || []) {
    const text = String(a.content || "").trim();
    if (!text) continue;
    if (a.shareIndex || a.role === "share" || /^Share\s+\d+/i.test(a.label || "")) {
      if (validateShareMnemonic(text).ok) out.push(text);
      continue;
    }
    if (validateShareMnemonic(text).ok) out.push(text);
  }
  return out;
}

/**
 * Extract first PEM private/public block from artifacts.
 * @param {import("./engine.js").ToolkitArtifact[]} arts
 * @param {"private"|"public"|"any"} [which]
 * @returns {string|null}
 */
export function extractPem(arts, which = "any") {
  for (const a of arts || []) {
    const t = String(a.content || "");
    if (which !== "public" && /BEGIN PRIVATE KEY/.test(t)) return t;
    if (which !== "private" && /BEGIN PUBLIC KEY/.test(t)) return t;
  }
  return null;
}

/**
 * @param {import("./engine.js").ToolkitArtifact[]} arts
 * @returns {string|null}
 */
export function extractEnvelopeAsc(arts) {
  for (const a of arts || []) {
    const t = String(a.content || "");
    const name = String(a.filename || a.label || "");
    if (
      /BEGIN PGP MESSAGE/.test(t) &&
      (/envelope/i.test(name) || a.role === "envelope")
    ) {
      return t;
    }
  }
  for (const a of arts || []) {
    const t = String(a.content || "");
    if (/BEGIN PGP MESSAGE/.test(t)) return t;
  }
  return null;
}

/**
 * Forward runRecipe → feed reverse via inputs (shares / envelope / text).
 * @param {ToolkitPreset} forward
 * @param {ToolkitPreset} reverse
 * @param {{
 *   pickShares?: (mnemonics: string[]) => string[],
 *   bindings?: import("./engine.js").RuntimeBindings,
 * }} [opts]
 */
export async function runInputsBridgePair(forward, reverse, opts = {}) {
  const stitch = stitchPresetPair(forward, reverse);
  const fwdAst = compileOk(forward.recipe);
  const revAst = compileOk(reverse.recipe);
  const fwdArts = await runRecipe(fwdAst, opts.bindings || {});
  const mnemonics = extractShareMnemonics(fwdArts);
  const pick =
    opts.pickShares ||
    ((m) => (m.length >= 2 ? [m[0], m[m.length - 1]] : m));
  const chosen = pick(mnemonics);
  const envelope = extractEnvelopeAsc(fwdArts);
  /** @type {import("./engine.js").RuntimeBindings} */
  const bindings = {
    ...(opts.bindings || {}),
    inputs: {
      ...(opts.bindings?.inputs || {}),
      shares: {
        mnemonics: chosen,
        envelopeArmored: envelope || undefined,
        ...(opts.bindings?.inputs?.shares || {}),
      },
      envelope: envelope
        ? { armored: envelope }
        : opts.bindings?.inputs?.envelope,
    },
  };
  const revArts = await runRecipe(revAst, bindings);
  return { stitch, fwdArts, revArts, mnemonics: chosen, envelope };
}

/**
 * Compile-only check for a preset (migrate + validate).
 * @param {ToolkitPreset} preset
 */
export function assertPresetCompiles(preset) {
  const src = migrateRecipe(String(preset.recipe || "")).recipe;
  const { ast, errors } = canonicalizeRecipe(src);
  if (errors.length || !ast) {
    throw new Error(
      `${preset.id}: ${errors.map((e) => e.message).join(" · ") || "parse failed"}`
    );
  }
  const { validation } = compileRecipe(src);
  if (!validation.ok) {
    throw new Error(
      `${preset.id}: ${validation.errors.map((e) => e.message).join(" · ")}`
    );
  }
  return validation;
}

/**
 * @param {import("./engine.js").ToolkitArtifact[]} arts
 * @param {RegExp|string} re
 * @returns {string|null}
 */
export function findArtifactContent(arts, re) {
  const rx = typeof re === "string" ? new RegExp(re) : re;
  for (const a of arts || []) {
    const t = String(a.content || "");
    if (rx.test(t)) return t;
  }
  return null;
}
