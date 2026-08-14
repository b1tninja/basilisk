/**
 * The four handoff calls, with the three things they all need worked out once.
 *
 * `handoff.js` is deliberately decision-free: `buildOfferFor`, `acceptHandoffOffer`,
 * `buildResultFor` and `acceptCellResult` each take a plan, the compiled notebook
 * that plan was made against, and the run's manifest, and derive everything else.
 * That is the right shape for the unit, and the wrong shape to call four times
 * from a shell — the three would be rebuilt at each call site, and the moment two
 * of them disagreed the offer would describe a notebook the accept did not.
 *
 * So this derives them once from the notebook's own text and hands the same
 * triple to every step. Nothing here decides anything either: it refuses where
 * `handoff.js` refuses, and it registers nothing.
 *
 * ## What it does not do
 *
 * It does not accept, and it cannot. `acceptHandoffOffer` and `acceptCellResult`
 * return *bindings a caller would register*, and registering them is the consent
 * — `approval-gate.js`'s rule that grants are minted by a human clicking, never
 * by a param, reaching one layer further out. These wrappers return the same
 * verdicts unchanged, and a shell puts them into a registry because somebody
 * pressed something.
 *
 * @module lib/toolkit/handoff-shell
 */

import {
  compileRecipe,
  migrateRecipe,
  publishedSlots,
  serializeRecipe,
} from "./recipe.js";
import { planRun, planChains } from "./plan.js";
import { buildRunManifest } from "./manifest.js";
import {
  buildOfferFor,
  acceptHandoffOffer,
  buildResultFor,
  acceptCellResult,
  offerToJson,
  parseHandoffOffer,
} from "./handoff.js";

/**
 * @typedef {object} HandoffContext
 * @property {import("./plan.js").RunPlan} plan
 * @property {*} compiled
 * @property {import("./manifest.js").RunManifest} manifest
 */

/**
 * Everything the four calls share, from the notebook's own text.
 *
 * **`source`, never a re-serialization of the chains.** Serializing drops blank
 * cells, so every cell after the first blank shifts by one — and here that would
 * mean an offer naming cell 4 while the peer's plan calls the same cell 3. The
 * manifest, the plan and the editor all number the same way precisely because
 * they all read this string.
 *
 * @param {{ source: string, me: string, roster: Record<string, string>,
 *   title?: string }} spec
 * @returns {Promise<HandoffContext>}
 */
export async function handoffContext({ source, me, roster, title = "notebook" }) {
  const compiled = compileRecipe(source);
  const plan = planRun(compiled, { me, roster });
  const chains = planChains(compiled);
  const manifest = await buildRunManifest({
    title,
    recipeSource: migrateRecipe(source).recipe,
    peers: roster,
    cells: chains.map((chain, i) => ({
      index: i,
      peer: String(chain.peer || ""),
      publish: publishedSlots(chain).length > 0,
      recipe: serializeRecipe({ chains: [chain] }),
    })),
  });
  return { plan, compiled, manifest };
}

/**
 * The offer for one cell this run left to somebody else.
 *
 * `skipped` is the gate's own report, not a cell index — `placement.js` produces
 * it and this passes it through, because a shell that rebuilt the reason a cell
 * was skipped would be deciding placement a second time.
 *
 * @param {HandoffContext} ctx
 * @param {import("./placement.js").SkippedCell} skipped
 * @param {(label: string) => import("./engine.js").PipelineValue|null} readSlot
 * @returns {Promise<{ ok: true, json: string, peer: string }
 *   | { ok: false, refusals: import("./handoff.js").HandoffRefusal[] }>}
 */
export async function offerForSkipped(ctx, skipped, readSlot) {
  const built = await buildOfferFor({
    plan: ctx.plan,
    compiled: ctx.compiled,
    manifest: ctx.manifest,
    skipped,
    readSlot,
  });
  if (!built.ok || !built.offer) return { ok: false, refusals: built.refusals };
  return { ok: true, json: offerToJson(built.offer), peer: skipped.waitingOn };
}

/**
 * Check an offer that arrived, and say what registering it would mean.
 *
 * Returns `handoff.js`'s verdict untouched. Nothing is registered here — see the
 * module note; the caller registers because a person clicked.
 *
 * @param {HandoffContext} ctx
 * @param {import("./handoff.js").HandoffOffer|string} offer  parsed, or its JSON
 * @param {(label: string) => boolean} hasSlot
 */
export async function reviewOffer(ctx, offer, hasSlot) {
  const parsed = typeof offer === "string" ? parseHandoffOffer(offer) : offer;
  return acceptHandoffOffer(parsed, {
    plan: ctx.plan,
    compiled: ctx.compiled,
    manifest: ctx.manifest,
    hasSlot,
  });
}

/**
 * What goes back after the accepted cell has run.
 *
 * @param {HandoffContext} ctx
 * @param {number} cell
 * @param {(label: string) => import("./engine.js").PipelineValue|null} readSlot
 */
export async function resultForCell(ctx, cell, readSlot) {
  return buildResultFor({
    plan: ctx.plan,
    compiled: ctx.compiled,
    manifest: ctx.manifest,
    cell,
    readSlot,
  });
}

/**
 * Check a result that came back, and say what registering it would mean.
 *
 * The same verdict-not-action shape as `reviewOffer`, and the end where it
 * matters more: a result that resumed the run on a peer's say-so would continue
 * the origin's own machine on values nobody looked at.
 *
 * `by` is the peer *label* the signature resolved to, never a fingerprint —
 * `handoff.js` checks the claim against the plan, and the plan speaks in
 * labels. `offered` is what this origin actually handed out, so a result for a
 * cell nobody offered is refused rather than merely unexpected.
 *
 * @param {HandoffContext} ctx
 * @param {import("./handoff.js").CellResult} result  already parsed
 * @param {{ by: string, offered: { manifest: string, cell: number, to: string }[],
 *   hasSlot: (label: string) => boolean }} who
 */
export async function reviewResult(ctx, result, who) {
  return acceptCellResult(result, {
    plan: ctx.plan,
    compiled: ctx.compiled,
    manifest: ctx.manifest,
    by: who.by,
    offered: who.offered,
    hasSlot: who.hasSlot,
  });
}
