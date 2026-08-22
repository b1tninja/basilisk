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
  canonicalCellSources,
  canonicalNotebookSource,
  compileRecipe,
  migrateRecipe,
  publishedSlots,
} from "./recipe.js";
import { chainsNumberedLikeNotebook, planRun, planChains } from "./plan.js";
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
 * ## The manifest states identity twice, and the two used to disagree
 *
 * `buildRunManifest` digests the notebook once whole (`recipeDigest`) and once
 * per cell (`cells[].recipeDigest`). The cells go through `serializeRecipe`, so
 * a doubled space between two steps changes nothing. The whole used to be the
 * *source text verbatim*, so the same doubled space changed everything: three
 * matching cell digests underneath a notebook digest that said two peers were
 * holding two different notebooks, and `handoff.js` refuses on the coarse one.
 * The fine-grained evidence said the offer was fine and the coarse claim threw
 * it out — one document contradicting itself, which is a defect whether or not
 * anything crashes.
 *
 * So the notebook is digested in **the cells' own canonical form**:
 * `canonicalNotebookSource` is `canonicalCellSources` joined by the blank line
 * between cells, and `cells[].recipe` is `canonicalCellSources`' own entries.
 * They are the same strings, so the two levels cannot disagree — not "agree
 * today", cannot. Whatever a cell digest ignores the notebook digest ignores;
 * whatever a cell digest notices the notebook digest notices.
 *
 * **This does not reopen the rule above.** The reason `source` is not simply
 * replaced by `serializeRecipe(chains)` is that serializing *drops* blank cells
 * and renumbers everything after one. `canonicalCellSources` emits one entry per
 * chain and spells a blank cell `""`, so the list that goes in comes out
 * one-for-one: `cells[i].index === i` for every notebook, and no index moves.
 * Cell count and cell order survive canonicalisation; only the spelling inside a
 * cell is normalised, which is what the per-cell digests already did.
 *
 * `recipeSource` carries the canonical text rather than the raw text, because
 * `buildRunManifest` sets `recipeDigest = digestText(recipeSource)` and a
 * manifest whose stated source does not hash to its stated digest would be the
 * same self-contradiction one level further down.
 *
 * A notebook that does not parse has no chains to canonicalise. It keeps the
 * migrated source verbatim — the honest answer, since nothing was read — rather
 * than being recorded as a manifest for an empty notebook.
 *
 * ## `notebook`, for the cells the text cannot spell
 *
 * The rule above — never a re-serialisation, because serialising drops blank
 * cells — protects this function from *doing* the lossy thing. It does not
 * protect it from being *handed* the result: `useNotebook` derives `source` as
 * `serializeRecipe(chains)`, so the blanks are already gone by the time this
 * sees a string, and every cell below one is named one lower than the notebook
 * shows it. Recipe text has no spelling for an empty cell, so no amount of care
 * with the string can recover them.
 *
 * `notebook` is the caller's own cell array, blanks included, and the parsed
 * chains are renumbered against it. Optional because the four callers that have
 * only a string are still right about everything except a blank cell, and
 * `currentRunManifest` set this precedent with `ctx.chains`.
 *
 * @param {{ source: string, me: string, roster: Record<string, string>,
 *   title?: string,
 *   notebook?: import("./recipe.js").RecipeChain[]|null }} spec
 * @returns {Promise<HandoffContext>}
 */
export async function handoffContext({
  source,
  me,
  roster,
  title = "notebook",
  notebook = null,
}) {
  const parsed = compileRecipe(source);
  const chains = chainsNumberedLikeNotebook(planChains(parsed), notebook);
  // One chain list, used for the plan and the manifest both. Building the plan
  // from `parsed` and the manifest from `chains` is exactly the split this is
  // here to close — `offer.cell` is checked against the manifest's positions
  // and produced from the plan's.
  const compiled = {
    ...parsed,
    ast: { ...(parsed.ast || {}), chains },
  };
  const plan = planRun(compiled, { me, roster });
  const recipes = canonicalCellSources(chains);
  const manifest = await buildRunManifest({
    title,
    recipeSource: chains.length
      ? canonicalNotebookSource(chains)
      : migrateRecipe(source).recipe,
    peers: roster,
    cells: chains.map((chain, i) => ({
      index: i,
      peer: String(chain.peer || ""),
      publish: publishedSlots(chain).length > 0,
      recipe: recipes[i],
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
