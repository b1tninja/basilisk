/**
 * The whole handoff, driven the way a shell drives it.
 *
 * `handoff-offer.test.js` and `handoff-result.test.js` pin each half against
 * `handoff.js` directly. This one goes the other way: it uses only
 * `handoff-shell.js`, which is what the app calls, and walks one placed
 * notebook from mara's stopped run through okafor's machine and back until
 * mara's run completes.
 *
 * That is the claim worth a test of its own. Each half worked in isolation for
 * a long time while the loop did not exist at all — the four functions had no
 * caller and were dropped from the bundle — so "both halves pass" was never the
 * same statement as "a cell placed on a peer runs there and comes back".
 *
 * Nothing is registered by the module under test. Where this test registers a
 * binding it does so itself, in one line, standing in for the click that would
 * do it in the app — which is the consent rule `handoff.js` states and the
 * reason there is no `accept()` to call.
 */
import { describe, expect, it } from "vitest";
import {
  handoffContext,
  offerForSkipped,
  reviewOffer,
  resultForCell,
  reviewResult,
} from "../lib/toolkit/handoff-shell.js";
import { parseHandoffOffer, summarizeHandoff } from "../lib/toolkit/handoff.js";
import { manifestDigest } from "../lib/toolkit/manifest.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { compileRecipe, migrateRecipe } from "../lib/toolkit/recipe.js";

const FPR_M = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_O = "91C7E6D5C4B3A29180716253443526170819AABB";
const ROSTER = { mara: FPR_M, okafor: FPR_O };

/**
 * mara seeds the room, okafor transforms it, mara reads the answer.
 *
 * The third cell is what makes a *result* exist at all: `buildResultFor`
 * refuses a cell whose output nobody else reads — "a result carries values,
 * and this one would carry none" — so a two-cell notebook proves the offer and
 * nothing about the way back. okafor publishes for the same reason mara does:
 * without it the value has no permission to leave the machine that made it.
 */
const HANDED = `@mara
bytes deadbeef | encode hex | out $seed | publish

@okafor
in $seed | decode hex | encode base64 | out $b64 | publish

@mara
in $b64 | decode base64 | encode hex | out $final
`;

/**
 * Run a notebook under a plan, collecting what the gate declined.
 *
 * The `catch` is not laziness: a placed notebook that reaches a cell whose
 * input lives on another machine *stops*, by design, and the values it wrote
 * before stopping are exactly what the offer carries.
 */
async function runPlaced(ctx, registry) {
  /** @type {import("../lib/toolkit/placement.js").SkippedCell[]} */
  const skipped = [];
  await runRecipe(
    compileRecipe(migrateRecipe(HANDED).recipe).ast,
    {},
    {
      slotRegistry: registry,
      // As the kernel does. Without it a second run re-registers a slot the
      // first one wrote and throws at cell 0, which looks exactly like the
      // gate having skipped nothing.
      allowReplaceSlots: true,
      placement: { plan: ctx.plan, onSkip: (s) => skipped.push(s) },
    }
  ).catch(() => {});
  return skipped;
}

const readFrom = (registry) => (label) =>
  registry.has(label) ? registry.resolve(label) : null;

describe("a placed cell runs on its peer and the value comes home", () => {
  it("completes the loop end to end", async () => {
    // ── mara: runs her half, and the gate declines okafor's ──────────────
    const mara = await handoffContext({ source: HANDED, me: "mara", roster: ROSTER });
    const maraSlots = createSlotRegistry();
    const skipped = await runPlaced(mara, maraSlots);

    expect(skipped).toHaveLength(1);
    expect(skipped[0]).toMatchObject({ cell: 1, waitingOn: "okafor" });
    // Her own cell ran; the one she cannot perform did not.
    expect(maraSlots.has("seed")).toBe(true);
    expect(maraSlots.has("b64")).toBe(false);

    const offer = await offerForSkipped(mara, skipped[0], readFrom(maraSlots));
    expect(offer.ok, JSON.stringify(offer)).toBe(true);
    expect(offer.peer).toBe("okafor");

    // ── okafor: reviews what arrived, and registers because a person would ──
    const okafor = await handoffContext({ source: HANDED, me: "okafor", roster: ROSTER });
    const okaforSlots = createSlotRegistry();
    const verdict = await reviewOffer(okafor, offer.json, (l) => okaforSlots.has(l));
    expect(verdict.ok, summarizeHandoff(verdict)).toBe(true);

    // The click. `reviewOffer` returned bindings and registered none of them.
    for (const b of verdict.bindings) okaforSlots.register(b.label, b.value, {});
    expect(okaforSlots.has("seed")).toBe(true);

    // ── okafor: runs the cell that is his, now that its input is here ────
    const okaforSkipped = await runPlaced(okafor, okaforSlots);
    // Both of mara's, and neither of them his — the gate is symmetric.
    expect(okaforSkipped.map((s) => s.cell)).toEqual([0, 2]);
    expect(okaforSlots.has("b64")).toBe(true);

    const back = await resultForCell(okafor, 1, readFrom(okaforSlots));
    expect(back.ok, JSON.stringify(back.refusals)).toBe(true);

    // ── mara: reviews the answer, registers it, and her run completes ────
    const answer = await reviewResult(mara, back.result, {
      by: "okafor",
      offered: [{ manifest: await manifestDigest(mara.manifest), cell: 1, to: "okafor" }],
      hasSlot: (l) => maraSlots.has(l),
    });
    expect(answer.ok, summarizeHandoff(answer)).toBe(true);

    for (const b of answer.bindings) maraSlots.register(b.label, b.value, {});
    expect(maraSlots.has("b64")).toBe(true);

    // The gate asks the registry first, so the cell that stopped the run now
    // has its value and the stop simply stops happening — with no edit to
    // `placement.js`, which is the seam the arc was designed around.
    const again = await runPlaced(mara, maraSlots);
    expect(again.map((s) => s.cell)).toEqual([1]);
    expect(maraSlots.resolve("b64")).toBeTruthy();
  });

  it("refuses an offer whose notebook is not the one this peer is holding", async () => {
    // The manifest is what binds an offer to a run. A peer editing their copy
    // is no longer running the notebook the offer describes, and accepting
    // would register a value computed against different text.
    const mara = await handoffContext({ source: HANDED, me: "mara", roster: ROSTER });
    const maraSlots = createSlotRegistry();
    const skipped = await runPlaced(mara, maraSlots);
    const offer = await offerForSkipped(mara, skipped[0], readFrom(maraSlots));
    expect(offer.ok).toBe(true);

    const edited = `${HANDED}\n@okafor\nbytes cafe | out $extra\n`;
    const drifted = await handoffContext({ source: edited, me: "okafor", roster: ROSTER });
    const verdict = await reviewOffer(drifted, offer.json, () => false);
    expect(verdict.ok).toBe(false);
  });

  it("derives one context that every step agrees on", async () => {
    // The reason this module exists: four call sites each rebuilding the plan,
    // the compile and the manifest is four chances for two of them to differ,
    // and the symptom would be an offer describing a notebook the accept does
    // not recognise.
    const a = await handoffContext({ source: HANDED, me: "mara", roster: ROSTER });
    const b = await handoffContext({ source: HANDED, me: "mara", roster: ROSTER });
    expect(await manifestDigest(a.manifest)).toBe(await manifestDigest(b.manifest));
    expect(a.plan.cells.length).toBe(b.plan.cells.length);
    expect(parseHandoffOffer.length).toBeGreaterThan(0); // the parser is real
  });
});
