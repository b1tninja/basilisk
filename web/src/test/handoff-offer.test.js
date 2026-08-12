/**
 * A placed cell becomes something its assignee can accept.
 *
 * `run-gate.test.js` ends where this begins: a cell placed on somebody else is
 * not performed here, and a later cell that needed it stops the run. That file
 * also wrote, before this one existed, the test that says how the value gets
 * there — *"runs the moment the value is actually here"*. Acceptance delivers
 * through that seam and through no other, which is why nothing in `placement.js`
 * or `engine.js` changed for this unit.
 *
 * What the cases below are for, in the order they matter:
 *
 * 1. **The round trip.** mara runs her cell, hands okafor his, okafor accepts,
 *    and okafor's run — placed, gated, unmodified — produces the artifact that
 *    mara's stopped run could not. The control is the same run without the
 *    bindings: it must stop.
 * 2. **The refusals**, each written so it fires: an offer from a peer whose key
 *    is not confirmed; an offer naming a cell the recipient's own plan does not
 *    give them; an offer that would carry a private value; an offer against a
 *    manifest digest the recipient has never seen; an offer whose cell index
 *    could mean two things.
 * 3. **Consent.** An arriving offer registers nothing. There is no path from
 *    `runRecipe`, from the session, or from any parameter to a bound slot — only
 *    from a caller that asked for the bindings and put them in itself.
 */
import { describe, expect, it } from "vitest";
import {
  HANDOFF_KIND,
  HANDOFF_VERSION,
  acceptHandoffOffer,
  buildOfferFor,
  offerAwaiting,
  offerToJson,
  parseHandoffOffer,
  summarizeHandoff,
} from "../lib/toolkit/handoff.js";
import { planChains, planRun } from "../lib/toolkit/plan.js";
import { placementGate } from "../lib/toolkit/placement.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { buildRunManifest, manifestDigest } from "../lib/toolkit/manifest.js";
import { compileRecipe, migrateRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { parseRecipeSource } from "../lib/toolkit/recipe-parse.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";

const FPR_M = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_O = "91C7E6D5C4B3A29180716253443526170819AABB";
const ROSTER = { mara: FPR_M, okafor: FPR_O };

/** mara writes a value into the room; okafor's cell reads it. */
const HANDED = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor
in $seed | decode hex | encode base64 | out $b64
`;

/** @param {string} src */
const compile = (src) => compileRecipe(migrateRecipe(src).recipe);

/**
 * A manifest for a notebook, cells numbered the way a plan numbers them.
 *
 * `planChains` is the numbering — the same function the plan, the gate's
 * bookkeeping and the offer all count with — and `serializeRecipe` is the cell
 * spelling `appendRunLog` and `run.manifest` both record.
 * @param {string} src
 * @param {Record<string, string>} [peers]
 */
function manifestFor(src, peers = ROSTER) {
  const chains = planChains(compile(src));
  return buildRunManifest({
    title: "handoff",
    recipeSource: migrateRecipe(src).recipe,
    peers,
    cells: chains.map((chain, i) => ({
      index: i,
      peer: String(chain.peer || ""),
      publish: !!chain.publish,
      recipe: serializeRecipe({ chains: [chain] }),
    })),
  });
}

/** @param {string} src @param {string} me */
function planFor(src, me) {
  return planRun(compile(src), { me, roster: ROSTER });
}

/**
 * mara runs her half of `HANDED` and builds the offer the gate's skip produced.
 * @param {string} [src]
 */
async function offerFrom(src = HANDED) {
  const compiled = compile(src);
  const plan = planFor(src, "mara");
  /** @type {import("../lib/toolkit/placement.js").SkippedCell[]} */
  const skipped = [];
  const registry = createSlotRegistry();
  await runRecipe(
    compiled.ast,
    {},
    { slotRegistry: registry, placement: { plan, onSkip: (s) => skipped.push(s) } }
  ).catch(() => {
    /* a notebook that stops on a withheld input still produced what it produced */
  });
  const manifest = await manifestFor(src);
  const built = await buildOfferFor({
    plan,
    compiled,
    manifest,
    skipped: skipped[0],
    readSlot: (label) => (registry.has(label) ? registry.resolve(label) : null),
  });
  return { built, skipped, registry, manifest, plan };
}

/* ───────────────────────────── the round trip ───────────────────────────── */

describe("a placed cell becomes something its assignee can accept", () => {
  it("stops on mara's side, which is the state an offer exists to leave", async () => {
    const { skipped, built } = await offerFrom();
    expect(skipped).toHaveLength(1);
    expect(skipped[0]).toMatchObject({ cell: 1, waitingOn: "okafor", produces: ["b64"] });
    expect(built.ok, summarizeHandoff(built)).toBe(true);
    expect(built.offer).toMatchObject({
      v: HANDOFF_VERSION,
      kind: HANDOFF_KIND,
      cell: 1,
      needs: [{ label: "seed", type: "text", data: "deadbeef" }],
    });
    // Everything the offerer is left with, said in one line — and it does not
    // claim to know whether okafor said no or never looked.
    const line = offerAwaiting({ cell: 1, peer: "okafor", sent: 1, slots: ["seed"] });
    expect(line).toContain("cell 1 offered to `@okafor`");
    expect(line).toContain("Declined and unread look the same from here");
  });

  it("does not run on okafor's side either, until the offer is accepted", async () => {
    // The control. okafor has the same notebook, the same plan, the same gate —
    // and no value, because mara made it. This is the run the offer repairs.
    const err = await runRecipe(
      compile(HANDED).ast,
      {},
      { slotRegistry: createSlotRegistry(), placement: { plan: planFor(HANDED, "okafor") } }
    ).then(
      () => null,
      (e) => e
    );
    expect(String(err?.message)).toContain("$seed");
    expect(err.basiliskWithheld).toEqual({ cell: 1, slot: "seed", from: 0, peer: "mara" });
  });

  it("runs on okafor's side once the bindings are registered, and no gate changed", async () => {
    const { built } = await offerFrom();
    const wire = offerToJson(built.offer);
    const offer = parseHandoffOffer(wire);

    const compiled = compile(HANDED);
    const plan = planFor(HANDED, "okafor");
    const registry = createSlotRegistry();
    const verdict = await acceptHandoffOffer(offer, {
      plan,
      compiled,
      manifest: await manifestFor(HANDED),
      hasSlot: (l) => registry.has(l),
    });
    expect(verdict.ok, summarizeHandoff(verdict)).toBe(true);
    expect(verdict.bindings.map((b) => b.label)).toEqual(["seed"]);
    expect(summarizeHandoff(verdict)).toContain("every one of them public");

    // Accepting is this line, and this line is a person clicking. Nothing above
    // it touched the registry.
    expect(registry.has("seed")).toBe(false);
    for (const b of verdict.bindings) registry.register(`$${b.label}`, b.value);

    const arts = await runRecipe(compiled.ast, {}, { slotRegistry: registry, placement: { plan } });
    expect(registry.has("b64")).toBe(true);
    expect(arts.some((a) => String(a.content).includes("3q2+7w=="))).toBe(true);
  });

  it("carries bytes as bytes, not as a string that happens to print the same", async () => {
    const src = `@mara publish
bytes deadbeef | out $raw

@okafor
in $raw | encode base64 | out $b64
`;
    const { built } = await offerFrom(src);
    expect(built.ok, summarizeHandoff(built)).toBe(true);
    expect(built.offer.needs).toEqual([{ label: "raw", type: "bytes", data: "3q2+7w==" }]);

    const compiled = compile(src);
    const plan = planFor(src, "okafor");
    const verdict = await acceptHandoffOffer(parseHandoffOffer(offerToJson(built.offer)), {
      plan,
      compiled,
      manifest: await manifestFor(src),
    });
    expect(verdict.ok, summarizeHandoff(verdict)).toBe(true);
    expect(verdict.bindings[0].value.data).toBeInstanceOf(Uint8Array);
    expect([...verdict.bindings[0].value.data]).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });
});

/* ──────────────────────── which cell, and only which cell ───────────────── */

describe("a cell index means one thing or the offer means nothing", () => {
  it("binds the index to the cell's text on both sides", async () => {
    const { built } = await offerFrom();
    const manifest = await manifestFor(HANDED);
    expect(built.offer.cellDigest).toBe(manifest.cells[1].recipeDigest);
    expect(built.offer.cell).toBe(1);
  });

  it("selects nothing when the index is off by one", async () => {
    const { built } = await offerFrom();
    // The index a caller would use if they counted chains instead of cells, or
    // simply got it wrong. Without the digest this would select *a* cell.
    const bent = { ...built.offer, cell: 0 };
    const verdict = await acceptHandoffOffer(bent, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("cell-mismatch");
    expect(verdict.refusals[0].message).toContain("makes a wrong index select nothing");
  });

  it("refuses a manifest that left a notebook's blank cell out of its count", async () => {
    // The manifest v1 built: every cell that had text in it, renumbered. The
    // notebook has three cells and the document describes two, so "cell 2"
    // means mara's cell in one and nothing in the other — and an offer is
    // refused outright rather than resolved to the likelier reading. The blank
    // chain is built rather than parsed, because recipe text has no spelling
    // for an empty cell.
    const chains = /** @type {*} */ (compile(HANDED).ast).chains;
    const blanked = {
      chains: [chains[0], { steps: [] }, chains[1]],
      steps: chains[0].steps,
      source: "",
    };
    const filtered = await buildRunManifest({
      recipeSource: migrateRecipe(HANDED).recipe,
      peers: ROSTER,
      cells: blanked.chains
        .filter((c) => c?.steps?.length)
        .map((chain, i) => ({
          index: i,
          peer: String(chain.peer || ""),
          publish: !!chain.publish,
          recipe: serializeRecipe({ chains: [chain] }),
        })),
    });

    const built = await buildOfferFor({
      plan: planRun(blanked, { me: "mara", roster: ROSTER }),
      compiled: blanked,
      manifest: filtered,
      skipped: { cell: 2, waitingOn: "okafor", runsOn: ["okafor"], why: "", produces: ["b64"] },
      readSlot: () => ({ type: "text", data: "deadbeef", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("different-notebook");
    expect(built.refusals[0].message).toContain("not the same notebook");
  });

  it("refuses a manifest whose cell calls itself a different number", async () => {
    // The check that survives one numbering: a manifest arrives from a peer,
    // and a row whose `index` is not its own position was not built by the rule
    // this build states. It cannot happen to a document `run.manifest` wrote —
    // which is why it is the *document* that is refused here rather than the
    // notebook being blamed for having a blank cell in it.
    const honest = await manifestFor(HANDED);
    const bent = {
      ...honest,
      cells: [honest.cells[0], { ...honest.cells[1], index: 2 }],
    };
    const verdict = await acceptHandoffOffer(
      { ...(await offerFrom()).built.offer, manifest: await manifestDigest(bent) },
      { plan: planFor(HANDED, "okafor"), compiled: compile(HANDED), manifest: bent }
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("ambiguous-index");
    expect(verdict.refusals[0].message).toContain("calls itself cell 2");
  });

  it("refuses a manifest for a different notebook outright", async () => {
    const { built } = await offerFrom();
    const other = await manifestFor(`@mara publish
bytes 00 | encode hex | out $seed
`);
    const verdict = await acceptHandoffOffer(built.offer, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: other,
    });
    expect(verdict.ok).toBe(false);
    // The digest does not match either, so the manifest is not even reached as
    // "the one this offer is about".
    expect(verdict.refusals[0].reason).toBe("unknown-manifest");
  });
});

/* ─────────────────────────────── the refusals ───────────────────────────── */

describe("an offer against a manifest this peer has not seen is refused", () => {
  it("says which of the two it might be, and guesses neither", async () => {
    const { built } = await offerFrom();
    const verdict = await acceptHandoffOffer(built.offer, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: null,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unknown-manifest");
    expect(verdict.refusals[0].message).toContain("either a race");
    expect(verdict.bindings).toEqual([]);
  });
});

describe("an offer for a cell this peer's plan does not give them is refused", () => {
  it("answers from the recipient's own plan, not from the offer", async () => {
    const { built } = await offerFrom();
    // The offer is honest and well formed. What is wrong is who is reading it:
    // mara's own plan says cell 1 is okafor's, so mara may not run it however
    // the document is addressed. The document does not name an assignee at all
    // — there is nowhere in it to put one — so this can only be answered here.
    expect(Object.keys(built.offer)).not.toContain("assignee");
    const verdict = await acceptHandoffOffer(built.offer, {
      plan: planFor(HANDED, "mara"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("not-mine");
    expect(verdict.refusals[0].message).toContain("`@okafor`");
    expect(verdict.refusals[0].message).toContain("it says not you");
  });

  it("refuses a peer who does not know which peer they are", async () => {
    const { built } = await offerFrom();
    const verdict = await acceptHandoffOffer(built.offer, {
      plan: planRun(compile(HANDED), { roster: ROSTER }),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("not-mine");
  });
});

describe("an offer that would carry a private value is refused", () => {
  /**
   * The planner refuses this notebook: `$kp` is a keypair and cell 0 is marked
   * `publish`, which is `publish-secret`. The handoff is handed that refused
   * plan on purpose — the guard's whole job is to hold when the analysis above
   * it is wrong or was never checked, so a test that only ever fed it a plan it
   * had already validated would be testing the plan.
   */
  const LEAKY = `@mara publish
genkey x25519 | out $kp

@okafor
in $kp | export spki | encode base64 | out $pub
`;

  it("refuses to build one, on the type, whatever the plan concluded", async () => {
    const plan = planRun(compile(LEAKY), { me: "mara", roster: ROSTER });
    expect(plan.ok).toBe(false);
    expect(plan.cells[1].mine).toBe(false);

    const built = await buildOfferFor({
      plan,
      compiled: compile(LEAKY),
      manifest: await manifestFor(LEAKY),
      skipped: { cell: 1, waitingOn: "okafor", runsOn: ["okafor"], why: "", produces: ["pub"] },
      readSlot: () => ({ type: "text", data: "not the key, but it would not matter", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.offer).toBe(null);
    expect(built.refusals[0].reason).toBe("private-value");
    expect(built.refusals[0].message).toContain("may leave the machine that made it");
  });

  it("refuses to accept one, re-deciding on this peer's own notebook", async () => {
    // A peer that skipped the build-side guard, or that ran a build with a
    // different notebook in hand. The recipient re-runs both guards over their
    // own plan and their own types rather than believing the sender did.
    const offer = {
      v: HANDOFF_VERSION,
      kind: HANDOFF_KIND,
      manifest: await manifestDigest(await manifestFor(LEAKY)),
      cell: 1,
      cellDigest: (await manifestFor(LEAKY)).cells[1].recipeDigest,
      needs: [{ label: "kp", type: "text", data: "-----BEGIN PRIVATE KEY-----" }],
      offeredAt: new Date(0).toISOString(),
    };
    const verdict = await acceptHandoffOffer(parseHandoffOffer(JSON.stringify(offer)), {
      plan: planRun(compile(LEAKY), { me: "okafor", roster: ROSTER }),
      compiled: compile(LEAKY),
      manifest: await manifestFor(LEAKY),
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals.map((r) => r.reason)).toContain("private-value");
    expect(verdict.bindings).toEqual([]);
  });

  it("refuses on ownership alone when the analysis above it says private", async () => {
    // The other guard, in isolation: a plan whose `consumes[].private` is true
    // for a cell it nonetheless placed elsewhere. That combination cannot come
    // out of `planRun` — it would be `two-owners`, refused on text — which is
    // exactly why the guard is here and why the plan is corrupted by hand to
    // reach it. A placement bug looks like this from the handoff's side.
    const plan = planFor(HANDED, "mara");
    const bent = structuredClone(plan);
    bent.cells[1].consumes[0].private = true;
    bent.cells[1].consumes[0].owner = "mara";

    const built = await buildOfferFor({
      plan: bent,
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
      skipped: { cell: 1, waitingOn: "okafor", runsOn: ["okafor"], why: "", produces: ["b64"] },
      readSlot: () => ({ type: "text", data: "deadbeef", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("private-value");
    expect(built.refusals[0].message).toContain("would move a secret");
  });

  it("has no encoding for key material even if a guard were removed", () => {
    expect(() =>
      parseHandoffOffer(
        JSON.stringify({
          v: HANDOFF_VERSION,
          kind: HANDOFF_KIND,
          manifest: "a".repeat(64),
          cell: 0,
          cellDigest: "b".repeat(64),
          needs: [{ label: "kp", type: "keypair", data: {} }],
          offeredAt: new Date(0).toISOString(),
        })
      )
    ).toThrow(/not a kind an offer carries/);
  });
});

describe("an offer writes only into slots the cell actually reads", () => {
  it("refuses a slot the cell never asked for", async () => {
    const { built } = await offerFrom();
    const smuggled = {
      ...built.offer,
      needs: [...built.offer.needs, { label: "me", type: "text", data: "somebody else's key" }],
    };
    const verdict = await acceptHandoffOffer(smuggled, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unasked-slot");
    expect(verdict.refusals[0].message).toContain("a slot of their choosing");
  });

  it("refuses an offer that leaves out something the cell reads", async () => {
    const { built } = await offerFrom();
    const thin = { ...built.offer, needs: [] };
    const verdict = await acceptHandoffOffer(thin, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("incomplete");
  });

  it("refuses to overwrite a value this peer already holds", async () => {
    const { built } = await offerFrom();
    const verdict = await acceptHandoffOffer(built.offer, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
      hasSlot: (l) => l === "seed",
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("slot-present");
  });

  it("will not build a partial offer when a third peer holds part of it", async () => {
    const src = `@mara publish
bytes deadbeef | encode hex | out $a

@nkechi publish
bytes cafebabe | encode hex | out $b

@okafor
in $a | out $x
in $b | out $y
`;
    const roster = { ...ROSTER, nkechi: "1122334455667788990011223344556677889900" };
    const plan = planRun(compile(src), { me: "mara", roster });
    expect(plan.ok, plan.refusals.map((r) => r.message).join(" · ")).toBe(true);
    const built = await buildOfferFor({
      plan,
      compiled: compile(src),
      manifest: await manifestFor(src, roster),
      skipped: { cell: 2, waitingOn: "okafor", runsOn: ["okafor"], why: "", produces: ["x", "y"] },
      readSlot: (label) =>
        label === "a" ? { type: "text", data: "deadbeef", meta: {} } : null,
    });
    expect(built.ok).toBe(false);
    expect(built.refusals.map((r) => r.reason)).toContain("incomplete");
    expect(built.refusals.find((r) => r.reason === "incomplete").message).toContain("@nkechi");
  });
});

describe("a rendezvous cell is refused rather than half-supported", () => {
  const RENDEZVOUS = `@mara publish
bytes deadbeef | encode hex | out $seed

@*
in $seed | decode hex | encode base64 | out $b64
`;

  /**
   * A rendezvous plan, built the only way one can still arrive.
   *
   * `validateRecipe` now refuses `@*` — this build can describe a rendezvous
   * and not perform one, so the header is a compile error rather than a cell
   * that runs alone. That does not make these guards dead: `planRun` places a
   * rendezvous from any AST it is handed, and a plan or an offer reaching this
   * peer was built somewhere else — by an older build, a newer one, or one that
   * simply permits the header. Defence in depth is the whole point of a guard
   * sitting behind a compiler.
   *
   * So the plan comes from the *parsed* AST rather than the compiled one, which
   * is exactly the shape a foreign plan has.
   */
  const rendezvousPlan = (me) =>
    planRun(parseRecipeSource(RENDEZVOUS).ast, { me, roster: ROSTER });

  it("is not offered, because there is no barrier to enter it with", async () => {
    const plan = rendezvousPlan("mara");
    expect(plan.cells[1].kind).toBe("rendezvous");
    const built = await buildOfferFor({
      plan,
      compiled: compile(RENDEZVOUS),
      manifest: await manifestFor(RENDEZVOUS),
      skipped: { cell: 1, waitingOn: "*", runsOn: [], why: "", produces: ["b64"] },
      readSlot: () => ({ type: "text", data: "deadbeef", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("rendezvous");
    expect(built.refusals[0].message).toContain("half a rendezvous");
  });

  it("is not accepted either, however it was built", async () => {
    const manifest = await manifestFor(RENDEZVOUS);
    const verdict = await acceptHandoffOffer(
      {
        v: HANDOFF_VERSION,
        kind: /** @type {*} */ (HANDOFF_KIND),
        manifest: await manifestDigest(manifest),
        cell: 1,
        cellDigest: manifest.cells[1].recipeDigest,
        needs: [{ label: "seed", type: "text", data: "deadbeef" }],
        offeredAt: new Date(0).toISOString(),
      },
      // The manifest and the compiled recipe are the recipient's own; the
      // *plan* is the foreign-shaped one. This is a peer whose build made a
      // rendezvous offering it to a build that will not.
      { plan: rendezvousPlan("okafor"), compiled: compile(RENDEZVOUS), manifest }
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("rendezvous");
  });
});

/* ───────────────────────── the document's closed shape ──────────────────── */

describe("an offer carries seven fields and has nowhere to put an eighth", () => {
  it("refuses a document that grew a claim about who runs the cell", async () => {
    const { built } = await offerFrom();
    const wire = JSON.parse(offerToJson(built.offer));
    expect(() => parseHandoffOffer(JSON.stringify({ ...wire, assignee: "okafor" }))).toThrow(
      /does not say who runs the cell/
    );
    expect(() => parseHandoffOffer(JSON.stringify({ ...wire, fpr: FPR_O }))).toThrow(
      /unexpected field/
    );
  });

  it("refuses annotations riding along on a carried value", async () => {
    const { built } = await offerFrom();
    const wire = JSON.parse(offerToJson(built.offer));
    wire.needs[0].meta = { sensitive: false };
    expect(() => parseHandoffOffer(JSON.stringify(wire))).toThrow(/stay on the machine/);
  });

  it("refuses two values for one slot, a bad digest, and a bad index", () => {
    const base = {
      v: HANDOFF_VERSION,
      kind: HANDOFF_KIND,
      manifest: "a".repeat(64),
      cell: 0,
      cellDigest: "b".repeat(64),
      needs: [],
      offeredAt: new Date(0).toISOString(),
    };
    expect(() =>
      parseHandoffOffer(
        JSON.stringify({
          ...base,
          needs: [
            { label: "x", type: "text", data: "1" },
            { label: "x", type: "text", data: "2" },
          ],
        })
      )
    ).toThrow(/carried twice/);
    expect(() => parseHandoffOffer(JSON.stringify({ ...base, manifest: "nope" }))).toThrow(
      /64 lowercase hex/
    );
    expect(() => parseHandoffOffer(JSON.stringify({ ...base, cell: -1 }))).toThrow(
      /must be a cell index/
    );
    expect(() => parseHandoffOffer(JSON.stringify({ ...base, kind: "basilisk.run-manifest" }))).toThrow(
      /not a Basilisk cell handoff offer/
    );
    expect(() => parseHandoffOffer(JSON.stringify({ ...base, v: 99 }))).toThrow(
      /unsupported version/
    );
  });

  it("tells a v1 offer which cell it would have meant, rather than refusing a digest", async () => {
    // `cell` kept its shape and changed what it counts, so a v1 offer read
    // under v2 would have selected a different cell of any notebook with a
    // blank one — and been refused with a `cellDigest` mismatch, which says
    // the cell's *text* is wrong when what is wrong is which cell was meant.
    const { built } = await offerFrom();
    const asV1 = JSON.stringify({ ...built.offer, v: 1 });
    expect(() => parseHandoffOffer(asV1)).toThrow(/unsupported version 1/);
    expect(() => parseHandoffOffer(asV1)).toThrow(/numbers every cell the way the notebook does/);
    expect(() => parseHandoffOffer(asV1)).not.toThrow(/mismatch|does not match/);
  });

  it("drops nothing on the floor when the values arrive as a pasted one would", async () => {
    const { built } = await offerFrom();
    const verdict = await acceptHandoffOffer(built.offer, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    // No `meta` travels: the annotations an op left on a value are things it
    // said about the value, and a peer does not get to choose them here.
    expect(verdict.bindings[0].value.meta).toEqual({});
  });
});
