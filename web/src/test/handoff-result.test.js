/**
 * The value comes back, and the run that stopped finishes.
 *
 * `run-gate.test.js` wrote the seam — *"runs the moment the value is actually
 * here"* — before either half of the handoff existed. `handoff-offer.test.js`
 * arrived through it in one direction. This file is the other: mara's run stops
 * at a cell reading `$b64`, okafor runs the cell that writes it, signs what came
 * out, and mara registers it. Nothing in `placement.js` or `engine.js` changed
 * for either half, because the gate asks the registry first and a value that is
 * here is a value it has nothing to say about.
 *
 * What the cases are for, in the order they matter:
 *
 * 1. **The round trip, end to end in one test.** The stopped run, the returned
 *    value, and the same run completing — with the control that the run is still
 *    stopped right up until the bindings go in.
 * 2. **The refusals**, each written so it fires: a result nobody is attributed
 *    with; one for a cell this peer's plan does not place on that peer; one for
 *    a cell nobody offered; one against an unknown manifest; one for a cell
 *    already satisfied; one carrying a slot the cell does not write; one leaving
 *    out a slot the run stops on; and the two private-value guards, both reached
 *    the only way they can be reached — through a plan that is wrong.
 * 3. **Consent.** A result registers nothing and restarts nothing. The bindings
 *    are returned, and putting them in is a line somebody writes.
 * 4. **The document's shape**, closed, and its one asymmetry with the offer: it
 *    is signed, and it is parsed only out of the bytes a signature covered.
 */
import { generateKey } from "openpgp";
import { describe, expect, it } from "vitest";
import {
  RESULT_KIND,
  RESULT_VERSION,
  acceptCellResult,
  acceptHandoffOffer,
  buildOfferFor,
  buildResultFor,
  offerToJson,
  parseCellResult,
  parseHandoffOffer,
  resultToJson,
  summarizeHandoff,
} from "../lib/toolkit/handoff.js";
import { readSignedResult } from "../lib/notebook/documents.js";
import { signOpenPgp } from "../lib/pgp/sign.js";
import { planChains, planRun } from "../lib/toolkit/plan.js";
import { parseRecipeSource } from "../lib/toolkit/recipe-parse.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { buildRunManifest, manifestDigest } from "../lib/toolkit/manifest.js";
import { compileRecipe, migrateRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";

const FPR_M = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_O = "91C7E6D5C4B3A29180716253443526170819AABB";
const FPR_N = "1122334455667788990011223344556677889900";
const ROSTER = { mara: FPR_M, okafor: FPR_O };
const ROOM_OF_THREE = { ...ROSTER, nkechi: FPR_N };

/**
 * The notebook the whole file turns on.
 *
 * Three cells and two machines: mara publishes a seed, okafor's cell turns it
 * into `$b64` and publishes that, and **mara's last cell reads `$b64`**. That
 * last cell is what makes this different from `handoff-offer.test.js`'s
 * notebook, where mara's run merely skipped a cell and walked on. Here mara's
 * run *stops*, which is the state a result exists to end.
 */
const ROUND_TRIP = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor publish
in $seed | decode hex | encode base64 | out $b64

@mara
in $b64 | out $done
`;

/** @param {string} src */
const compile = (src) => compileRecipe(migrateRecipe(src).recipe);

/**
 * A manifest for a notebook, cells numbered the way a plan numbers them.
 * @param {string} src @param {Record<string, string>} [peers]
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

/** @param {string} src @param {string} me @param {Record<string, string>} [roster] */
function planFor(src, me, roster = ROSTER) {
  return planRun(compile(src), { me, roster });
}

/**
 * Run a notebook as one peer, gated, and keep what it left behind.
 *
 * The `catch` is the point rather than tidiness: a placed run that stops on a
 * withheld input still produced everything above the cell it stopped at, and
 * that is exactly the state both sides of a handoff are built from.
 * @param {string} src @param {string} me
 * @param {import("../lib/toolkit/slot-registry.js").SlotRegistry} [into]
 * @param {Record<string, string>} [roster]
 */
async function runAs(src, me, into, roster = ROSTER) {
  const compiled = compile(src);
  const plan = planFor(src, me, roster);
  /** @type {import("../lib/toolkit/placement.js").SkippedCell[]} */
  const skipped = [];
  const registry = into || createSlotRegistry();
  /** @type {Error|null} */
  let stopped = null;
  const arts = await runRecipe(
    compiled.ast,
    {},
    { slotRegistry: registry, placement: { plan, onSkip: (s) => skipped.push(s) } }
  ).catch((err) => {
    stopped = err;
    return [];
  });
  return {
    compiled,
    plan,
    registry,
    skipped,
    stopped: /** @type {*} */ (stopped),
    arts,
    readSlot: (/** @type {string} */ label) =>
      registry.has(label) ? registry.resolve(label) : null,
  };
}

/**
 * okafor accepts the offer for cell 1, runs, and builds the result.
 * @param {string} [src] @param {Record<string, string>} [roster]
 */
async function resultFrom(src = ROUND_TRIP, roster = ROSTER) {
  const manifest = await manifestFor(src, roster);
  const mara = await runAs(src, "mara", undefined, roster);
  const offered = await buildOfferFor({
    plan: mara.plan,
    compiled: mara.compiled,
    manifest,
    skipped: mara.skipped[0],
    readSlot: mara.readSlot,
  });
  expect(offered.ok, summarizeHandoff(offered)).toBe(true);

  // okafor's side: check the offer against his own plan, put the bindings in,
  // and only then run. Two acts, and the person is between them.
  const okafor = await runAs(src, "okafor", createSlotRegistry(), roster);
  const taken = await acceptHandoffOffer(parseHandoffOffer(offerToJson(offered.offer)), {
    plan: okafor.plan,
    compiled: okafor.compiled,
    manifest,
    hasSlot: (l) => okafor.registry.has(l),
  });
  expect(taken.ok, summarizeHandoff(taken)).toBe(true);
  for (const b of taken.bindings) okafor.registry.register(`$${b.label}`, b.value);
  const ran = await runAs(src, "okafor", okafor.registry, roster);

  const built = await buildResultFor({
    plan: ran.plan,
    compiled: ran.compiled,
    manifest,
    cell: 1,
    readSlot: ran.readSlot,
    ranAt: new Date(0),
  });
  return { built, manifest, mara, ran, offered };
}

/** What mara holds about what she handed out. @param {string} sha */
const offeredCell1 = (sha) => [{ manifest: sha, cell: 1, to: "okafor" }];

/* ───────────────────────────── the round trip ───────────────────────────── */

describe("a returned value ends the run that stopped for want of it", () => {
  it("stops on mara's side, which is the state a result exists to end", async () => {
    const mara = await runAs(ROUND_TRIP, "mara");
    // Cell 0 ran here. Cell 1 is okafor's. Cell 2 is mara's own and reads what
    // cell 1 writes, so the gate stops the run rather than letting it finish
    // short — the sentence names the slot, the cell and the peer.
    expect(mara.registry.has("seed")).toBe(true);
    expect(mara.skipped.map((s) => s.cell)).toEqual([1]);
    expect(mara.skipped[0]).toMatchObject({ waitingOn: "okafor", produces: ["b64"] });
    expect(mara.stopped?.basiliskWithheld).toEqual({
      cell: 2,
      slot: "b64",
      from: 1,
      peer: "okafor",
    });
    expect(mara.registry.has("done")).toBe(false);
  });

  it("comes back as a document naming the run, the cell and what came out", async () => {
    const { built, manifest } = await resultFrom();
    expect(built.ok, summarizeHandoff(built)).toBe(true);
    expect(built.result).toEqual({
      v: RESULT_VERSION,
      kind: RESULT_KIND,
      manifest: await manifestDigest(manifest),
      cell: 1,
      cellDigest: manifest.cells[1].recipeDigest,
      produced: [{ label: "b64", type: "text", data: "3q2+7w==" }],
      ranAt: new Date(0).toISOString(),
    });
    // The pairing is the offer's, and there is nowhere in the document for a
    // second one: no correlation id, no offer digest, no nonce.
    expect(Object.keys(built.result).sort()).toEqual([
      "cell",
      "cellDigest",
      "kind",
      "manifest",
      "produced",
      "ranAt",
      "v",
    ]);
  });

  it("registers, and the previously stopped run completes — the seam, end to end", async () => {
    const { built, manifest } = await resultFrom();
    const sha = await manifestDigest(manifest);
    const wire = resultToJson(built.result);
    const result = parseCellResult(wire);

    // mara's run, stopped, with everything it produced still in hand.
    const mara = await runAs(ROUND_TRIP, "mara");
    expect(mara.stopped).toBeTruthy();
    expect(mara.registry.has("done")).toBe(false);

    const verdict = await acceptCellResult(result, {
      plan: mara.plan,
      compiled: mara.compiled,
      manifest,
      by: "okafor",
      offered: offeredCell1(sha),
      hasSlot: (l) => mara.registry.has(l),
    });
    expect(verdict.ok, summarizeHandoff(verdict)).toBe(true);
    expect(verdict.bindings.map((b) => b.label)).toEqual(["b64"]);
    expect(summarizeHandoff(verdict)).toContain("nothing runs until somebody says so");

    // The control, and the whole reason this is one test: run it again and it
    // stops in the same place. Checking a result changes nothing — the bindings
    // are still sitting in the verdict, and a run is a fresh registry away.
    const still = await runAs(ROUND_TRIP, "mara");
    expect(still.stopped?.basiliskWithheld).toMatchObject({ cell: 2, slot: "b64" });
    expect(still.registry.has("b64")).toBe(false);

    // Accepting is this line. A person wrote it, and then pressed Run.
    const handed = createSlotRegistry();
    for (const b of verdict.bindings) handed.register(`$${b.label}`, b.value);

    const done = await runAs(ROUND_TRIP, "mara", handed);
    expect(done.stopped).toBe(null);
    expect(done.skipped.map((s) => s.cell)).toEqual([1]);
    expect(handed.has("done")).toBe(true);
    expect(done.arts.some((a) => String(a.content).includes("3q2+7w=="))).toBe(true);
  });

  it("carries bytes as bytes, and drops the annotations an op left on them", async () => {
    const src = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor publish
in $seed | decode hex | out $raw

@mara
in $raw | encode base64 | out $done
`;
    const { built, manifest } = await resultFrom(src);
    expect(built.ok, summarizeHandoff(built)).toBe(true);
    expect(built.result.produced).toEqual([{ label: "raw", type: "bytes", data: "3q2+7w==" }]);

    const mara = await runAs(src, "mara");
    const verdict = await acceptCellResult(built.result, {
      plan: mara.plan,
      compiled: mara.compiled,
      manifest,
      by: "okafor",
      offered: offeredCell1(await manifestDigest(manifest)),
    });
    expect(verdict.ok, summarizeHandoff(verdict)).toBe(true);
    expect(verdict.bindings[0].value.data).toBeInstanceOf(Uint8Array);
    expect([...verdict.bindings[0].value.data]).toEqual([0xde, 0xad, 0xbe, 0xef]);
    // A returned value arrives the way a pasted one does. `sensitive`, a
    // filename, an inspect snapshot: all of them are things an op on another
    // machine said, and none of them is the value.
    expect(verdict.bindings[0].value.meta).toEqual({});
  });
});

/* ───────────────────── who returned it, and what for ────────────────────── */

describe("a result is answered from this peer's own plan and record", () => {
  /** @param {Partial<Parameters<typeof acceptCellResult>[1]>} over */
  async function accepting(over) {
    const { built, manifest } = await resultFrom();
    const mara = await runAs(ROUND_TRIP, "mara");
    return acceptCellResult(built.result, {
      plan: mara.plan,
      compiled: mara.compiled,
      manifest,
      by: "okafor",
      offered: offeredCell1(await manifestDigest(manifest)),
      ...over,
    });
  }

  it("refuses one nobody is attributed with", async () => {
    const verdict = await accepting({ by: "" });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unattributed");
    expect(verdict.refusals[0].message).toContain("a claim nobody made");
    expect(verdict.bindings).toEqual([]);
  });

  it("refuses one from a peer this plan does not place the cell on", async () => {
    // The document says nothing about who ran the cell — there is nowhere in it
    // to say so — and this peer's plan says cell 1 is okafor's. A result from
    // nkechi is nkechi claiming somebody else's work, whoever signed it.
    const verdict = await accepting({ by: "nkechi" });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("not-theirs");
    expect(verdict.refusals[0].message).toContain("`@okafor`");
    expect(verdict.refusals[0].message).toContain("it does not say them");
  });

  it("refuses one for a cell nobody was offered", async () => {
    // Absence is not permission, at the other end of the exchange from
    // `placement.js`'s version of the same rule.
    const verdict = await accepting({ offered: [] });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("not-offered");
    expect(verdict.refusals[0].message).toContain("Absence is not permission");
  });

  it("refuses one whose offer went to a different peer, cell or run", async () => {
    const sha = await manifestDigest(await manifestFor(ROUND_TRIP));
    for (const offered of [
      [{ manifest: sha, cell: 1, to: "nkechi" }],
      [{ manifest: sha, cell: 2, to: "okafor" }],
      [{ manifest: "f".repeat(64), cell: 1, to: "okafor" }],
    ]) {
      const verdict = await accepting({ offered });
      expect(verdict.ok, JSON.stringify(offered)).toBe(false);
      expect(verdict.refusals[0].reason).toBe("not-offered");
    }
  });

  it("refuses one against a manifest this peer has not seen", async () => {
    const verdict = await accepting({ manifest: null });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unknown-manifest");
    expect(verdict.refusals[0].message).toContain("Nothing was committed to");
  });

  it("refuses one for a cell this peer runs itself", async () => {
    const { built, manifest } = await resultFrom();
    const okafor = await runAs(ROUND_TRIP, "okafor");
    const verdict = await acceptCellResult(built.result, {
      plan: okafor.plan,
      compiled: okafor.compiled,
      manifest,
      by: "mara",
      offered: [{ manifest: await manifestDigest(manifest), cell: 1, to: "mara" }],
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("mine-already");
    expect(verdict.refusals[0].message).toContain("nobody was asked to run it");
  });

  it("selects nothing when the cell index is bent", async () => {
    const { built, manifest } = await resultFrom();
    const mara = await runAs(ROUND_TRIP, "mara");
    const verdict = await acceptCellResult(
      { ...built.result, cell: 0 },
      {
        plan: mara.plan,
        compiled: mara.compiled,
        manifest,
        by: "okafor",
        offered: [{ manifest: await manifestDigest(manifest), cell: 0, to: "okafor" }],
      }
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("cell-mismatch");
  });

  it("refuses a rendezvous however the document was built", async () => {
    const src = `@mara publish
bytes deadbeef | encode hex | out $seed

@*
in $seed | decode hex | encode base64 | out $b64
`;
    const manifest = await manifestFor(src);
    const sha = await manifestDigest(manifest);
    const mara = await runAs(src, "mara");
    const verdict = await acceptCellResult(
      {
        v: RESULT_VERSION,
        kind: /** @type {*} */ (RESULT_KIND),
        manifest: sha,
        cell: 1,
        cellDigest: manifest.cells[1].recipeDigest,
        produced: [{ label: "b64", type: /** @type {*} */ ("text"), data: "3q2+7w==" }],
        ranAt: new Date(0).toISOString(),
      },
      {
        // `validateRecipe` now refuses `@*`, so a rendezvous plan can no longer
        // come from a compiled recipe. It can still *arrive*: `planRun` places
        // one from any AST it is handed, and the plan a result is checked
        // against was built by whoever sent it. Parsed rather than compiled
        // here, which is that shape — and the guard exists for exactly this.
        plan: planRun(parseRecipeSource(src).ast, { me: "mara", roster: ROSTER }),
        compiled: mara.compiled,
        manifest,
        by: "okafor",
        offered: offeredCell1(sha),
      }
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("rendezvous");
    expect(verdict.refusals[0].message).toContain("standing in for a room's");
  });
});

/* ─────────────────── which slots, and only which slots ──────────────────── */

describe("a result writes only into the slots its cell writes", () => {
  it("refuses a slot the cell does not write", async () => {
    const { built, manifest } = await resultFrom();
    const mara = await runAs(ROUND_TRIP, "mara");
    const verdict = await acceptCellResult(
      {
        ...built.result,
        produced: [
          ...built.result.produced,
          { label: "seed", type: /** @type {*} */ ("text"), data: "00000000" },
        ],
      },
      {
        plan: mara.plan,
        compiled: mara.compiled,
        manifest,
        by: "okafor",
        offered: offeredCell1(await manifestDigest(manifest)),
      }
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unasked-slot");
    expect(verdict.refusals[0].message).toContain("a slot of their choosing");
    expect(verdict.bindings).toEqual([]);
  });

  it("refuses one that leaves out the slot the run is stopped on", async () => {
    const { built, manifest } = await resultFrom();
    const mara = await runAs(ROUND_TRIP, "mara");
    const verdict = await acceptCellResult(
      { ...built.result, produced: [] },
      {
        plan: mara.plan,
        compiled: mara.compiled,
        manifest,
        by: "okafor",
        offered: offeredCell1(await manifestDigest(manifest)),
      }
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("incomplete");
    expect(verdict.refusals[0].message).toContain("worse place to stop");
  });

  it("refuses a cell that is already satisfied", async () => {
    const { built, manifest } = await resultFrom();
    const mara = await runAs(ROUND_TRIP, "mara");
    const verdict = await acceptCellResult(built.result, {
      plan: mara.plan,
      compiled: mara.compiled,
      manifest,
      by: "okafor",
      offered: offeredCell1(await manifestDigest(manifest)),
      hasSlot: (l) => l === "b64",
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("slot-present");
    expect(verdict.refusals[0].message).toContain("two peers answering one offer");
  });

  it("takes one answer to one offer, and refuses the second either way", async () => {
    // Two peers returning results for one cell, both ways it can happen. The
    // plan places cell 1 on okafor, so a result from nkechi is refused before
    // the values are looked at; and okafor answering twice is refused on the
    // slot, because which of two values is the right one is not a question a
    // document can answer.
    const { built, manifest } = await resultFrom(ROUND_TRIP, ROOM_OF_THREE);
    const sha = await manifestDigest(manifest);
    const mara = await runAs(ROUND_TRIP, "mara", undefined, ROOM_OF_THREE);
    const ctx = {
      plan: mara.plan,
      compiled: mara.compiled,
      manifest,
      offered: [
        { manifest: sha, cell: 1, to: "okafor" },
        { manifest: sha, cell: 1, to: "nkechi" },
      ],
    };

    const first = await acceptCellResult(built.result, { ...ctx, by: "okafor" });
    expect(first.ok, summarizeHandoff(first)).toBe(true);
    for (const b of first.bindings) mara.registry.register(`$${b.label}`, b.value);

    const fromAnother = await acceptCellResult(built.result, { ...ctx, by: "nkechi" });
    expect(fromAnother.refusals[0].reason).toBe("not-theirs");

    const again = await acceptCellResult(built.result, {
      ...ctx,
      by: "okafor",
      hasSlot: (l) => mara.registry.has(l),
    });
    expect(again.refusals[0].reason).toBe("slot-present");
  });
});

/* ───────────────────────── the private-value guards ─────────────────────── */

describe("a result that would carry a private value is refused", () => {
  /**
   * The planner refuses this notebook — `$kp` is a keypair and cell 1 is marked
   * `publish`, which is `publish-secret` — and the guard is handed that refused
   * plan on purpose. Its whole job is to hold when the analysis above it is
   * wrong or was never run, so a test that only fed it plans it had already
   * validated would be testing the plan.
   */
  const LEAKY = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor publish
genkey x25519 | out $kp

@mara
in $kp | export spki | encode base64 | out $pub
`;

  it("refuses to build one, on the type, whatever the plan concluded", async () => {
    const plan = planFor(LEAKY, "okafor");
    expect(plan.ok).toBe(false);
    const built = await buildResultFor({
      plan,
      compiled: compile(LEAKY),
      manifest: await manifestFor(LEAKY),
      cell: 1,
      readSlot: () => ({ type: "text", data: "not the key, but it would not matter", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.result).toBe(null);
    expect(built.refusals[0].reason).toBe("private-value");
    expect(built.refusals[0].message).toContain("may leave the machine that made it");
  });

  it("refuses to accept one, re-deciding on this peer's own notebook", async () => {
    // A runner who skipped their own guard, or ran it against a different
    // notebook. The recipient re-runs both guards over their own plan and their
    // own types rather than believing the sender did.
    const manifest = await manifestFor(LEAKY);
    const sha = await manifestDigest(manifest);
    const mara = await runAs(LEAKY, "mara");
    const verdict = await acceptCellResult(
      parseCellResult(
        JSON.stringify({
          v: RESULT_VERSION,
          kind: RESULT_KIND,
          manifest: sha,
          cell: 1,
          cellDigest: manifest.cells[1].recipeDigest,
          produced: [{ label: "kp", type: "text", data: "-----BEGIN PRIVATE KEY-----" }],
          ranAt: new Date(0).toISOString(),
        })
      ),
      {
        plan: mara.plan,
        compiled: mara.compiled,
        manifest,
        by: "okafor",
        offered: offeredCell1(sha),
      }
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals.map((r) => r.reason)).toContain("private-value");
    expect(verdict.bindings).toEqual([]);
  });

  it("refuses on ownership alone when the analysis above it says private", async () => {
    // The other guard, in isolation. A plan whose reader says `$b64` is private
    // to okafor while still placing that reader on mara cannot come out of
    // `planRun` — secret-locality would have moved the reading cell to okafor,
    // and a header insisting otherwise is `two-owners`, refused on text. Which
    // is exactly why the guard is here, and why the plan has to be corrupted by
    // hand to reach it. A placement bug looks like this from the handoff's side.
    const okafor = await runAs(ROUND_TRIP, "okafor");
    const bent = structuredClone(okafor.plan);
    bent.cells[2].consumes[0].private = true;
    bent.cells[2].consumes[0].owner = "okafor";

    const built = await buildResultFor({
      plan: bent,
      compiled: okafor.compiled,
      manifest: await manifestFor(ROUND_TRIP),
      cell: 1,
      readSlot: () => ({ type: "text", data: "3q2+7w==", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("private-value");
    expect(built.refusals[0].message).toContain("would move a secret");
  });

  it("treats a slot nothing could be typed as one that must not travel", async () => {
    // `publish-untyped` is an *ask* rather than a refusal, so a plan this peer
    // accepted can still carry a slot the type walk could not resolve. A value
    // that cannot be shown to be public is treated here as though it were not.
    const mara = await runAs(ROUND_TRIP, "mara");
    const bent = structuredClone(mara.plan);
    bent.cells[1].produces.push("ghost");
    bent.cells[2].consumes.push({
      label: "ghost",
      via: "in",
      from: 1,
      owner: "",
      private: false,
      type: "",
      slotOf: [],
    });
    const manifest = await manifestFor(ROUND_TRIP);
    const sha = await manifestDigest(manifest);
    const verdict = await acceptCellResult(
      {
        v: RESULT_VERSION,
        kind: /** @type {*} */ (RESULT_KIND),
        manifest: sha,
        cell: 1,
        cellDigest: manifest.cells[1].recipeDigest,
        produced: [
          { label: "b64", type: /** @type {*} */ ("text"), data: "3q2+7w==" },
          { label: "ghost", type: /** @type {*} */ ("text"), data: "who knows" },
        ],
        ranAt: new Date(0).toISOString(),
      },
      {
        plan: bent,
        compiled: mara.compiled,
        manifest,
        by: "okafor",
        offered: offeredCell1(sha),
      }
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals.map((r) => r.reason)).toContain("untyped-value");
    expect(verdict.bindings).toEqual([]);
  });
});

/* ──────────────────── a result is built from a run, or not ──────────────── */

describe("a result is built by the machine that ran the cell", () => {
  it("refuses to report a cell this peer did not run", async () => {
    const mara = await runAs(ROUND_TRIP, "mara");
    const built = await buildResultFor({
      plan: mara.plan,
      compiled: mara.compiled,
      manifest: await manifestFor(ROUND_TRIP),
      cell: 1,
      readSlot: () => ({ type: "text", data: "3q2+7w==", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("not-mine");
    expect(built.refusals[0].message).toContain("not produced by running that cell");
  });

  it("refuses to report a cell every participant runs", async () => {
    const src = `bytes deadbeef | encode hex | out $seed

in $seed | out $copy
`;
    const plan = planRun(compile(src), { me: "mara", roster: ROSTER });
    const built = await buildResultFor({
      plan,
      compiled: compile(src),
      manifest: await manifestFor(src),
      cell: 0,
      readSlot: () => ({ type: "text", data: "deadbeef", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("nothing-to-return");
    expect(built.refusals[0].message).toContain("everybody already has what it wrote");
  });

  it("refuses to report a cell whose output nobody else reads", async () => {
    // okafor ran the cell and nothing downstream is anybody's but his. Nobody
    // is stopped, so there is nothing for a result to end — and what is wanted
    // instead is said by name.
    const src = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor publish
in $seed | decode hex | encode base64 | out $b64
`;
    const okafor = await runAs(src, "okafor");
    const built = await buildResultFor({
      plan: okafor.plan,
      compiled: okafor.compiled,
      manifest: await manifestFor(src),
      cell: 1,
      readSlot: () => ({ type: "text", data: "3q2+7w==", meta: {} }),
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("nothing-to-return");
    expect(built.refusals[0].message).toContain("a receipt or an attestation");
  });

  it("refuses to report a value the run did not produce", async () => {
    const okafor = await runAs(ROUND_TRIP, "okafor");
    const built = await buildResultFor({
      plan: okafor.plan,
      compiled: okafor.compiled,
      manifest: await manifestFor(ROUND_TRIP),
      cell: 1,
      readSlot: () => null,
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("absent-value");
    expect(built.refusals[0].message).toContain("run the cell before reporting it");
  });

  it("refuses a manifest that is not this notebook's", async () => {
    const { ran } = await resultFrom();
    const built = await buildResultFor({
      plan: ran.plan,
      compiled: ran.compiled,
      manifest: await manifestFor(`@mara publish
bytes 00 | encode hex | out $seed
`),
      cell: 1,
      readSlot: ran.readSlot,
    });
    expect(built.ok).toBe(false);
    expect(built.refusals[0].reason).toBe("different-notebook");
  });
});

/* ───────────────────────── the document's closed shape ──────────────────── */

describe("a result carries seven fields and has nowhere to put an eighth", () => {
  const base = {
    v: RESULT_VERSION,
    kind: RESULT_KIND,
    manifest: "a".repeat(64),
    cell: 1,
    cellDigest: "b".repeat(64),
    produced: [{ label: "b64", type: "text", data: "3q2+7w==" }],
    ranAt: new Date(0).toISOString(),
  };

  it("refuses a document that grew a claim it cannot support", async () => {
    expect(() => parseCellResult(JSON.stringify({ ...base, proof: "trust me" }))).toThrow(
      /there is none to carry/
    );
    expect(() => parseCellResult(JSON.stringify({ ...base, receipt: "c".repeat(64) }))).toThrow(
      /unexpected field/
    );
    expect(() => parseCellResult(JSON.stringify({ ...base, signer: FPR_O }))).toThrow(
      /unexpected field/
    );
  });

  it("refuses annotations riding along on a returned value", () => {
    expect(() =>
      parseCellResult(
        JSON.stringify({
          ...base,
          produced: [{ label: "b64", type: "text", data: "x", meta: { sensitive: false } }],
        })
      )
    ).toThrow(/stay on the machine/);
  });

  it("has no encoding for key material", () => {
    expect(() =>
      parseCellResult(
        JSON.stringify({ ...base, produced: [{ label: "kp", type: "keypair", data: {} }] })
      )
    ).toThrow(/not a kind a result carries/);
  });

  it("refuses two values for one slot, a bad digest, a bad index and another document", () => {
    expect(() =>
      parseCellResult(
        JSON.stringify({
          ...base,
          produced: [
            { label: "x", type: "text", data: "1" },
            { label: "x", type: "text", data: "2" },
          ],
        })
      )
    ).toThrow(/carried twice/);
    expect(() => parseCellResult(JSON.stringify({ ...base, manifest: "nope" }))).toThrow(
      /64 lowercase hex/
    );
    expect(() => parseCellResult(JSON.stringify({ ...base, cell: -1 }))).toThrow(
      /must be a cell index/
    );
    expect(() => parseCellResult(JSON.stringify({ ...base, v: 99 }))).toThrow(
      /unsupported version/
    );
    // No other document can be read as one, in either direction.
    expect(() => parseCellResult(JSON.stringify({ ...base, kind: "basilisk.cell-handoff" }))).toThrow(
      /not a Basilisk cell result/
    );
    expect(() => parseHandoffOffer(JSON.stringify(base))).toThrow(
      /not a Basilisk cell handoff offer/
    );
  });
});

/* ─────────────────────── signed, and read as signed ─────────────────────── */

describe("a result is a claim, so it travels signed and is read that way", () => {
  /** @param {string} email */
  async function identity(email) {
    const { publicKey, privateKey } = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email }],
      format: "object",
    });
    return { fpr: publicKey.getFingerprint().toUpperCase(), key: publicKey, privateKey };
  }

  it("is parsed only out of the bytes a signature covered", async () => {
    const okafor = await identity("okafor@result.test");
    const { built } = await resultFrom();
    const json = resultToJson(built.result);
    const { armored } = await signOpenPgp(json, [okafor.privateKey], "cleartext");

    // Handed the armor directly, the parser refuses rather than unwrapping it a
    // second way — one answer to "which bytes were signed", and it comes from
    // the one place that has a key to check them with.
    expect(() => parseCellResult(armored)).toThrow(/check the signature/);

    const read = await readSignedResult(armored, { key: okafor.key, fpr: okafor.fpr });
    expect(read.result).toEqual(built.result);
    expect(read.digest).toBe(built.result.manifest);
    expect(JSON.parse(read.text)).toEqual(built.result);
  });

  it("refuses a good signature that is not that peer's", async () => {
    // The replay a `verify against every key in the room` check waves through:
    // one peer returning another peer's signed result as their own answer. The
    // signature is perfectly good. It is not theirs.
    const okafor = await identity("okafor@result.test");
    const nkechi = await identity("nkechi@result.test");
    const { built } = await resultFrom();
    const { armored } = await signOpenPgp(
      resultToJson(built.result),
      [nkechi.privateKey],
      "cleartext"
    );
    await expect(
      readSignedResult(armored, { key: okafor.key, fpr: okafor.fpr })
    ).rejects.toThrow(/not signed by that peer/);
  });

  it("refuses an unsigned result, however well formed", async () => {
    const okafor = await identity("okafor@result.test");
    const { built } = await resultFrom();
    await expect(
      readSignedResult(resultToJson(built.result), { key: okafor.key, fpr: okafor.fpr })
    ).rejects.toThrow(/cleartext-signed/);
  });
});
