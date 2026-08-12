/**
 * `publish` can name which of a cell's `out` artifacts leave the machine.
 *
 * The ceremony shape is the reason. A verifiable split writes three things and
 * they have three different destinations: the commitments are *public* and
 * every custodian needs them to check the share they were handed; the shares
 * are the secret being protected and go to one holder each, by hand; the
 * expected digest is a local check the room compares against later. All three
 * are nested — under `tee`, under `tee`, under `foreach` — because that is what
 * a fan-out is, and `plan.js` already says a nested `out` is still the cell's
 * output.
 *
 * A header that could only say "publish everything" therefore could not say
 * anything a dealer means. Two things stood in the way, and both are pinned
 * below:
 *
 * 1. `validateChainHeader` looked for `out` in the cell's **top-level** steps
 *    only, so a cell whose every `out` is nested was told it "has no `out`" —
 *    a sentence that is not true about the recipe it was refusing.
 * 2. `publish` took no operand, so the only thing it could mean was *all of
 *    them*, and the planner rightly refused the whole cell because `$share`
 *    is a value that may not leave the machine that made it.
 *
 * `@mara publish=$commitments` says the one thing the dealer means. What it
 * lets out is one named slot; what it newly *keeps in* is every other slot of
 * that cell, which a bare `publish` had been handing to the room wholesale.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { splitRecipe } from "../lib/toolkit/ceremony.js";
import {
  buildOfferFor,
  buildResultFor,
  summarizeHandoff,
} from "../lib/toolkit/handoff.js";
import { buildRunManifest } from "../lib/toolkit/manifest.js";
import { planChains, planRun } from "../lib/toolkit/plan.js";
import {
  compileRecipe,
  parseRecipe,
  publishedSlots,
  serializeRecipe,
  validateRecipe,
} from "../lib/toolkit/recipe.js";
import {
  compactRecipeText,
  decodeSharePayload,
  encodeSharePayload,
  expandShareRecipe,
} from "../lib/toolkit/fragment.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { runRecipe } from "../lib/toolkit/engine.js";

const FPR_M = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_O = "91C7E6D5C4B3A29180716253443526170819AABB";
const ROSTER = { mara: FPR_M, okafor: FPR_O };

/** The ceremony's own split cell, from the module the Sheet runs. */
const SPLIT = splitRecipe({ threshold: 2, shares: 3 });

/** The recipe that could not be written. */
const DEALER = `@mara publish=$commitments\n${SPLIT}`;

const errorsFor = (src) =>
  (compileRecipe(src).validation.errors || []).map((e) => e.message);

/* ─────────────────────── the shape that was blocked ─────────────────────── */

describe("a dealer publishes the commitments and keeps the shares", () => {
  it("is the ceremony's own split cell, unchanged but for the header", () => {
    // If `splitRecipe` stops writing these, this file is testing a shape the
    // product no longer has, and the assertion above it is worthless.
    expect(SPLIT).toContain("vss.commitments | out $commitments");
    expect(SPLIT).toContain("- out $share | qr");
    expect(SPLIT).toContain("digest | encode hex | out $expected");
    // Every one of them is nested — none is a top-level step of the cell.
    expect(SPLIT.split("\n").filter((l) => /^\s*\|?\s*out /.test(l))).toEqual([]);
  });

  it("compiles", () => {
    expect(errorsFor(DEALER)).toEqual([]);
  });

  it("publishes exactly the commitments", () => {
    const { ast } = compileRecipe(DEALER);
    const chain = ast.chains[0];
    expect(chain.peer).toBe("mara");
    expect(chain.publish).toBe(true);
    expect(chain.publishSlots).toEqual(["commitments"]);
    expect(publishedSlots(chain)).toEqual(["commitments"]);
  });

  it("plans without a refusal, where a bare `publish` cannot", () => {
    const named = planRun(compileRecipe(DEALER), { me: "mara", roster: ROSTER });
    expect(named.refusals).toEqual([]);
    expect(named.cells[0].publishes).toEqual(["commitments"]);
    // The cell still *produces* all three: publishing is about what leaves,
    // not about what the cell writes.
    expect(named.cells[0].produces).toEqual(["expected", "commitments", "share"]);

    // The same cell with a bare `publish` is refused, and named `$share` as
    // the reason — which is the correct answer to "publish all of this".
    const all = planRun(compileRecipe(`@mara publish\n${SPLIT}`), {
      me: "mara",
      roster: ROSTER,
    });
    expect(all.refusals.map((r) => r.reason)).toEqual(["publish-secret"]);
    expect(all.refusals[0].actual).toContain("$share");
  });
});

/* ───────────────── the sentence that was not true (fix 1) ───────────────── */

describe("`publish` sees an `out` at any depth", () => {
  it("no longer tells a cell full of nested `out`s that it has none", () => {
    // The old message said "the cell has no `out`" about a cell with three of
    // them. It is now a plan refusal about `$share`, which is a true sentence
    // about the same recipe — and refusing at plan time rather than compile
    // time is what lets `publish=$commitments` be written at all.
    expect(errorsFor(`@mara publish\n${SPLIT}`)).toEqual([]);
  });

  it("still refuses a cell that writes nothing at all", () => {
    expect(errorsFor("@alice publish\nrandom 32 | inspect")[0]).toMatch(
      /has no `out`/
    );
  });
});

/* ─────────────────────────── what it keeps in ───────────────────────────── */

describe("naming a slot un-publishes every other slot of that cell", () => {
  // `$expected` rather than `$share` because a `foreach` body registers its
  // `out` per item (`$share1`…), so `$expected` is the withheld slot a second
  // cell can actually name. The ownership question is the same one.
  const READS_EXPECTED = `${DEALER}\n\n@okafor\nin $expected | out $back`;

  it("makes the unnamed slots private to the peer that wrote them", () => {
    const plan = planRun(compileRecipe(READS_EXPECTED), { me: "okafor", roster: ROSTER });
    const row = plan.cells[1].consumes.find((c) => c.label === "expected");
    expect(row.private).toBe(true);
    expect(row.owner).toBe("mara");
  });

  it("refuses the cell that reads one, naming the remedy", () => {
    const plan = planRun(compileRecipe(READS_EXPECTED), { me: "okafor", roster: ROSTER });
    expect(plan.ok).toBe(false);
    expect(plan.refusals[0].reason).toBe("two-owners");
    expect(plan.refusals[0].message).toContain("$expected");
  });

  it("and a bare `publish` on the same notebook does not — which is the hazard", () => {
    // Same recipe, header widened. `$expected` becomes everybody's, and
    // okafor's cell plans cleanly. This is the assertion that says what
    // `publish=` narrows rather than what it widens.
    const wide = READS_EXPECTED.replace("publish=$commitments", "publish");
    const plan = planRun(compileRecipe(wide), { me: "okafor", roster: ROSTER });
    const row = plan.cells[1].consumes.find((c) => c.label === "expected");
    expect(row.private).toBe(false);
  });
});

/* ────────────────────────────── round trip ──────────────────────────────── */

describe("the named header survives every trip a recipe takes", () => {
  it("serializes back to the header it was read from", () => {
    const { ast } = compileRecipe(DEALER);
    expect(serializeRecipe(ast).split("\n")[0]).toBe("@mara publish=$commitments");
    // Idempotent: the canonical text of the canonical text is itself.
    const once = serializeRecipe(ast);
    expect(serializeRecipe(compileRecipe(once).ast)).toBe(once);
  });

  it("reads the compact spelling a `#r=` link carries", () => {
    // A flat cell, because compacting a *nested* body is broken for reasons
    // that have nothing to do with the header — `tee{ - a - b }` space-joins
    // two branches into one and does not re-parse. What is under test here is
    // that the header survives the link, and a flat cell tests exactly that.
    const flat = "@mara publish=$hex\nrandom 32 | encode hex | out $hex";
    const compact = compactRecipeText(flat);
    expect(compact).toContain("@mara publish=$hex ");
    const back = parseRecipe(expandShareRecipe(decodeSharePayload(encodeSharePayload(compact))));
    expect(back.errors).toEqual([]);
    expect(back.ast.chains[0].publishSlots).toEqual(["hex"]);
    expect(serializeRecipe(back.ast)).toBe(flat);
  });

  it("carries more than one name", () => {
    const two = `@mara publish=$commitments,$expected\n${SPLIT}`;
    const { ast } = compileRecipe(two);
    expect(ast.chains[0].publishSlots).toEqual(["commitments", "expected"]);
    expect(serializeRecipe(ast).split("\n")[0]).toBe(
      "@mara publish=$commitments,$expected"
    );
    expect(errorsFor(two)).toEqual([]);
  });

  it("leaves a bare `publish` bare", () => {
    const src = "@mara publish\nbytes deadbeef | encode hex | out $a";
    const { ast } = compileRecipe(src);
    expect(ast.chains[0].publishSlots).toBeUndefined();
    expect(serializeRecipe(ast)).toBe(src);
  });
});

/* ───────────────────────── what it refuses to mean ──────────────────────── */

describe("the named header refuses what it cannot mean", () => {
  it("refuses a name the cell does not write", () => {
    const [message] = errorsFor(`@mara publish=$commitment\n${SPLIT}`);
    expect(message).toMatch(/\$commitment/);
    expect(message).toMatch(/does not write/);
  });

  it("refuses `publish=` with nothing after it", () => {
    expect(errorsFor(`@mara publish=\n${SPLIT}`)[0]).toMatch(/names the slots/);
  });

  it("requires the `$`, so a bare word cannot be mistaken for a step", () => {
    expect(errorsFor(`@mara publish=commitments\n${SPLIT}`)[0]).toMatch(/\$commitments/);
  });

  it("refuses a hand-built AST that names slots without publishing", () => {
    // Unspellable in text, reachable through the AST, and it would serialize
    // to a recipe that no longer says it.
    const { ast } = parseRecipe(DEALER);
    const forged = {
      ...ast,
      chains: [{ ...ast.chains[0], publish: undefined }],
    };
    expect(validateRecipe(forged).errors[0].message).toMatch(/without `publish`/);
  });

  it("keeps the peer requirement — a name is not a peer", () => {
    const { ast } = parseRecipe(DEALER);
    const forged = { ...ast, chains: [{ ...ast.chains[0], peer: undefined }] };
    expect(validateRecipe(forged).errors[0].message).toMatch(/needs a peer to go from/);
  });
});

/* ──────────────────────────────── handoff ───────────────────────────────── */

describe("a withheld slot does not ride out in a handoff", () => {
  /**
   * okafor's cell writes two things and its header publishes one. mara's copy
   * of the notebook says `publish`, so *her plan* calls both of them public.
   *
   * That disagreement is the only way to reach this guard, and it is exactly
   * the case it exists for: a peer whose ownership analysis says a value may
   * travel, asking for one the recipe withheld by name. An honest plan of the
   * narrow notebook refuses mara's reader long before a handoff — which is the
   * planner doing its job, and no reason for the boundary to be unchecked.
   */
  const NARROW = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor publish=$b64
in $seed | decode hex | encode base64 | out $b64 | decode base64 | encode hex | out $hex

@mara
in $b64 | out $one

@mara
in $hex | out $two`;
  const WIDE = NARROW.replace("publish=$b64", "publish");

  const manifestFor = async (src) => {
    const chains = planChains(compileRecipe(src));
    return buildRunManifest({
      title: "handoff",
      recipeSource: src,
      peers: ROSTER,
      cells: chains.map((chain, i) => ({
        index: i,
        peer: String(chain.peer || ""),
        publish: !!chain.publish,
        recipe: serializeRecipe({ chains: [chain] }),
      })),
    });
  };

  /** Run a notebook as one peer, gated, keeping whatever it produced. */
  async function runAs(src, me, into) {
    const compiled = compileRecipe(src);
    const plan = planRun(compiled, { me, roster: ROSTER });
    const registry = into || createSlotRegistry();
    const skipped = [];
    await runRecipe(
      compiled.ast,
      {},
      { slotRegistry: registry, placement: { plan, onSkip: (s) => skipped.push(s) } }
    ).catch(() => []);
    return {
      compiled,
      plan,
      registry,
      skipped,
      readSlot: (label) => (registry.has(label) ? registry.resolve(label) : null),
    };
  }

  it("hands over the slot the header publishes, and refuses the other", async () => {
    // The wide notebook runs end to end, which is what gives okafor real
    // values in both slots to be asked for.
    const manifest = await manifestFor(NARROW);
    const mara = await runAs(WIDE, "mara");
    const offered = await buildOfferFor({
      plan: mara.plan,
      compiled: mara.compiled,
      manifest: await manifestFor(WIDE),
      skipped: mara.skipped[0],
      readSlot: mara.readSlot,
    });
    expect(offered.ok, summarizeHandoff(offered)).toBe(true);

    const okafor = await runAs(WIDE, "okafor");
    for (const need of offered.offer.needs) {
      okafor.registry.register(`$${need.label}`, { type: "text", data: need.data });
    }
    const ran = await runAs(WIDE, "okafor", okafor.registry);
    expect(ran.readSlot("b64")).toBeTruthy();
    expect(ran.readSlot("hex")).toBeTruthy();

    // Reported under the wide plan, against the notebook that actually says
    // which slot may leave.
    const built = await buildResultFor({
      plan: planRun(compileRecipe(WIDE), { me: "okafor", roster: ROSTER }),
      compiled: compileRecipe(NARROW),
      manifest,
      cell: 1,
      readSlot: ran.readSlot,
      ranAt: new Date(0),
    });
    expect(built.ok).toBe(false);
    const withheld = built.refusals.filter((r) => r.reason === "withheld-value");
    expect(withheld.map((r) => r.actual)).toEqual(["hex"]);
    expect(withheld[0].message).toContain("$b64");
  });
});

/* ──────────────────────────── an entry point ────────────────────────────── */

/**
 * The recurring defect in this stack is a finished mechanism with nothing that
 * can reach it — `CellAssign` exists because the `@peer` header was one. A
 * modifier only the source view can type is the same defect again, so the path
 * from the menu to the chain is pinned here.
 *
 * Source assertions because the suite is `environment: "node"` and cannot
 * mount a component — and because the defect is a *missing* argument, which no
 * rendering of the correct output would have caught.
 */
describe("the menu can write the header, not only the source view", () => {
  const read = (rel) =>
    readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

  it("hands the named slots out of CellAssign", () => {
    const src = read("../toolkit/widgets/CellAssign.tsx");
    // Three arguments, not two: a callback that dropped the third would leave
    // the control able to publish everything and nothing else.
    expect(src).toMatch(
      /onAssign:\s*\(\s*peer[^)]*publish[^)]*publishSlots:\s*string\[\]\s*\)/
    );
    expect(src).toContain("outSlots");
  });

  it("gives it the cell's own out slots, at any depth", () => {
    const src = read("../toolkit/ToolkitShell.tsx");
    // `outSlotLabels` rather than a local walk: the menu must offer exactly the
    // labels `validateChainHeader` will accept, and one walker answers both.
    expect(src).toContain("outSlots={outSlotLabels(chain.steps || [])}");
    expect(src).toMatch(/setCellPeer\(i,\s*peer,\s*publish,\s*publishSlots\)/);
  });

  it("carries them into the chain", () => {
    const src = read("../toolkit/useNotebook.ts");
    const start = src.indexOf("const setCellPeer");
    expect(start).toBeGreaterThan(-1);
    const body = src.slice(start, src.indexOf("[]\n  );", start));
    expect(body).toContain("publishSlots");
    // Cleared with the peer, like `publish` — a list of slots attached to
    // nobody is a claim about a boundary that no longer exists.
    expect(body).toContain("publishSlots: _slots");
  });
});
