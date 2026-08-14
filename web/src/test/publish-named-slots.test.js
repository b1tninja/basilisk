/**
 * `publish` says which of a cell's `out` artifacts leave the machine.
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
 * A claim that could only say "publish everything" therefore could not say
 * anything a dealer means. It was a header modifier — `@mara publish=$a,$b` —
 * and it is a step now: `out $commitments | publish`, standing on the value it
 * is a claim about. Three things follow, and each is pinned below.
 *
 * 1. The claim cannot name a slot the cell does not write, because it has to
 *    stand behind an `out` and there would be nothing to stand behind. The old
 *    form named slots from two lines away and had to be checked against the
 *    cell's `out`s at any depth — a check that once told a cell with three
 *    nested `out`s that it had none.
 * 2. "Publishes nothing" and "publishes everything" are different texts. On the
 *    header they were the same one: an empty list *meant* all of them, so the
 *    narrowing could not be turned off without silently widening.
 * 3. What leaves is read off the steps, by `publishedSlots`, which is the one
 *    answer the planner, the handoff and the menu all take.
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
  setPublishedSlots,
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

/**
 * That cell as canonical text, which is what every comparison below is against.
 * `splitRecipe` writes `digest` and the canonical spelling is `digest sha-256`,
 * so comparing serialized output to the raw template would be asserting that
 * two different normalisations agree.
 */
const SPLIT_CANON = serializeRecipe(compileRecipe(SPLIT).ast);

/** One cell of canonical text, publishing exactly `labels`. */
const dealerPublishing = (labels) =>
  serializeRecipe({
    chains: [
      {
        peer: "mara",
        steps: setPublishedSlots(compileRecipe(SPLIT).ast.chains[0].steps, labels),
      },
    ],
  });

/** The recipe that could not be written. */
const DEALER = dealerPublishing(["commitments"]);

/** The same cell with every `out` published, which is what a bare `publish` was. */
const WIDE_DEALER = dealerPublishing(["expected", "commitments", "share"]);

const errorsFor = (src) =>
  (compileRecipe(src).validation.errors || []).map((e) => e.message);

/* ─────────────────────── the shape that was blocked ─────────────────────── */

describe("a dealer publishes the commitments and keeps the shares", () => {
  it("is the ceremony's own split cell, unchanged but for one step", () => {
    // If `splitRecipe` stops writing these, this file is testing a shape the
    // product no longer has, and the assertion above it is worthless.
    expect(SPLIT).toContain("vss.commitments | out $commitments");
    expect(SPLIT).toContain("- out $share | qr");
    expect(SPLIT).toContain("digest | encode hex | out $expected");
    // Every one of them is nested — none is a top-level step of the cell.
    expect(SPLIT.split("\n").filter((l) => /^\s*\|?\s*out /.test(l))).toEqual([]);
    expect(DEALER).toContain("- vss.commitments | out $commitments | publish");
  });

  it("compiles", () => {
    expect(errorsFor(DEALER)).toEqual([]);
    expect(errorsFor(WIDE_DEALER)).toEqual([]);
  });

  it("publishes exactly the commitments", () => {
    const { ast } = compileRecipe(DEALER);
    const chain = ast.chains[0];
    expect(chain.peer).toBe("mara");
    expect(publishedSlots(chain)).toEqual(["commitments"]);
    // And no header field says anything about it any more — one representation.
    expect(chain.publish).toBeUndefined();
    expect(chain.publishSlots).toBeUndefined();
  });

  it("plans without a refusal, where publishing all three cannot", () => {
    const named = planRun(compileRecipe(DEALER), { me: "mara", roster: ROSTER });
    expect(named.refusals).toEqual([]);
    expect(named.cells[0].publishes).toEqual(["commitments"]);
    // The cell still *produces* all three: publishing is about what leaves,
    // not about what the cell writes.
    expect(named.cells[0].produces).toEqual(["expected", "commitments", "share"]);

    // The same cell publishing everything is refused, and names `$share` as
    // the reason — which is the correct answer to "publish all of this".
    const all = planRun(compileRecipe(WIDE_DEALER), { me: "mara", roster: ROSTER });
    expect(all.refusals.map((r) => r.reason)).toEqual(["publish-secret"]);
    expect(all.refusals[0].actual).toContain("$share");
  });

  it("names the narrower disclosure outright, and what it names is this one", () => {
    // The refusal used to elide it — "name only what may leave
    // (`@mara publish=$…`)" — which is a remedy the reader has to derive
    // before they can take it, and on a cell with nothing else to publish it
    // is not a remedy at all. This cell writes three things, two of which may
    // leave, so what it should carry is knowable and gets written out.
    //
    // The assertion takes the message at its word: the step it names is
    // written into the cell and planned. Nothing here spells the expected
    // answer twice — if `publishability` and this suggestion ever disagree,
    // the plan below refuses and this fails.
    const all = planRun(compileRecipe(WIDE_DEALER), { me: "mara", roster: ROSTER });
    const narrowed = all.refusals[0].message.match(/`(out \$[^`]+ \| publish)`\)/)?.[1];
    expect(narrowed).toBeTruthy();
    expect(narrowed).not.toContain("$share");
    const label = narrowed.replace(/^out \$| \| publish$/g, "");
    const fixed = `@mara\n${serializeRecipe({
      chains: [
        {
          steps: setPublishedSlots(compileRecipe(SPLIT).ast.chains[0].steps, [label]),
        },
      ],
    })}`;
    expect(errorsFor(fixed)).toEqual([]);
    expect(planRun(compileRecipe(fixed), { me: "mara", roster: ROSTER }).refusals).toEqual([]);
  });
});

/* ───────────────── the sentence that was not true (fix 1) ───────────────── */

describe("`publish` stands on an `out` at any depth", () => {
  it("no longer tells a cell full of nested `out`s that it has none", () => {
    // The old message said "the cell has no `out`" about a cell with three of
    // them, because it looked only at the cell's top-level steps. A `publish`
    // is written *beside* the `out` it means, so the question cannot be asked
    // at the wrong depth: `- vss.commitments | out $commitments | publish` is
    // one line, and the branch it sits in is where it is read from.
    expect(errorsFor(WIDE_DEALER)).toEqual([]);
    expect(publishedSlots(compileRecipe(WIDE_DEALER).ast.chains[0])).toEqual([
      "expected",
      "commitments",
      "share",
    ]);
  });

  it("refuses a `publish` with no `out` in front of it", () => {
    // The state that replaces "this cell writes nothing": the value is real
    // and nameless, and a handoff is addressed by slot label.
    expect(errorsFor("@alice\nrandom 32 | inspect | publish")[0]).toMatch(
      /`inspect` does not name one/
    );
    expect(errorsFor("@alice\nrandom 32 | publish")[0]).toMatch(
      /`random` does not name one/
    );
  });

  it("refuses a `publish` with no peer to send from", () => {
    expect(errorsFor("random 32 | out $a | publish")[0]).toMatch(
      /needs a peer to send it from/
    );
  });

  it("publishes nothing at all when the step before it is not an `out`", () => {
    // Not the same assertion as the refusal above, and the difference is the
    // whole reason `publishedSlots` checks rather than trusting the compiler.
    // The notebook *holds* recipes that parse and do not type-check —
    // `applyCellRecipeText` accepts them on purpose, so the cell's own banner
    // can name the problem — and `ToolkitShell` and `planRun` both ask what
    // those cells publish while they are in that state.
    //
    // `text` is the case that bites: its positional param is called `name`,
    // exactly like `out`'s. A reader of "the step before it" that did not
    // insist on an `out` would answer `$text` here, and a plan would list a
    // slot no `out` registers as leaving this machine.
    const { ast } = parseRecipe("@mara\nrandom 32 | text | publish");
    expect(ast.chains[0].steps.map((s) => s.name)).toEqual([
      "random",
      "text",
      "publish",
    ]);
    expect(ast.chains[0].steps[1].params.name).toBe("text");
    expect(publishedSlots(ast.chains[0])).toEqual([]);
    expect(errorsFor("@mara\nrandom 32 | text | publish")[0]).toMatch(
      /`text` does not name one/
    );
  });
});

/* ─────────────────────────── what it keeps in ───────────────────────────── */

describe("publishing one slot keeps every other slot of that cell in", () => {
  // `$expected` rather than `$share` because a `foreach` body registers its
  // `out` per item (`$share1`…), so `$expected` is the withheld slot a second
  // cell can actually name. The ownership question is the same one.
  const READS_EXPECTED = `${DEALER}\n\n@okafor\nin $expected | out $back`;

  it("makes the unpublished slots private to the peer that wrote them", () => {
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

  it("and publishing everything does not — which is the hazard", () => {
    // Same notebook, disclosure widened. `$expected` becomes everybody's, and
    // okafor's cell plans cleanly. This is the assertion that says what a
    // narrow disclosure withholds rather than what it lets out.
    const wide = `${WIDE_DEALER}\n\n@okafor\nin $expected | out $back`;
    const plan = planRun(compileRecipe(wide), { me: "okafor", roster: ROSTER });
    const row = plan.cells[1].consumes.find((c) => c.label === "expected");
    expect(row.private).toBe(false);
  });
});

/* ────────────────────────────── round trip ──────────────────────────────── */

describe("the disclosure survives every trip a recipe takes", () => {
  it("serializes back to the cell it was read from", () => {
    const { ast } = compileRecipe(DEALER);
    expect(serializeRecipe(ast)).toBe(DEALER);
    // Idempotent: the canonical text of the canonical text is itself.
    const once = serializeRecipe(ast);
    expect(serializeRecipe(compileRecipe(once).ast)).toBe(once);
  });

  it("reads the compact spelling a `#r=` link carries", () => {
    // A flat cell, because compacting a *nested* body is broken for reasons
    // that have nothing to do with disclosure — `tee{ - a - b }` space-joins
    // two branches into one and does not re-parse. What is under test here is
    // that the claim survives the link, and a flat cell tests exactly that.
    const flat = "@mara\nrandom 32 | encode hex | out $hex | publish";
    const compact = compactRecipeText(flat);
    expect(compact).toContain("|publish");
    const back = parseRecipe(expandShareRecipe(decodeSharePayload(encodeSharePayload(compact))));
    expect(back.errors).toEqual([]);
    expect(publishedSlots(back.ast.chains[0])).toEqual(["hex"]);
    expect(serializeRecipe(back.ast)).toBe(flat);
  });

  it("carries more than one", () => {
    const two = dealerPublishing(["expected", "commitments"]);
    const { ast } = compileRecipe(two);
    expect(publishedSlots(ast.chains[0])).toEqual(["expected", "commitments"]);
    expect(serializeRecipe(ast)).toBe(two);
    expect(errorsFor(two)).toEqual([]);
  });

  it("keeps publishing nothing distinguishable from publishing everything", () => {
    // The property the header could not have. An empty list *was* the bare
    // `publish`, so the two ends of the range shared one spelling and the
    // narrower one was unreachable from a control that could only empty a list.
    const none = compileRecipe(dealerPublishing([])).ast.chains[0];
    expect(publishedSlots(none)).toEqual([]);
    expect(publishedSlots(compileRecipe(WIDE_DEALER).ast.chains[0])).toHaveLength(3);
    expect(serializeRecipe({ chains: [none] })).not.toBe(WIDE_DEALER);
  });
});

/* ───────────────────────── what the retired form does ───────────────────── */

describe("the retired header still reads, and converges on the step", () => {
  it("rewrites `publish=$a` into a step on that `out`", () => {
    const old = `@mara publish=$commitments\n${SPLIT}`;
    expect(errorsFor(old)).toEqual([]);
    const { ast } = compileRecipe(old);
    expect(publishedSlots(ast.chains[0])).toEqual(["commitments"]);
    // One pass, and the text is the new text — a link written before the
    // change opens into the notebook it meant, and digests as the notebook
    // anybody writing it today would have.
    expect(serializeRecipe(ast)).toBe(DEALER);
  });

  it("rewrites a bare `publish` into one step per `out`", () => {
    const { ast } = compileRecipe(`@mara publish\n${SPLIT}`);
    expect(publishedSlots(ast.chains[0])).toEqual([
      "expected",
      "commitments",
      "share",
    ]);
    expect(serializeRecipe(ast)).toBe(WIDE_DEALER);
  });

  it("still refuses a name the cell does not write", () => {
    const [message] = errorsFor(`@mara publish=$commitment\n${SPLIT}`);
    expect(message).toMatch(/\$commitment/);
    expect(message).toMatch(/does not write/);
  });

  it("still refuses `publish=` with nothing after it", () => {
    expect(errorsFor(`@mara publish=\n${SPLIT}`)[0]).toMatch(/names the slots/);
  });

  it("still requires the `$`, so a bare word cannot be mistaken for a step", () => {
    expect(errorsFor(`@mara publish=commitments\n${SPLIT}`)[0]).toMatch(/\$commitments/);
  });

  it("still refuses a cell that writes nothing at all", () => {
    expect(errorsFor("@alice publish\nrandom 32 | inspect")[0]).toMatch(/has no `out`/);
  });
});

/* ──────────────────────────────── handoff ───────────────────────────────── */

describe("an unpublished slot does not ride out in a handoff", () => {
  /**
   * okafor's cell writes two things and publishes one. mara's copy of the
   * notebook publishes both, so *her plan* calls both of them public.
   *
   * That disagreement is the only way to reach this guard, and it is exactly
   * the case it exists for: a peer whose ownership analysis says a value may
   * travel, asking for one the recipe kept in. An honest plan of the narrow
   * notebook refuses mara's reader long before a handoff — which is the
   * planner doing its job, and no reason for the boundary to be unchecked.
   */
  const NARROW = `@mara
bytes deadbeef | encode hex | out $seed | publish

@okafor
in $seed | decode hex | encode base64 | out $b64 | publish | decode base64 | encode hex | out $hex

@mara
in $b64 | out $one

@mara
in $hex | out $two`;
  const WIDE = NARROW.replace("| out $hex", "| out $hex | publish");

  const manifestFor = async (src) => {
    const chains = planChains(compileRecipe(src));
    return buildRunManifest({
      title: "handoff",
      recipeSource: src,
      peers: ROSTER,
      cells: chains.map((chain, i) => ({
        index: i,
        peer: String(chain.peer || ""),
        publish: publishedSlots(chain).length > 0,
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

  it("hands over the slot the cell publishes, and refuses the other", async () => {
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
 * claim only the source view can type is the same defect again, so the path
 * from the menu to the chain is pinned here.
 *
 * Source assertions because the suite is `environment: "node"` and cannot
 * mount a component — and because the defect is a *missing* argument, which no
 * rendering of the correct output would have caught.
 */
describe("the menu can write the disclosure, not only the source view", () => {
  const read = (rel) =>
    readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

  it("hands the published slots out of CellAssign", () => {
    const src = read("../toolkit/widgets/CellAssign.tsx");
    // Two arguments: who runs it, and what leaves. A callback that dropped the
    // second would leave the control able to publish everything and nothing
    // else — which is the state the header form was stuck in.
    expect(src).toMatch(
      /onAssign:\s*\(\s*peer:\s*string\s*\|\s*null,\s*publishSlots:\s*string\[\]\s*\)/
    );
    expect(src).toContain("outSlots");
  });

  it("gives it the cell's own out slots, at any depth, and reads back the same way", () => {
    const src = read("../toolkit/ToolkitShell.tsx");
    // `outSlotLabels` rather than a local walk: the menu must offer exactly the
    // labels a `publish` can stand behind, and one walker answers both.
    expect(src).toContain("outSlots={outSlotLabels(chain.steps || [])}");
    // And `publishedSlots` rather than a second reading of the steps, so the
    // menu cannot show one answer while the plan acts on another.
    expect(src).toContain("publishSlots={publishedSlots(chain as RecipeChain)}");
    expect(src).toMatch(/setCellPeer\(i,\s*peer,\s*publishSlots\)/);
  });

  it("carries them into the chain through the recipe layer", () => {
    const src = read("../toolkit/useNotebook.ts");
    const start = src.indexOf("const setCellPeer");
    expect(start).toBeGreaterThan(-1);
    const body = src.slice(start, src.indexOf("[]\n  );", start));
    // The same edit `serializeRecipe` would make from text — nothing here
    // writes recipe source, and nothing here decides a second time which `out`
    // a `publish` belongs behind.
    expect(body).toContain("setPublishedSlots(chain.steps || []");
    // Cleared with the peer: a value sent to nobody is not a claim about
    // anything, and a cell that kept a `publish` would not compile.
    expect(body).toContain("peer ? publishSlots : []");
  });

  it("makes the edit the source view makes, and it round-trips", () => {
    // The library half of the assertion above, which is real behaviour rather
    // than a source match: the menu's edit produces the text a person writing
    // the cell by hand would produce.
    const base = compileRecipe(SPLIT).ast.chains[0];
    const edited = {
      peer: "mara",
      steps: setPublishedSlots(base.steps, ["commitments"]),
    };
    expect(serializeRecipe({ chains: [edited] })).toBe(DEALER);
    // And back off again, to the cell with no disclosure at all.
    const cleared = { peer: "mara", steps: setPublishedSlots(edited.steps, []) };
    expect(serializeRecipe({ chains: [cleared] })).toBe(`@mara\n${SPLIT_CANON}`);
  });
});
