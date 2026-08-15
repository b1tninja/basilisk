/**
 * Two peers on different builds are told the truth about why they disagree.
 *
 * Old texts converge on load, so two peers on the *same* build always derive
 * the same canonical text and the same manifest digest — that invariant is
 * held elsewhere and nothing here weakens it. But a tab left open across a
 * deploy re-canonicalises the same source under a different registry, derives
 * a different `recipeDigest` and a different `toolchain.ops`, and every offer
 * between the two ends refuses. The refusal was truthful about the digest and
 * wrong about the cause: it said "you two hold different notebooks" and named
 * remedies — re-share, check the text — that cannot work, because the
 * receiving build would just re-spell the text again. `47e7ffa` is this
 * repo's name for that defect: a refusal naming an unperformable remedy.
 *
 * The fact that tells the cases apart already travels: `buildRunManifest`
 * folds `opsRegistryVersion()` — the build's language fingerprint, a function
 * of the build and never of the run — into every manifest as `toolchain.ops`,
 * inside the digest. So whenever a manifest is *in hand* (pasted, imported),
 * a digest mismatch can be attributed: fingerprints differ → two builds,
 * reload the stale tab; fingerprints match → today's refusals, word for word.
 * When no manifest is in hand (`unknown-manifest`, the derived-locally case)
 * the offer carries no fingerprint to compare — a closed-list format question,
 * reported rather than decided here — so that refusal now names both possible
 * states and gives each its performable remedy instead of asserting one.
 */
import { describe, expect, it } from "vitest";
import {
  acceptCellResult,
  acceptHandoffOffer,
  buildOfferFor,
  summarizeHandoff,
} from "../lib/toolkit/handoff.js";
import { planChains, planRun } from "../lib/toolkit/plan.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { buildRunManifest, manifestDigest } from "../lib/toolkit/manifest.js";
import { opsRegistryVersion } from "../lib/toolkit/receipt.js";
import {
  compileRecipe,
  migrateRecipe,
  publishedSlots,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";

const FPR_M = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_O = "91C7E6D5C4B3A29180716253443526170819AABB";
const ROSTER = { mara: FPR_M, okafor: FPR_O };

/** mara writes a value into the room; okafor's cell reads it. */
const HANDED = `@mara
bytes deadbeef | encode hex | out $seed | publish

@okafor
in $seed | decode hex | encode base64 | out $b64
`;

/**
 * What another build's registry fingerprint looks like: same shape, different
 * hash — the value `opsRegistryVersion()` returns on a build whose language
 * moved. A constant rather than a computed value, because the test's whole
 * premise is that the other end's registry is one this build cannot compute.
 */
const FOREIGN_REGISTRY = "ops-0-00000000";

/** A digest another canonicalisation of the same cell would produce. */
const FOREIGN_CELL_DIGEST = "f".repeat(64);

/** @param {string} src */
const compile = (src) => compileRecipe(migrateRecipe(src).recipe);

/**
 * A manifest for a notebook, optionally under another build's registry.
 * `registry` is `buildRunManifest`'s own escape hatch for exactly this: the
 * manifest a *different* build derives differs from ours in `toolchain.ops`
 * (always) and in cell digests (whenever canonical spelling moved).
 * @param {string} src
 * @param {{ registry?: string }} [opts]
 */
function manifestFor(src, opts = {}) {
  const chains = planChains(compile(src));
  return buildRunManifest({
    title: "handoff",
    recipeSource: migrateRecipe(src).recipe,
    peers: ROSTER,
    registry: opts.registry,
    cells: chains.map((chain, i) => ({
      index: i,
      peer: String(chain.peer || ""),
      publish: publishedSlots(chain).length > 0,
      recipe: serializeRecipe({ chains: [chain] }),
    })),
  });
}

/** @param {string} src @param {string} me */
function planFor(src, me) {
  return planRun(compile(src), { me, roster: ROSTER });
}

/**
 * mara runs her half of `HANDED` and builds the offer against a given
 * manifest — the sender's side of every case below.
 * @param {import("../lib/toolkit/manifest.js").RunManifest} manifest
 */
async function offerAgainst(manifest) {
  const compiled = compile(HANDED);
  const plan = planFor(HANDED, "mara");
  /** @type {import("../lib/toolkit/placement.js").SkippedCell[]} */
  const skipped = [];
  const registry = createSlotRegistry();
  await runRecipe(
    compiled.ast,
    {},
    { slotRegistry: registry, placement: { plan, onSkip: (s) => skipped.push(s) } }
  ).catch(() => {});
  return buildOfferFor({
    plan,
    compiled,
    manifest,
    skipped: skipped[0],
    readSlot: (label) => (registry.has(label) ? registry.resolve(label) : null),
  });
}

describe("a digest difference is attributed to the build when the manifest can prove it", () => {
  it("refuses `different-build`, naming both fingerprints and the remedy that works", async () => {
    // A manifest from the other build, in hand (pasted or imported): same
    // notebook, foreign registry, and a cell digest its canonicaliser
    // produced. The offer is the one that build sent alongside it.
    const foreign = await manifestFor(HANDED, { registry: FOREIGN_REGISTRY });
    foreign.cells[1] = { ...foreign.cells[1], recipeDigest: FOREIGN_CELL_DIGEST };
    const built = await offerAgainst(await manifestFor(HANDED));
    const bent = {
      ...built.offer,
      manifest: await manifestDigest(foreign),
      cellDigest: FOREIGN_CELL_DIGEST,
    };

    const verdict = await acceptHandoffOffer(bent, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: foreign,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("different-build");
    // Both fingerprints, whole — short enough that nothing needs truncating.
    expect(verdict.refusals[0].message).toContain(FOREIGN_REGISTRY);
    expect(verdict.refusals[0].message).toContain(opsRegistryVersion());
    expect(verdict.refusals[0].message).toContain("Reload");
    // The remedies that cannot work are not named.
    expect(verdict.refusals[0].message).not.toContain("share");
  });

  it("keeps today's `cell-mismatch` wording, word for word, when the fingerprints match", async () => {
    // The control the branch must not swallow: same tampered cell digest, but
    // the manifest was written by *this* build — a genuine text difference on
    // one build, which is exactly what the old sentence describes.
    const samebuild = await manifestFor(HANDED);
    samebuild.cells[1] = { ...samebuild.cells[1], recipeDigest: FOREIGN_CELL_DIGEST };
    const built = await offerAgainst(await manifestFor(HANDED));
    const bent = {
      ...built.offer,
      manifest: await manifestDigest(samebuild),
      cellDigest: FOREIGN_CELL_DIGEST,
    };

    const verdict = await acceptHandoffOffer(bent, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: samebuild,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("cell-mismatch");
    expect(verdict.refusals[0].message).toContain("same number, different text");
  });

  it("attributes a cell-count difference the same way", async () => {
    // The other build's manifest describes a different number of cells — the
    // v1/v2 history shows counting itself can move between builds. With the
    // foreign fingerprint on the document, that is a build fact, not proof of
    // a second notebook.
    const foreign = await manifestFor(`@mara\nbytes 00 | encode hex | out $seed | publish\n`, {
      registry: FOREIGN_REGISTRY,
    });
    const built = await offerAgainst(await manifestFor(HANDED));
    const bent = { ...built.offer, manifest: await manifestDigest(foreign) };

    const verdict = await acceptHandoffOffer(bent, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: foreign,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("different-build");
    expect(verdict.refusals[0].message).toContain(FOREIGN_REGISTRY);
  });

  it("keeps `different-notebook` when the count differs on one build", async () => {
    const other = await manifestFor(`@mara\nbytes 00 | encode hex | out $seed | publish\n`);
    const built = await offerAgainst(await manifestFor(HANDED));
    const bent = { ...built.offer, manifest: await manifestDigest(other) };

    const verdict = await acceptHandoffOffer(bent, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: other,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("different-notebook");
    expect(verdict.refusals[0].message).toContain("not the same notebook");
  });

  it("refuses nothing on a fingerprint difference alone", async () => {
    // The registry moved and this notebook's spelling did not — an unrelated
    // op was added, say. Every digest the acceptance checks still matches, so
    // there is nothing to refuse and nothing new fires: the branch reads the
    // fingerprint only to explain a mismatch, never to invent one.
    const foreign = await manifestFor(HANDED, { registry: FOREIGN_REGISTRY });
    const built = await offerAgainst(foreign);
    expect(built.ok, summarizeHandoff(built)).toBe(true);

    const verdict = await acceptHandoffOffer(built.offer, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: foreign,
    });
    expect(verdict.ok, summarizeHandoff(verdict)).toBe(true);
    expect(verdict.bindings.map((b) => b.label)).toEqual(["seed"]);
  });
});

describe("when no manifest is in hand, the refusal claims no more than it can know", () => {
  /**
   * The case this file was written for, now that the offer format can carry the
   * fact: **the two-state sentence is gone from it, because the state is
   * knowable.**
   *
   * `HANDOFF_VERSION` 3 added `registry`, so an offer written by another build
   * says so, and the `unknown-manifest` branch — the one that could only ever
   * name both worlds — becomes the `different-build` refusal with the remedy
   * that ends it. The offer is stamped `FOREIGN_REGISTRY` rather than built and
   * bent, because that is what `buildOfferFor` running over there would write,
   * and an offer stamped with *this* build's fingerprint would be describing a
   * peer that does not exist in this scenario.
   */
  it("branches to `different-build` when a v3 offer says which build wrote it", async () => {
    const foreign = await manifestFor(HANDED, { registry: FOREIGN_REGISTRY });
    const built = await offerAgainst(foreign);
    expect(built.ok, summarizeHandoff(built)).toBe(true);
    const theirs = { ...built.offer, registry: FOREIGN_REGISTRY };

    const verdict = await acceptHandoffOffer(theirs, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    expect(verdict.ok).toBe(false);
    // Definitive, where it used to be two-state.
    expect(verdict.refusals[0].reason).toBe("different-build");
    const message = verdict.refusals[0].message;
    expect(message).toContain("This offer is against a run manifest this peer has not seen");
    // Both fingerprints, so the reader can check the claim rather than take it.
    expect(message).toContain(FOREIGN_REGISTRY);
    expect(message).toContain(opsRegistryVersion());
    expect(message).toContain("Reload whichever tab is on the older build");
    // The remedy that cannot work must not be offered: re-sharing the notebook
    // is what this build would re-spell straight back into the same refusal,
    // and naming it is `47e7ffa`'s defect.
    expect(message).not.toContain("The notebook itself");
    // And the structural fields say which fact disagreed, not which digest.
    expect(verdict.refusals[0].field).toBe("registry");
    expect(verdict.refusals[0].expected).toBe(opsRegistryVersion());
    expect(verdict.refusals[0].actual).toBe(FOREIGN_REGISTRY);
  });

  /**
   * The case that stays two-state, and the reason it is still right to be.
   *
   * A v2 offer carries no `registry`, and nothing can make it have carried one.
   * Defaulting "absent" to "same build" would turn this into a definite refusal
   * that is wrong exactly when the peer is on the old build — the case where
   * being wrong costs the most — so the sentence keeps naming both states.
   */
  it("still names both states for a v2 offer, which carries no registry", async () => {
    const foreign = await manifestFor(HANDED, { registry: FOREIGN_REGISTRY });
    const built = await offerAgainst(foreign);
    expect(built.ok, summarizeHandoff(built)).toBe(true);
    const { registry: _dropped, ...v2 } = built.offer;
    const theirs = { ...v2, v: 2 };

    const verdict = await acceptHandoffOffer(theirs, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unknown-manifest");
    const message = verdict.refusals[0].message;
    // The anchors other tests and other modules quote survive.
    expect(message).toContain("This offer is against a run manifest this peer has not seen");
    expect(message).toContain("A manifest is derived from the notebook on this machine");
    expect(message).toContain("The notebook itself");
    // Both states, each with the remedy that ends it.
    expect(message).toContain("different builds of Basilisk");
    expect(message).toContain("reload the older tab");
  });

  /**
   * A v3 offer whose registry *agrees* rules the build out, so the sentence
   * says so instead of leaving a reader to wonder. Same refusal reason as the
   * v2 case — the notebook really is what differs — and a different second
   * half, because here that is a fact rather than a guess.
   */
  it("rules the build out when a v3 offer's registry agrees", async () => {
    const built = await offerAgainst(await manifestFor(HANDED, { registry: FOREIGN_REGISTRY }));
    expect(built.offer.registry).toBe(opsRegistryVersion());

    const verdict = await acceptHandoffOffer(built.offer, {
      plan: planFor(HANDED, "okafor"),
      compiled: compile(HANDED),
      manifest: await manifestFor(HANDED),
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unknown-manifest");
    const message = verdict.refusals[0].message;
    expect(message).toContain("Both ends are on the same build");
    // The unreachable remedy is not offered on a build that is not stale.
    expect(message).not.toContain("reload the older tab");
  });

  it("says the same of a result that arrives after a reload", async () => {
    const foreign = await manifestFor(HANDED, { registry: FOREIGN_REGISTRY });
    const result = {
      v: 1,
      kind: "basilisk.cell-result",
      manifest: await manifestDigest(foreign),
      cell: 1,
      cellDigest: (await manifestFor(HANDED)).cells[1].recipeDigest,
      produced: [{ label: "b64", type: "text", data: "3q2+7w==" }],
      ranAt: new Date(0).toISOString(),
    };
    const verdict = await acceptCellResult(result, {
      plan: planFor(HANDED, "mara"),
      compiled: compile(HANDED),
      by: "okafor",
      manifest: await manifestFor(HANDED),
      offered: [],
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unknown-manifest");
    expect(verdict.refusals[0].message).toContain("reloaded into a newer build");
  });
});
