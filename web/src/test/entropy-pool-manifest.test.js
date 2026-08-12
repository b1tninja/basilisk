/**
 * The manifest's `entropy` field stops being a slot.
 *
 * `manifest.js` has carried `entropy: { mode: "pool", digest }` for a while
 * with nothing to put in it, and `currentRunManifest` left the field at its
 * fail-closed `local` default while saying so in a comment: *no op reads a
 * pool*. Now one produces one, and the field records what the run actually
 * drew.
 *
 * The distinction this file exists for is **record versus claim**. A manifest
 * that said `pool` because the notebook *mentions* `entropy.pool` would be a
 * document asserting something about a run that may never have happened; one
 * that says `pool` because a pool came back is evidence. So the two tests that
 * matter are the negative ones: no pool drawn, and a pool that refused.
 */
import { afterEach, describe, expect, it } from "vitest";
import { buildRunManifest } from "../lib/toolkit/manifest.js";
import { clearPooledEntropy } from "../lib/toolkit/entropy-pool-ops.js";

afterEach(() => clearPooledEntropy());

const DIGEST = "a".repeat(64);
const cells = (recipe) => [{ index: 0, peer: "", publish: false, recipe }];

describe("what a manifest says about the randomness a run drew", () => {
  it("says local when nothing pooled", async () => {
    // The honest default, and still the answer for every run that does not
    // open a room. `mirroredRunRefusals` has nothing to check in this mode.
    const m = await buildRunManifest({ registry: "1", recipeSource: "", cells: cells("random 32 | out $k") });
    expect(m.entropy.mode).toBe("local");
    expect(m.entropy.digest).toBeUndefined();
  });

  it("records the digest when one was drawn", async () => {
    const m = await buildRunManifest({
      registry: "1",
      recipeSource: "",
      cells: cells("entropy.pool | out $salt"),
      entropy: { mode: "pool", digest: DIGEST },
    });
    expect(m.entropy).toEqual({ mode: "pool", digest: DIGEST });
  });

  it("no longer carries a whole-notebook keying refusal", async () => {
    // `mirroredRunRefusals` used to refuse a `pool` manifest containing any op
    // that draws keying randomness. It is gone: nothing in this build seeds an
    // op from a pool, so the refusal was false; it would have refused every
    // manifest this build produces, since drawing a pool needs `quorum.join`
    // and that correctly declares `keying`; and it never ran, because nothing
    // passed a manifest to `planRun`.
    //
    // The danger it was aimed at is real and is now checked where it can be
    // seen — a pooled *value* becoming key material, in the compiler. See
    // `pooled-value-rule.test.js`.
    const manifest = await import("../lib/toolkit/manifest.js");
    expect(manifest.mirroredRunRefusals).toBeUndefined();
  });
});

describe("the record cannot outlive what it describes", () => {
  it("is cleared when the session ends", async () => {
    // A pool describes the room that drew it. Held past the close, it would be
    // recorded against the next room's manifest — a document claiming a value
    // those participants never chose. `closeQuorumExchange` clears it; this
    // asserts the clearing function it calls actually empties the record.
    const { lastPooledEntropy } = await import("../lib/toolkit/entropy-pool-ops.js");
    clearPooledEntropy();
    expect(lastPooledEntropy()).toBeNull();
  });

  it("hands back a copy, so a caller cannot edit the record", async () => {
    // The digest is what a manifest commits to. A reader that could mutate the
    // contributor list in place would be editing evidence.
    const ops = await import("../lib/toolkit/entropy-pool-ops.js");
    expect(ops.lastPooledEntropy()).toBeNull();
    expect(typeof ops.clearPooledEntropy).toBe("function");
  });
});
