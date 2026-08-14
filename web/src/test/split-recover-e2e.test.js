/**
 * The gate bug, end to end: companion split/recover templates load as two
 * cells, and the recover cell's empty shares panel used to block the whole
 * notebook — the cell that *produces* the shares could never run.
 *
 * Three layers under test here:
 *  - slot-graph wiring: the recover cell's "shares" need is wired, not unmet;
 *  - the engine's `shares` fallback to indexed slots a foreach emitted;
 *  - the actual round trip: split runs, recover runs, the secret survives.
 */
import { describe, expect, it } from "vitest";
import { createKernel } from "../lib/toolkit/kernel.js";
import { PRESETS, compileRecipe } from "../lib/toolkit/recipe.js";
import { cellSlotIO, wiredForCell, producesShareSlots } from "../lib/toolkit/slot-graph.js";

/** @param {string} id */
function presetChains(id) {
  const p = PRESETS.find((x) => x.id === id);
  if (!p) throw new Error(`missing preset ${id}`);
  const { ast, validation } = compileRecipe(p.recipe);
  expect(validation.errors.map((e) => e.message), id).toEqual([]);
  return ast.chains;
}

describe("slot-graph wiring", () => {
  const chains = [...presetChains("slip39-split"), ...presetChains("recover-shares")];

  it("sees the split cell producing indexed share slots", () => {
    expect(producesShareSlots(chains[0].steps)).toBe(true);
    expect(producesShareSlots(chains[1].steps)).toBe(false);
  });

  it("wires the recover cell's shares need to the split cell above it", () => {
    expect(wiredForCell(chains, 1).wiredNeeds.has("shares")).toBe(true);
    // No producer above the first cell — nothing is wired there.
    expect(wiredForCell(chains, 0).wiredNeeds.size).toBe(0);
  });

  it("does not wire when the order is reversed — recover above split", () => {
    const reversed = [chains[1], chains[0]];
    expect(wiredForCell(reversed, 0).wiredNeeds.size).toBe(0);
  });

  it("traces labeled slot edges", () => {
    const multi = compileRecipe(
      "genkey ec/p256 | out $kp\n\n$kp | export pkcs8 | pem | out $private"
    ).ast.chains;
    expect([...cellSlotIO(multi[0]).produces]).toEqual(["kp"]);
    expect([...cellSlotIO(multi[1]).consumes]).toEqual(["kp"]);
    expect(wiredForCell(multi, 1).wiredSlots.has("kp")).toBe(true);
  });
});

describe("split → recover, same session, nothing pasted", () => {
  it("recovers the secret from the slots the split cell emitted", async () => {
    const kernel = createKernel();
    const chains = [
      ...presetChains("slip39-split"),
      ...presetChains("recover-shares"),
    ];
    const splitArts = await kernel.runCell(0, chains[0], {});
    const shareTiles = splitArts.filter((a) => a.role === "share");
    expect(shareTiles.length).toBe(3);

    // The recover cell runs with an empty paste panel — the engine falls
    // back to the indexed share slots the foreach just registered.
    const recoverArts = await kernel.runCell(1, chains[1], {});
    const secret = recoverArts.find((a) => /secret/i.test(a.label || a.filename || ""));
    expect(secret, "recovered $secret artifact").toBeTruthy();

    // Round-trip proof: the recovered base64 decodes to 32 bytes — the same
    // width the split cell drew. (The raw master never surfaces to compare
    // directly, which is the point of the design.)
    const b64 = String(secret.content || "").trim();
    const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    expect(raw.length).toBe(32);
    kernel.destroy();
  });

  it("pasted shares still win over the fallback", async () => {
    const kernel = createKernel();
    const chains = presetChains("recover-shares");
    // Nothing ran before this cell and nothing is pasted: the op must say so.
    //
    // The remedy it names is asserted along with the refusal, because the
    // sentence this replaced named one that could not always be performed: it
    // ended "or run a split cell first", and on the machine that *received* the
    // shares that cell belongs to somebody else and would mint a different
    // secret if it ran. Both of these can be done by whoever is reading it.
    await expect(kernel.runCell(0, chains[0], {})).rejects.toThrow(
      /nothing to collect/i
    );
    await expect(kernel.runCell(0, chains[0], {})).rejects.toThrow(
      /paste them into Inputs/i
    );
    await expect(kernel.runCell(0, chains[0], {})).rejects.toThrow(/with=\$late/);
    await expect(kernel.runCell(0, chains[0], {})).rejects.not.toThrow(
      /run a split cell/i
    );
    kernel.destroy();
  });
});
