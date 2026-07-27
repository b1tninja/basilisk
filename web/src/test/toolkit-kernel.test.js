/**
 * Notebook kernel: slots across cell runs, replace on re-run, clearSensitive.
 */
import { describe, expect, it, vi, beforeEach } from "vitest";
import { generateKey, readKey } from "openpgp";
import { createKernel, runChain } from "../lib/toolkit/kernel.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { recipientsPipelineValue } from "../lib/toolkit/recipients-ops.js";

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("slot registry", () => {
  it("lists metas without armor", () => {
    const reg = createSlotRegistry();
    reg.register("@priv", {
      type: "openpgp-key",
      data: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSECRET\n-----END PGP PRIVATE KEY BLOCK-----",
      meta: { which: "private", fingerprint: "A".repeat(40), sensitive: true },
    });
    const metas = reg.listMetas();
    expect(metas).toHaveLength(1);
    expect(metas[0].label).toBe("priv");
    expect(JSON.stringify(metas)).not.toMatch(/PRIVATE KEY|SECRET/);
  });
});

describe("kernel cell runs", () => {
  it("carries @slots from cell 0 into cell 1 encrypt", async () => {
    const alice = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ email: "alice@example.com" }],
      format: "armored",
    });
    const pub = await readKey({ armoredKey: alice.publicKey });
    const fpr = pub.getFingerprint().toUpperCase();

    const kernel = createKernel();
    const recipients = recipientsPipelineValue([
      {
        fingerprint: fpr,
        armoredPublic: alice.publicKey,
        label: "Alice",
        email: "alice@example.com",
        approvalState: "approved",
        valid: true,
        encryptCapable: true,
      },
    ]);

    // Seed as if cell 0 wrote out @alices
    kernel.slots.register("@alices", recipients);

    // Single-cell compile can't see kernel @alices — notebook validates the full AST.
    const encSteps = [
      {
        name: "input",
        params: {},
        start: 0,
        end: 0,
      },
      {
        name: "gpg.encrypt",
        params: { to: "@alices", mode: "separate", policy: "ask", sign: false },
        start: 0,
        end: 0,
      },
    ];
    const arts = await kernel.runCell(1, encSteps, {
      inputs: { text: { value: "hello notebook" } },
    });
    expect(arts.some((a) => String(a.content).includes("BEGIN PGP MESSAGE"))).toBe(
      true
    );
    expect(kernel.getCellStatus(1)).toBe("ok");
  }, 60_000);

  it("marks downstream stale after re-run", async () => {
    const kernel = createKernel();
    const cell0 = compileRecipe(`random 16 | hex | out @x`);
    await kernel.runCell(0, cell0.ast.chains[0]);
    const cell1 = compileRecipe(`in @x | out @y`);
    await kernel.runCell(1, cell1.ast.chains[0]);
    expect(kernel.getCellStatus(1)).toBe("ok");

    await kernel.runCell(0, cell0.ast.chains[0]);
    expect(kernel.getCellStatus(1)).toBe("stale");
    expect(kernel.staleCellIndices()).toEqual([1]);
  });

  it("clearSensitive wipes slots and outputs but leave API ready", async () => {
    const kernel = createKernel();
    const cell0 = compileRecipe(`random 8 | hex | out @x`);
    await kernel.runCell(0, cell0.ast.chains[0]);
    expect(kernel.slotCount()).toBe(1);
    expect(kernel.getCellOutputs(0).length).toBeGreaterThan(0);
    kernel.clearSensitive();
    expect(kernel.slotCount()).toBe(0);
    expect(kernel.getCellOutputs(0)).toEqual([]);
    expect(kernel.getCellStatus(0)).toBe("idle");
  });

  it("runChain helper returns registry", async () => {
    const { artifacts, slots } = await runChain(
      compileRecipe(`random 8 | hex | out @n`).ast.chains[0]
    );
    expect(artifacts.length).toBeGreaterThan(0);
    expect(slots.has("@n")).toBe(true);
  });

  it("remapCells + markAllWithOutputsStale after reorder", async () => {
    const kernel = createKernel();
    await kernel.runCell(0, compileRecipe(`random 8 | hex | out @a`).ast.chains[0]);
    await kernel.runCell(1, compileRecipe(`in @a | out @b`).ast.chains[0]);
    expect(kernel.getCellStatus(1)).toBe("ok");
    // Swap 0 ↔ 1
    kernel.remapCells((i) => (i === 0 ? 1 : i === 1 ? 0 : i));
    kernel.markAllWithOutputsStale();
    expect(kernel.getCellStatus(0)).toBe("stale");
    expect(kernel.getCellStatus(1)).toBe("stale");
    expect(kernel.getCellOutputs(0).length).toBeGreaterThan(0);
    expect(kernel.getCellOutputs(1).length).toBeGreaterThan(0);
  });
});
