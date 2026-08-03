/**
 * Notebook kernel: slots across cell runs, replace on re-run, clearSensitive.
 */
import { describe, expect, it, vi, beforeEach } from "vitest";
import { generateKey, readKey } from "openpgp";
import { cellRunErrorFrom, createKernel, runChain } from "../lib/toolkit/kernel.js";
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
    const cell0 = compileRecipe(`random 16 | encode hex | out @x`);
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
    const cell0 = compileRecipe(`random 8 | encode hex | out @x`);
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
      compileRecipe(`random 8 | encode hex | out @n`).ast.chains[0]
    );
    expect(artifacts.length).toBeGreaterThan(0);
    expect(slots.has("@n")).toBe(true);
  });

  it("remapCells + markAllWithOutputsStale after reorder", async () => {
    const kernel = createKernel();
    await kernel.runCell(0, compileRecipe(`random 8 | encode hex | out @a`).ast.chains[0]);
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

  it("lockSensitive evicts private slots but keeps public recipients", async () => {
    const alice = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ email: "alice@example.com" }],
      format: "armored",
    });
    const pub = await readKey({ armoredKey: alice.publicKey });
    const fpr = pub.getFingerprint().toUpperCase();
    const kernel = createKernel();
    kernel.slots.register(
      "@alices",
      recipientsPipelineValue([
        {
          fingerprint: fpr,
          armoredPublic: alice.publicKey,
          label: "Alice",
          email: "alice@example.com",
          approvalState: "approved",
          valid: true,
          encryptCapable: true,
        },
      ])
    );
    kernel.slots.register("@me", {
      type: "openpgp-key",
      data: alice.privateKey,
      meta: { which: "private", sensitive: true, fingerprint: fpr },
    });
    await kernel.runCell(0, compileRecipe(`random 8 | encode hex | out @x`).ast.chains[0]);
    expect(kernel.slotCount()).toBe(3);
    kernel.lockSensitive();
    expect(kernel.slots.has("@alices")).toBe(true);
    expect(kernel.slots.has("@me")).toBe(false);
    // Non-sensitive @x may remain; outputs are always wiped.
    expect(kernel.getCellOutputs(0)).toEqual([]);
  }, 60_000);
});

/**
 * A cell that fails says why, in the cell.
 *
 * `runCell` used to keep only the *fact*: `setCellStatus("error")`, timings,
 * and the reason thrown onward to the run bar — one red line above the
 * notebook, outside the cell that failed. `rtc-live-diagnostics` rendered as
 * three empty cells and that one line, none of it attached to `rtc.state`,
 * which is the op that threw and whose message names both ways to fix it.
 */
describe("a failed cell keeps its reason", () => {
  const failing = () => compileRecipe("random 8 | encode hex | pem").ast.chains[0];

  it("records the message, the op and the chip it belongs to", async () => {
    const kernel = createKernel();
    await expect(kernel.runCell(0, failing())).rejects.toThrow(/pem expects bytes/);
    expect(kernel.getCellStatus(0)).toBe("error");
    expect(kernel.getCellRunError(0)).toEqual({
      // Verbatim. A layout that needed this shortened would be the wrong layout.
      message: "pem expects bytes",
      stepIndex: 2,
      stepName: "pem",
    });
    expect(kernel.getCellRunError(1)).toBeNull();
  });

  it("still re-throws, so the run bar and the run loop are unaffected", async () => {
    // Recording the reason must not swallow it: `runFrom` stops the loop on
    // this throw, and the always-visible run bar is what a failure in cell 9
    // of a long notebook is read from.
    const kernel = createKernel();
    let caught = null;
    try {
      await kernel.runCell(0, failing());
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(Error);
    expect(caught.message).toBe(kernel.getCellRunError(0).message);
  });

  it("anchors a nested failure to the stem, the way the validator numbers one", async () => {
    const kernel = createKernel();
    const chain = compileRecipe("random 8 | encode hex | tee\n  - pem\n| out @x").ast
      .chains[0];
    await expect(kernel.runCell(0, chain)).rejects.toThrow();
    const err = kernel.getCellRunError(0);
    // The innermost op is named; the chip is the top-level stem that holds it,
    // because that is the only index a chip exists for.
    expect(err.stepName).toBe("pem");
    expect(err.stepIndex).toBe(2);
    expect(chain.steps[err.stepIndex].name).toBe("tee");
  });

  it("clears the moment the cell runs again, before it is known to succeed", async () => {
    const kernel = createKernel();
    await expect(kernel.runCell(0, failing())).rejects.toThrow();
    expect(kernel.getCellRunError(0)).toBeTruthy();
    await kernel.runCell(0, compileRecipe("random 8 | encode hex | out @x").ast.chains[0]);
    expect(kernel.getCellStatus(0)).toBe("ok");
    expect(kernel.getCellRunError(0)).toBeNull();
  });

  it("survives an upstream re-run, which is not the same as being stale", async () => {
    // Staleness says "computed from something that has since changed", which
    // needs outputs to be stale about. A failed cell has none, and running the
    // cell above it does not undo the last thing that happened in this one.
    const kernel = createKernel();
    await kernel.runCell(0, compileRecipe("random 8 | encode hex | out @x").ast.chains[0]);
    await expect(kernel.runCell(1, failing())).rejects.toThrow();
    await kernel.runCell(0, compileRecipe("random 8 | encode hex | out @x").ast.chains[0]);
    expect(kernel.getCellStatus(1)).toBe("error");
    expect(kernel.getCellRunError(1)?.message).toBe("pem expects bytes");
  });

  it("goes with the outputs on clear, lock and reset", async () => {
    for (const wipe of ["clearCellOutputs", "clearSensitive", "lockSensitive"]) {
      const kernel = createKernel();
      await expect(kernel.runCell(0, failing())).rejects.toThrow();
      expect(kernel.getCellRunError(0), wipe).toBeTruthy();
      if (wipe === "clearCellOutputs") kernel.clearCellOutputs(0);
      else kernel[wipe]();
      expect(kernel.getCellRunError(0), wipe).toBeNull();
    }
  });

  it("moves with the cell on remap, so it cannot land on one that never ran", async () => {
    const kernel = createKernel();
    await kernel.runCell(0, compileRecipe("random 8 | encode hex | out @a").ast.chains[0]);
    await expect(kernel.runCell(1, failing())).rejects.toThrow();
    kernel.remapCells((i) => (i === 0 ? 1 : i === 1 ? 0 : i));
    expect(kernel.getCellRunError(0)?.stepName).toBe("pem");
    expect(kernel.getCellRunError(1)).toBeNull();
  });
});

describe("cellRunErrorFrom", () => {
  it("reads the engine's attribution off the error", () => {
    const err = new Error("boom");
    Object.defineProperty(err, "basiliskStep", { value: "pem" });
    Object.defineProperty(err, "basiliskStepIndex", { value: 3 });
    expect(cellRunErrorFrom(err)).toEqual({ message: "boom", stepIndex: 3, stepName: "pem" });
  });

  it("says something rather than nothing when a throw carries no message", () => {
    expect(cellRunErrorFrom(new Error(""))).toEqual({
      message: "Run failed",
      stepIndex: -1,
      stepName: "",
    });
    expect(cellRunErrorFrom(undefined).message).toBe("Run failed");
    expect(cellRunErrorFrom("plain string").message).toBe("plain string");
  });

  it("refuses an anchor the engine did not give", () => {
    const err = new Error("boom");
    Object.defineProperty(err, "basiliskStepIndex", { value: -1 });
    expect(cellRunErrorFrom(err).stepIndex).toBe(-1);
    expect(cellRunErrorFrom(new Error("boom")).stepIndex).toBe(-1);
  });
});
