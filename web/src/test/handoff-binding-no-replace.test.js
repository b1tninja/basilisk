/**
 * A handoff binding never replaces a slot, and the flag that said it might is
 * gone.
 *
 * ## The state that was true
 *
 * `useNotebook.ts` registered every accepted handoff binding with
 * `{ allowReplace: true }`. `slot-registry.js` replaces only when
 * `allowReplace` **and** a `preexisting` set containing the key are both
 * supplied, and that call passed no set — so the flag changed nothing. A
 * reader met a call that announced an intention the code could not carry out.
 *
 * ## Why the flag went rather than the set arriving
 *
 * `preexisting` is the engine's, and it means something specific: it is
 * `registry.snapshotKeys()` taken as a *run* begins, so re-running a notebook
 * may overwrite the slots the previous run left, while two `out $x` inside one
 * run still collide. A handoff binding belongs to no run and has no such set to
 * be measured against — there is no honest value to pass.
 *
 * More decisively, completing the flag would have broken the rule the layer
 * above already enforces. `reviewOffer` and `reviewResult` are handed `hasSlot`
 * and both refuse a label this machine already holds, with `slot-present`:
 * "which of the two is right is not a question a result can answer — two peers
 * answering one offer look exactly like this." A refused verdict carries **no
 * bindings at all**, so the registration loop is only ever reached when every
 * label is free. Passing a set would not have repaired a silent failure; it
 * would have installed the overwrite `slot-present` exists to refuse.
 *
 * ## What a person sees on a collision
 *
 * The refusal, named. `acceptHandoff` returns `{ ok: false, why }` from
 * `summarizeHandoff(verdict)` one line before the loop, and `ToolkitShell`
 * puts that sentence in the handoff note. Not a replacement, and not silence.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";

const SHELL = fileURLToPath(new URL("../toolkit/useNotebook.ts", import.meta.url));

const text = (s) => ({ type: "text", data: s, meta: {} });

describe("the flag on its own does nothing, which is what it did here", () => {
  it("refuses a duplicate even when `allowReplace` is set, with no `preexisting`", () => {
    // The reproduction. This is exactly the call `useNotebook.ts` made, and it
    // is indistinguishable from passing no options at all.
    const registry = createSlotRegistry();
    registry.register("$a", text("first"));
    expect(() => registry.register("$a", text("second"), { allowReplace: true })).toThrow(
      /Duplicate out slot \$a/
    );
    expect(registry.resolve("$a").data).toBe("first");
  });

  it("refuses identically with no options, so the flag changed nothing", () => {
    const registry = createSlotRegistry();
    registry.register("$a", text("first"));
    expect(() => registry.register("$a", text("second"))).toThrow(/Duplicate out slot \$a/);
    expect(registry.resolve("$a").data).toBe("first");
  });

  it("replaces when the set that means it is supplied — the control", () => {
    // This must survive every mutation aimed at the two above. It is the proof
    // that the replace path works and that the assertions above are about the
    // *caller*, not about a registry that cannot replace at all.
    const registry = createSlotRegistry();
    registry.register("$a", text("first"));
    registry.register("$a", text("second"), {
      allowReplace: true,
      preexisting: new Set(["a"]),
    });
    expect(registry.resolve("$a").data).toBe("second");
  });

  it("still refuses when the set is supplied but does not hold the key", () => {
    // `preexisting` is a set of the keys a run began with, so a label created
    // *during* the run is absent from it and stays a collision. This is the
    // distinction the handoff caller had no way to draw.
    const registry = createSlotRegistry();
    registry.register("$a", text("first"));
    expect(() =>
      registry.register("$a", text("second"), {
        allowReplace: true,
        preexisting: new Set(["b"]),
      })
    ).toThrow(/Duplicate out slot \$a/);
  });
});

describe("the shell no longer claims a replacement it cannot perform", () => {
  it("registers accepted handoff bindings with no options at all", () => {
    // The absence pin. A deletion that only removes a word is one the next
    // reader restores; this fails if `allowReplace` returns to the shell.
    const source = readFileSync(SHELL, "utf8");
    const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
    expect(code).not.toMatch(/allowReplace/);
    expect(code).toMatch(/slots\.register\(b\.label,\s*b\.value\)/);
  });
});
