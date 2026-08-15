/**
 * A step's declared `output` and its `effectiveIo` must agree at default params.
 *
 * Both are answers to "what does this step emit", read by different callers:
 * `output` is the flat declaration the ops drawer and `stepAcceptsRefined`
 * consult, `effectiveIo` is the param-aware one the caret consults, and
 * `types.js` carries a third answer for sources. Nothing made them agree.
 *
 * That is not hypothetical. `gpg.decrypt` declared `output: "shares"` while
 * emitting a plaintext, and the declaration was invisible: changing it back to
 * `"shares"` passed all 211 files, because every path that could have noticed
 * asked `effectiveIo` instead. A field nobody reads is a field that can be
 * wrong for as long as it likes, and this one was the first thing a person
 * looking up "what does decrypt emit" would find.
 *
 * Only the default-param case is checked, and deliberately so — `count=all`
 * *should* differ from the flat `output`, since saying so is what
 * `effectiveIo` is for. What must hold is that the two describe the same step
 * when nobody has asked for anything unusual.
 */
import { describe, expect, it } from "vitest";
import { STEPS } from "../lib/toolkit/registry.js";

/** @param {*} spec */
function defaultParams(spec) {
  return Object.fromEntries((spec.params || []).map((p) => [p.name, p.default]));
}

describe("effectiveIo agrees with the flat declaration", () => {
  const withIo = STEPS.filter((s) => typeof s.effectiveIo === "function");

  it("covers the steps that have one", () => {
    // A sweep that swept nothing would pass in silence.
    expect(withIo.length).toBeGreaterThan(20);
  });

  it("output matches at default params, for every step", () => {
    const drift = [];
    for (const spec of withIo) {
      const io = spec.effectiveIo(defaultParams(spec));
      if (io.output !== spec.output) {
        drift.push(`${spec.name}: output=${spec.output}, effectiveIo=${io.output}`);
      }
    }
    expect(
      drift,
      `${drift.join("; ")}. The flat \`output\` is what the ops drawer reads; ` +
        `when it disagrees with \`effectiveIo\` the two surfaces describe ` +
        `different steps, and only one of them is right.`
    ).toEqual([]);
  });

  it("input matches at default params too", () => {
    const drift = [];
    for (const spec of withIo) {
      const io = spec.effectiveIo(defaultParams(spec));
      if (io.input !== undefined && spec.input !== undefined && io.input !== spec.input) {
        drift.push(`${spec.name}: input=${spec.input}, effectiveIo=${io.input}`);
      }
    }
    expect(drift, drift.join("; ")).toEqual([]);
  });

  it("gpg.decrypt emits text by default and a bundle only when asked", () => {
    // The step the sweep exists for, pinned by name so a future edit to it has
    // to face this file.
    const spec = STEPS.find((s) => s.name === "gpg.decrypt");
    expect(spec.output).toBe("text");
    expect(spec.effectiveIo({ count: "1" }).output).toBe("text");
    expect(spec.effectiveIo({}).output).toBe("text");
    expect(spec.effectiveIo({ count: "all" }).output).toBe("bundle");
    expect(spec.effectiveIo({ count: "3" }).output).toBe("bundle");
  });
});
