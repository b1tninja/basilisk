/**
 * Companion preset stitch rules (explicit @slots; no new grammar).
 */
import { describe, expect, it } from "vitest";
import {
  bridgeSlotName,
  collectConsumedSlots,
  collectOutLabels,
  lastChainFinalOut,
  listPresetPairs,
  resolvePresetPair,
  stitchPresetPair,
} from "../lib/toolkit/conjugate-stitch.js";
import {
  canonicalizeRecipe,
  compileRecipe,
  PRESETS,
} from "../lib/toolkit/recipe.js";

describe("bridgeSlotName", () => {
  it("produces a valid @label from pair ids", () => {
    expect(bridgeSlotName("slip39-secret")).toBe("@slip39_secret");
    expect(bridgeSlotName("123bad")).toBe("@p_123bad");
    expect(bridgeSlotName("")).toBe("@bridge");
  });
});

describe("listPresetPairs", () => {
  it("finds forward/reverse for each PRESETS pair id", () => {
    const pairs = listPresetPairs();
    expect(pairs.length).toBeGreaterThanOrEqual(4);
    const secret = pairs.find((p) => p.id === "slip39-secret");
    expect(secret?.forward.id).toBe("slip39-split");
    expect(secret?.reverse.id).toBe("recover-shares");
    expect(resolvePresetPair("slip39-pem-envelope")?.forward.id).toBe(
      "pem-envelope-split"
    );
  });

  it("every pair member exists in PRESETS", () => {
    for (const p of listPresetPairs()) {
      expect(PRESETS.some((x) => x.id === p.forward.id)).toBe(true);
      expect(PRESETS.some((x) => x.id === p.reverse.id)).toBe(true);
    }
  });
});

describe("stitchPresetPair", () => {
  it("marks SSS recover pairs as inputs bridge (unchanged sources)", () => {
    const pair = resolvePresetPair("slip39-secret");
    expect(pair).toBeTruthy();
    const st = stitchPresetPair(pair.forward, pair.reverse);
    expect(st.mode).toBe("inputs");
    expect(st.bridge).toBeNull();
    expect(st.recipe).toContain("random 32");
    expect(st.recipe).toMatch(/^[\s\S]*shares\s*\|/m);
    expect(compileRecipe(st.recipe).validation.ok).toBe(true);
  });

  it("keeps as-is when reverse already consumes a forward out", () => {
    const forward = {
      id: "fwd",
      pair: "demo",
      title: "fwd",
      recipe: "random 16 | hex | out @ct",
    };
    const reverse = {
      id: "rev",
      pair: "demo",
      title: "rev",
      recipe: "in @ct | hex -d | base64url | out @plain",
    };
    const st = stitchPresetPair(forward, reverse);
    expect(st.mode).toBe("as-is");
    expect(st.bridge).toBe("@ct");
    expect(st.recipe).toContain("in @ct");
  });

  it("rewrites reverse input → in @bridge when forward ends with out", () => {
    const forward = {
      id: "fwd",
      pair: "slot-demo",
      title: "fwd",
      recipe: "random 16 | hex | out @payload",
    };
    const reverse = {
      id: "rev",
      pair: "slot-demo",
      title: "rev",
      recipe: "input | utf8 | base64url | out @b64",
    };
    const st = stitchPresetPair(forward, reverse);
    expect(st.mode).toBe("slot");
    expect(st.bridge).toBe("@payload");
    expect(st.recipe).toContain("in @payload");
    expect(st.recipe).not.toMatch(/^input\b/m);
    // hex text → utf8 encodes to bytes → base64url is valid after stitch
    const { validation } = compileRecipe(st.recipe);
    expect(validation.ok, validation.errors?.[0]?.message).toBe(true);
  });

  it("renames reverse out labels that collide with forward", () => {
    const pair = resolvePresetPair("slip39-pem-envelope");
    expect(pair).toBeTruthy();
    const st = stitchPresetPair(pair.forward, pair.reverse);
    expect(st.mode).toBe("inputs");
    expect(st.recipe).toContain("out @pem");
    expect(st.recipe).toMatch(/out @pem_rev\b/);
    expect(compileRecipe(st.recipe).validation.ok).toBe(true);
  });

  it("appends out @bridge when forward has no final out", () => {
    const forward = {
      id: "fwd",
      pair: "need-out",
      title: "fwd",
      recipe: "random 16 | hex",
    };
    const reverse = {
      id: "rev",
      pair: "need-out",
      title: "rev",
      recipe: "input | utf8 | out @x",
    };
    const st = stitchPresetPair(forward, reverse);
    expect(st.mode).toBe("slot");
    expect(st.bridge).toBe("@need_out");
    expect(st.recipe).toContain("| out @need_out");
    expect(st.recipe).toContain("in @need_out");
  });

  it("collectOutLabels / collectConsumedSlots / lastChainFinalOut", () => {
    const { ast } = canonicalizeRecipe(
      "random 8 | out @a\n\ninput | utf8 | aes-gcm key=@cek | out @ct"
    );
    expect([...collectOutLabels(ast)].sort()).toEqual(["@a", "@ct"]);
    expect([...collectConsumedSlots(ast)].sort()).toEqual(["@cek"]);
    expect(lastChainFinalOut(ast)).toBe("@ct");
  });
});
