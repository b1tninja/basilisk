/**
 * Companion preset stitch rules (explicit @slots; no new grammar).
 */
import { describe, expect, it } from "vitest";
import {
  bridgeModeMeta,
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

/**
 * Whether the recipe loads `label` from a slot anywhere.
 *
 * Asserted on the parsed AST, not the text: `in @ct` and the bare `@ct`
 * serialize differently but parse to the identical `in` step, and the
 * serializer deliberately prefers the bare form (RECIPE.md's own
 * multi-chain examples are written that way). These tests used to
 * string-match `in @ct` and so failed on a printer change that broke
 * nothing — what they mean to assert is which slot the reverse chain
 * consumes.
 * @param {string} recipe
 * @param {string} label e.g. "@ct"
 */
function loadsSlot(recipe, label) {
  const { ast } = compileRecipe(recipe);
  const want = label.replace(/^@/, "");
  return (ast?.chains || []).some((chain) =>
    (chain.steps || []).some(
      (s) =>
        s.name === "in" &&
        String(s.params?.ref || "").replace(/^@/, "") === want
    )
  );
}

describe("bridgeSlotName", () => {
  it("produces a valid @label from pair ids", () => {
    expect(bridgeSlotName("slip39-secret")).toBe("@slip39_secret");
    expect(bridgeSlotName("123bad")).toBe("@p_123bad");
    expect(bridgeSlotName("")).toBe("@bridge");
  });
});

describe("bridgeModeMeta", () => {
  it("returns distinct copy for slot vs inputs", () => {
    expect(bridgeModeMeta("slot", "@payload").badge).toBe("Slot bridge");
    expect(bridgeModeMeta("slot", "@payload").toast).toContain("@payload");
    expect(bridgeModeMeta("inputs").badge).toBe("Shares panel");
    expect(bridgeModeMeta("inputs").hint.toLowerCase()).toContain("shares");
    expect(bridgeModeMeta("as-is").badge).toBe("Linked slots");
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
      recipe: "random 16 | encode hex | out @ct",
    };
    const reverse = {
      id: "rev",
      pair: "demo",
      title: "rev",
      recipe: "in @ct | decode hex | base64url | out @plain",
    };
    const st = stitchPresetPair(forward, reverse);
    expect(st.mode).toBe("as-is");
    expect(st.bridge).toBe("@ct");
    expect(loadsSlot(st.recipe, "@ct")).toBe(true);
  });

  it("rewrites reverse input → in @bridge when forward ends with out", () => {
    const forward = {
      id: "fwd",
      pair: "slot-demo",
      title: "fwd",
      recipe: "random 16 | encode hex | out @payload",
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
    expect(loadsSlot(st.recipe, "@payload")).toBe(true);
    expect(st.recipe).not.toMatch(/^input\b/m);
    // to hex text → utf8 encodes to bytes → base64url is valid after stitch
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
      recipe: "random 16 | encode hex",
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
    expect(loadsSlot(st.recipe, "@need_out")).toBe(true);
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
