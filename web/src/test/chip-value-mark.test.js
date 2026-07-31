/**
 * The mark on a pipeline chip encodes one thing, and only appears when it
 * has something to say.
 *
 * `ToolboxDot` was carrying two orthogonal encodings at once: its *shape*
 * said what kind of value the step emits (§25a — address, session, live
 * channel, observe-only) and its *colour* said which toolbox the step came
 * from. On a chip the colour was the redundant half — the chip's own label
 * reads `gpg.encrypt` or `sss.split`, naming the toolbox in words right
 * beside it — and for the great majority of steps, which emit ordinary DATA,
 * the shape channel was blank. So every chip carried a dot and most of those
 * dots distinguished nothing. Measured on /toolkit-widgets before the change:
 * 28 chips, 28 dots, 0 of them shaped.
 *
 * Presence is the signal now. A mark means "not an ordinary data value",
 * which is worth interrupting a reader for; the colour survives only there,
 * where the originating toolbox is genuinely extra information and where a
 * 5px hollow ring needs the contrast to be visible at all.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { shapeForType } from "../toolkit/widgets/Glyph";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const CHIP = read("../toolkit/widgets/SuggestChip.tsx");
const GLYPH = read("../toolkit/widgets/Glyph.tsx");

describe("shapeForType decides whether a chip is marked at all", () => {
  it("marks the four non-DATA kinds", () => {
    expect(shapeForType("candidate")).toBe("candidate");
    expect(shapeForType("session")).toBe("session");
    expect(shapeForType("channel")).toBe("channel");
    expect(shapeForType("stats")).toBe("connState");
  });

  it("leaves ordinary data unmarked", () => {
    for (const t of ["bytes", "text", "key", "keypair", "artifact", undefined]) {
      expect(shapeForType(t), `${t} should not be marked`).toBeUndefined();
    }
  });
});

describe("SuggestChip", () => {
  it("renders the dot only when the value kind is non-DATA", () => {
    expect(CHIP).toMatch(/const marked = !!op && !!shapeForType\(op\.output\);/);
    expect(CHIP).toMatch(/\{op && marked \? <ToolboxDot op=\{op\} \/> : null\}/);
  });
});

describe("a shaped mark has a name; a bare colour dot does not", () => {
  it("names each kind in words", () => {
    // The shape is a private code otherwise — nothing on the chip says what
    // a hollow ring means, and a screen reader got nothing at all.
    for (const kind of ["candidate", "session", "channel", "connState"]) {
      expect(GLYPH, `KIND_LABEL missing ${kind}`).toMatch(
        new RegExp(`${kind}:\\s*"[^"]+"`)
      );
    }
  });

  it("keeps the unshaped dot out of the accessibility tree", () => {
    expect(GLYPH).toMatch(/aria-hidden=\{label \? undefined : true\}/);
    expect(GLYPH).toMatch(/role=\{label \? "img" : undefined\}/);
  });
});
