/**
 * The status light beside an op reports CAST, not toolbox identity.
 *
 * `suite-gate.js` had no callers at all: the self-test result was computed on
 * boot and never shown next to the ops it qualifies, while the dot that used
 * to carry it had been repurposed as a per-toolbox colour. That is worse than
 * no indicator — a green dot meaning "SSS toolbox" is indistinguishable from
 * a green dot meaning "SSS self-tested clean", so the safety signal read as
 * present while being absent.
 *
 * These tests pin the split: glyph = identity, dot = verification.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { GLYPH_PATHS } from "../lib/toolkit/glyphs.js";
import { toolboxVerification } from "../lib/toolkit/suite-gate.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const GLYPH = read("../toolkit/widgets/Glyph.tsx");
const SHELF = read("../toolkit/widgets/OpsShelf.tsx");
const TILE = read("../toolkit/widgets/OpsTile.tsx");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const CSS = read("../css/toolkit.css");

describe("CastDot reports the self-test", () => {
  it("is wired to the suite gate rather than the toolbox palette", () => {
    expect(GLYPH).toMatch(/import \{ toolboxVerification \}/);
    expect(GLYPH).toMatch(/export function CastDot/);
  });

  it("renders nothing for toolboxes that make no CAST claim", () => {
    // An indicator that is always lit and never means anything is how the
    // original signal was lost. Only openpgp/webcrypto/sss are self-tested.
    expect(toolboxVerification("encoding", { openpgp: "verified" })).toBe("none");
    expect(GLYPH).toMatch(/if \(state === "none"\) return null;/);
  });

  it("distinguishes verified, unverified and error", () => {
    const status = { openpgp: "verified", webcrypto: "error", sss: "unverified" };
    expect(toolboxVerification("openpgp", status)).toBe("verified");
    expect(toolboxVerification("webcrypto", status)).toBe("error");
    expect(toolboxVerification("sss", status)).toBe("unverified");
  });

  it("colours each state from the stylesheet, not an inline style", () => {
    expect(CSS).toMatch(/\.cast-dot\[data-cast="verified"\][^}]*var\(--success\)/);
    expect(CSS).toMatch(/\.cast-dot\[data-cast="unverified"\][^}]*var\(--warn\)/);
    expect(CSS).toMatch(/\.cast-dot\[data-cast="error"\][^}]*var\(--error\)/);
  });

  it("is fed real status from the shell, not left permanently null", () => {
    // The dot renders nothing without a status map, so an unwired prop would
    // look exactly like the regression it fixes.
    expect(SHELL).toMatch(/castStatus=\{suiteStatus\}/);
    expect(SHELF).toMatch(/castStatus\?: Record<string, string> \| null;/);
  });
});

describe("identity moved to the glyph", () => {
  it("shelf rows and pair tiles both render an op glyph", () => {
    expect(SHELF).toMatch(/<Glyph id=\{glyphIdFor\(op\)\}/);
    expect(TILE).toMatch(/<Glyph\s+id=\{glyphIdFor\(op\)\}/);
  });

  it("gives encrypt and decrypt distinct glyphs", () => {
    // Both pointed at `gpg-encrypt`, so the two halves of the most
    // consequential pair in the toolkit looked identical.
    const registry = read("../lib/toolkit/registry.js");
    expect(registry).toMatch(/"gpg\.encrypt": "gpg-encrypt"/);
    expect(registry).toMatch(/"gpg\.decrypt": "gpg-decrypt"/);
  });

  it("draws direction handles with encode/decode glyphs", () => {
    expect(TILE).toMatch(/<Glyph id="encode"/);
    expect(TILE).toMatch(/<Glyph id="decode"/);
  });

  it("ships those three glyphs", () => {
    for (const id of ["gpg-decrypt", "encode", "decode"]) {
      expect(GLYPH_PATHS[id], `missing glyph ${id}`).toBeTruthy();
    }
  });
});

describe("one shape for one gesture", () => {
  it("sizes the solo add button like a direction handle", () => {
    // A wide "add" pill next to 22×20 arrow squares presented two different
    // controls for the same action, and implied the arrows did something else.
    const add = SHELF.match(/function AddButton[\s\S]{0,900}?\n\}/);
    expect(add, "AddButton not found").toBeTruthy();
    expect(add[0]).toMatch(/h-5 w-\[22px\]/);
    expect(add[0]).not.toMatch(/>\s*add\s*</);
  });
});
