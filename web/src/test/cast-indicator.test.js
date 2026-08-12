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
    // `SuiteStatusMap`, not an open string map: the gate reports three named
    // suites, and the loose spelling was what let the shelf hand `CastDot` a
    // map it could not read.
    expect(SHELF).toMatch(/castStatus\?: SuiteStatusMap \| null;/);
  });

  it("sits on the toolbox header, at the granularity of the claim", () => {
    // The self-test qualifies a suite, so every op under one toolbox carries
    // the same bit. One light where the drawer names the suite; a per-op
    // light would imply a per-op test that does not exist.
    const header = SHELF.match(/function SectionHeader\([\s\S]*?\n\}\r?\n/);
    expect(header, "SectionHeader not found").toBeTruthy();
    expect(header[0]).toMatch(/<CastDot op=\{\{ toolbox \}\} status=\{castStatus\} \/>/);
    expect(SHELF).toMatch(/<SectionHeader[\s\S]{0,300}?castStatus=\{castStatus\}/);
  });

  it("does not repeat itself on every row and tile", () => {
    expect(SHELF.match(/<CastDot/g) || []).toHaveLength(1);
    expect(TILE).not.toMatch(/CastDot/);
  });

  it("is the only mark on the section header", () => {
    // The header also carried a 6px toolbox-identity square at the right
    // margin. On WebCrypto and OpenPGP that put a green circle meaning
    // "self-test passed" and a green rounded square meaning "this is the
    // WebCrypto toolbox" in the same 26px row — the conflation this whole
    // indicator exists to avoid, relocated rather than resolved. The header
    // already names the toolbox in words and every row under it carries an
    // op glyph, so identity was the redundant channel.
    const header = SHELF.match(/function SectionHeader\([\s\S]*?\n\}\r?\n/);
    expect(header, "SectionHeader not found").toBeTruthy();
    expect(header[0]).not.toMatch(/toolbox-dot/);
  });

  it("keeps a collapsed toolbox header readable", () => {
    // `opacity-40` on a zero-fit header took its label to 1.82:1 against the
    // shelf — on the only control that reopens the section. The "0 fit"
    // count is the signal; the dimming was a second, illegible copy of it.
    const header = SHELF.match(/function SectionHeader\([\s\S]*?\n\}\r?\n/)[0];
    expect(header).not.toMatch(/fitCount === 0 && "opacity/);
  });
});

describe("identity moved to the glyph", () => {
  it("shelf rows and pair tiles both render an op glyph", () => {
    // Matched across newlines: both call sites gained a conditional opacity
    // and Prettier wrapped them. The substance is that the glyph id comes
    // from the op, not that the JSX fits on one line.
    expect(SHELF).toMatch(/<Glyph\s[\s\S]{0,80}id=\{glyphIdFor\(op\)\}/);
    expect(TILE).toMatch(/<Glyph\s[\s\S]{0,80}id=\{glyphIdFor\(op\)\}/);
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
    // The window grew with the button's disabled/draggable states; it is
    // bounded by the next top-level declaration rather than a character
    // count so a future addition cannot silently truncate the match.
    const add = SHELF.match(/function AddButton[\s\S]*?\n\}\r?\n/);
    expect(add, "AddButton not found").toBeTruthy();
    expect(add[0]).toMatch(/h-5 w-\[22px\]/);
    expect(add[0]).not.toMatch(/>\s*add\s*</);
  });

  it("lets a solo op be dragged, like the direction handles beside it", () => {
    // The shapes were unified deliberately; leaving one of them undraggable
    // made the identical square mean two different things, on the gesture
    // the pipeline is built around.
    const add = SHELF.match(/function AddButton[\s\S]*?\n\}\r?\n/)[0];
    expect(add).toMatch(/setData\(STEP_MIME/);
    // `!disabled` until the refusal rule landed. The predicate is the same
    // one — a row that does not fit the caret can be neither clicked nor
    // dragged — but it now comes from the reason rather than from a boolean
    // beside it, so a refused handle and a silent one are the same state.
    expect(add).toMatch(/draggable=\{!refusal\.refused && !!dragName\}/);
  });
});
