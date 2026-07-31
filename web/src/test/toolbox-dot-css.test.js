/**
 * The CSP conversion's one real cost: toolbox colours now live twice — in
 * TOOLBOX_META (registry.js, drives glyph tints etc.) and as enumerated
 * `.toolbox-dot[data-toolbox-dot=…]` rules in toolkit.css (CSS cannot read
 * JS under `style-src 'self'`). This test is the drift guard: recolour or
 * add a toolbox in the registry and it fails until the stylesheet agrees.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TOOLBOX_META } from "../lib/toolkit/registry.js";

const CSS = readFileSync(
  fileURLToPath(new URL("../css/toolkit.css", import.meta.url)),
  "utf8"
);

/**
 * Two selector families carry the palette — `.toolbox-dot` (shelf headers,
 * `background`) and `.toolbox-shape` (ToolboxDot, `color`, so the filled dot,
 * the hollow ring and the channel triangle can all paint with
 * `currentColor`). Both are checked, so neither can drift from the registry
 * or from each other.
 *
 * @param {"dot"|"shape"} family
 * @returns {Map<string, string>} toolbox id → colour from the stylesheet
 */
function cssColors(family) {
  const out = new Map();
  const sel = family === "dot" ? "toolbox-dot" : "toolbox-shape";
  const attr = family === "dot" ? "data-toolbox-dot" : "data-toolbox";
  const prop = family === "dot" ? "background" : "color";
  // Selector groups may share one block: capture every id before the brace.
  const re = new RegExp(
    `((?:\\.${sel}\\[${attr}="[\\w-]+"\\],?\\s*)+)\\{\\s*${prop}:\\s*([^;]+);`,
    "g"
  );
  for (const m of CSS.matchAll(re)) {
    const ids = [...m[1].matchAll(new RegExp(`${attr}="([\\w-]+)"`, "g"))].map((x) => x[1]);
    for (const id of ids) out.set(id, m[2].trim());
  }
  return out;
}

describe.each([["dot"], ["shape"]])(
  "toolbox %s colours agree between registry and stylesheet",
  (family) => {
    const fromCss = cssColors(family);

    it("every toolbox with a colour has a matching CSS rule", () => {
      const neutral = "#8b949e"; // the family's default — no per-id rule needed
      const mismatches = [];
      for (const [id, meta] of Object.entries(TOOLBOX_META)) {
        const want = (meta.color || neutral).toLowerCase();
        const got = (fromCss.get(id) || neutral).toLowerCase();
        if (want !== got) mismatches.push(`${id}: registry ${want}, css ${got}`);
      }
      expect(mismatches, mismatches.join("\n")).toEqual([]);
    });

    it("the stylesheet names no toolbox the registry lacks", () => {
      const unknown = [...fromCss.keys()].filter((id) => !(id in TOOLBOX_META));
      expect(unknown, unknown.join(", ")).toEqual([]);
    });
  }
);

describe("ToolboxDot shapes are painted, not inlined", () => {
  it("keeps the observe-only ring hollow and the channel triangle border-drawn", () => {
    // The two shapes that are not a plain filled dot; both previously carried
    // the colour in a style prop the production CSP refuses.
    expect(CSS).toMatch(
      /\.toolbox-shape\[data-kind="connState"\]\s*\{[^}]*border:\s*1\.5px solid currentColor/
    );
    expect(CSS).toMatch(
      /\.toolbox-shape\[data-kind="channel"\]\s*\{[^}]*border-bottom:\s*6px solid currentColor/
    );
  });
});

describe("file picker scaffolding survives the global file-input rule", () => {
  const SITE_CSS = readFileSync(
    fileURLToPath(new URL("../css/site.css", import.meta.url)),
    "utf8"
  );

  it("still hides bare file inputs site-wide", () => {
    // The rule this guard exists because of. If it ever goes away the
    // `display: block` below stops being load-bearing, but it does no harm.
    expect(SITE_CSS).toMatch(/input\[type=["']?file["']?\]\s*\{[^}]*display:\s*none/);
  });

  it("declares display explicitly for the picker, at winning specificity", () => {
    // `display: none` makes an input click-inert in some engines, which would
    // silently break `file.read`'s <input type=file> fallback on exactly the
    // browsers that have no File System Access API. Measured in the live page
    // and pinned here; a stubbed-DOM unit test cannot see cascade bugs.
    const block = CSS.match(
      /\[data-basilisk-file-picker\][\s\S]*?\{([\s\S]*?)\}/
    );
    expect(block, "no [data-basilisk-file-picker] rule in toolkit.css").toBeTruthy();
    expect(block[1]).toMatch(/display:\s*block/);
    expect(block[1]).toMatch(/opacity:\s*0/);
    // Compound selector so it outranks `input[type=file]` (0,1,1).
    expect(CSS).toContain('input[type="file"][data-basilisk-file-picker]');
  });
});
