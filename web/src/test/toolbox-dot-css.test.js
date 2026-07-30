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

/** @returns {Map<string, string>} toolbox id → colour from the stylesheet */
function cssDotColors() {
  const out = new Map();
  // Selector groups may share one block: capture every id before the brace.
  const re = /((?:\.toolbox-dot\[data-toolbox-dot="[\w-]+"\],?\s*)+)\{\s*background:\s*([^;]+);/g;
  for (const m of CSS.matchAll(re)) {
    const ids = [...m[1].matchAll(/data-toolbox-dot="([\w-]+)"/g)].map((x) => x[1]);
    for (const id of ids) out.set(id, m[2].trim());
  }
  return out;
}

describe("toolbox dot colours agree between registry and stylesheet", () => {
  const fromCss = cssDotColors();

  it("every toolbox with a colour has a matching CSS rule", () => {
    const neutral = "#8b949e"; // the .toolbox-dot default — no per-id rule needed
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
});
