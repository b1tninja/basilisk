/**
 * Keyboard focus has to be visible, and it has to be one thing.
 *
 * The app used to draw focus four different ways: the UA default on most
 * controls, an app-coloured ring on four hand-picked ones (in three colours
 * — `--brand`, `--accent`, `--caret` — at two offsets), and nothing at all on
 * the pipeline chips, which set `outline: none` and leaned on a border tint
 * that was byte-for-byte their own hover style. A keyboard user could not
 * tell where they were in a recipe.
 *
 * Measured in the production build before the fix: `.suggest-chip-hit` at
 * `outline-style: none` while `:focus-visible` matched. After: 2px solid
 * `--brand`, inset.
 *
 * These are source-level assertions because `:focus-visible` is a UA
 * heuristic jsdom does not implement — there is no DOM assertion that would
 * have caught the regression either.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const CSS = read("../css/site.css");

/**
 * Rule bodies whose selector list mentions `:focus-visible` — the keyboard
 * ring specifically. Plain `:focus` on a text field is a different idiom:
 * an always-visible box may show focus by recolouring its own border and
 * shadow, and several fields here legitimately do.
 */
function focusVisibleRules(css) {
  const out = [];
  const re = /([^{}]*:focus-visible[^{}]*)\{([^}]*)\}/g;
  let m;
  while ((m = re.exec(css.replace(/\/\*[\s\S]*?\*\//g, ""))))
    out.push({ selector: m[1].trim(), body: m[2] });
  return out;
}

describe("one focus ring", () => {
  it("declares the ring once, at low specificity, from a token", () => {
    expect(CSS).toMatch(
      /:focus-visible\s*\{\s*outline:\s*2px solid var\(--focus-ring\);\s*outline-offset:\s*2px;\s*\}/
    );
  });

  it("defines --focus-ring in both themes", () => {
    // Light overrides every other state colour for AA on white; a ring that
    // only existed in dark would be exactly the sort of half-fix this
    // replaces.
    const light = CSS.slice(CSS.indexOf("@media (prefers-color-scheme: light)"));
    expect(CSS).toMatch(/--focus-ring:\s*var\(--brand\);/);
    expect(light).toMatch(/--focus-ring:\s*var\(--brand\);/);
  });

  it("never cancels the ring without replacing it", () => {
    // `outline: none` inside a :focus rule is the exact shape of the bug.
    const offenders = focusVisibleRules(CSS)
      .filter(({ body }) => /outline(-style)?:\s*none/.test(body))
      .map(({ selector }) => selector);
    expect(offenders).toEqual([]);
  });

  it("leaves only offsets, not colours, to individual components", () => {
    // A component may tighten the ring against its own edge. Redeclaring the
    // colour is how three rings in three colours happened.
    const colours = focusVisibleRules(CSS)
      .filter(({ selector, body }) => selector !== ":focus-visible" && /outline:\s*\d/.test(body))
      .map(({ selector }) => selector);
    expect(colours).toEqual([]);
  });
});

describe("hover is not a semantic channel", () => {
  it("tints chips with --interactive rather than the shared-secret gold", () => {
    // `--accent` is documented as the SSS surface and lands within a few
    // percent of `--warn`, so a hovered chip rendered as a chip in its
    // warning state.
    const block = CSS.match(/\.suggest-chip:hover\s*\{[^}]*\}/);
    expect(block, ".suggest-chip:hover not found").toBeTruthy();
    expect(block[0]).toMatch(/var\(--interactive\)/);
    expect(block[0]).not.toMatch(/--accent/);
    expect(block[0]).not.toMatch(/--warn/);
  });

  it("keeps hover and focus in separate rules so a chip can be both", () => {
    expect(CSS).not.toMatch(/\.suggest-chip:hover,\s*\r?\n\.suggest-chip:focus-visible/);
  });

  it("defines --interactive in both themes, distinct from --accent", () => {
    const dark = CSS.slice(0, CSS.indexOf("@media (prefers-color-scheme: light)"));
    const light = CSS.slice(CSS.indexOf("@media (prefers-color-scheme: light)"));
    for (const [name, scope] of [
      ["dark", dark],
      ["light", light],
    ]) {
      const interactive = scope.match(/--interactive:\s*(#[0-9a-f]{6})/i);
      const accent = scope.match(/--accent:\s*(#[0-9a-f]{6})/i);
      expect(interactive, `--interactive missing in ${name}`).toBeTruthy();
      expect(interactive[1].toLowerCase()).not.toBe(accent[1].toLowerCase());
    }
  });
});
