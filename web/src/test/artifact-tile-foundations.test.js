/**
 * The two corrections the artifact tile is built on (§39b/§39c,
 * design_handoff_artifact_actions/visual).
 *
 * Both are cascade and contrast facts that a unit test can only guard at the
 * source level — the real proof is `getComputedStyle` in the built page, and
 * both were measured there. What these assert is that the mechanism stays in
 * place, because both failures were invisible: text rendered at the wrong size
 * for as long as the tile has existed, and every badge tone sat below the
 * contrast floor in light without anything complaining.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SITE_CSS = read("../css/site.css");
const TOOLKIT_CSS = read("../css/toolkit.css");
/**
 * The tile's markup, wherever it lives. §33a lifted the anatomy out of
 * `OutputList` into `ArtifactTile`; reading both is what keeps these
 * assertions about the *rendered tile* rather than about a filename, so a
 * later move cannot quietly take their teeth out by leaving an empty file
 * behind that still matches nothing.
 */
const OUTPUT_LIST =
  read("../toolkit/widgets/ArtifactTile.tsx") + read("../toolkit/widgets/OutputList.tsx");

describe("the tile's mono text obeys a type scale (§39b)", () => {
  it("sizes tile code by scoped rule, because the global one outranks utilities", () => {
    // site.css sets an *unlayered* `code { font-size: .78rem }`; Tailwind
    // utilities live in @layer utilities, and unlayered beats layered
    // regardless of specificity. Measured in the built page: label 11px,
    // body 10px, and a control <span> with the same class also 11px.
    expect(TOOLKIT_CSS).toMatch(/\[data-output-list\] code\.artifact-label\s*\{[^}]*font-size:\s*11px/);
    expect(TOOLKIT_CSS).toMatch(/\[data-output-list\] code\.artifact-body\s*\{[^}]*font-size:\s*10px/);
  });

  it("leaves the global code rule alone", () => {
    // It serves every non-toolkit page; narrowing it would be felt far
    // outside the tile, and this change has no mandate over those pages.
    expect(SITE_CSS).toMatch(/\bcode\s*\{[^}]*font-size:\s*0?\.78rem/);
  });

  it("marks the elements that need the scale", () => {
    expect(OUTPUT_LIST).toMatch(/code className="artifact-label/);
    expect(OUTPUT_LIST).toMatch(/artifact-body/);
    // The body must not also carry a utility size — it would lose to the
    // global rule and reintroduce the inversion it just fixed, silently.
    expect(OUTPUT_LIST).not.toMatch(/artifact-label[^"]*text-\[\d/);
    expect(OUTPUT_LIST).not.toMatch(/artifact-body[^"]*text-\[\d/);
  });
});

describe("small tinted surfaces clear the contrast floor in both themes (§39c)", () => {
  it("defines --tile-tint per theme", () => {
    expect(SITE_CSS).toMatch(/--tile-tint:\s*12%/);
    expect(SITE_CSS).toMatch(/--tile-tint:\s*6%/);
  });

  it("sets the light value inside the light-scheme block", () => {
    const light = SITE_CSS.match(/@media \(prefers-color-scheme: light\)[\s\S]*?\n\}/);
    expect(light, "light block not found").toBeTruthy();
    expect(light[0]).toMatch(/--tile-tint:\s*6%/);
  });

  it("routes every tile tint through the token, not a literal percentage", () => {
    // Measured in light: badges went 4.38 → 4.77 against a 4.5 floor, and the
    // format tab's 18% measured 4.01. A literal left behind at any call site
    // is a tone that still fails, in the theme nobody develops in.
    const tinted = OUTPUT_LIST.match(/bg-\[color-mix\(in_srgb,var\(--[a-z-]+\)_[^)]*\)/g) || [];
    expect(tinted.length).toBeGreaterThan(3);
    for (const t of tinted) {
      expect(t, t).toMatch(/var\(--tile-tint\)/);
    }
  });
});
