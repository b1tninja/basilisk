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
    //
    // Both spellings count, because the tints live in two places now and the
    // invariant is about the *token*, not about which file says it. The three
    // badge tints moved to enumerated `.artifact-badge[data-badge-family]`
    // rules in the polish pass — a ternary naming `key` and `keypair` by hand
    // had left the four key roles added after it tinted as plain text — so
    // reading only the TSX would have quietly stopped guarding them.
    const utilities =
      OUTPUT_LIST.match(/bg-\[color-mix\(in_srgb,var\(--[a-z-]+\)_[^)]*\)/g) || [];
    // The tile's own badge rules, backgrounds only — `toolkit.css` dresses the
    // whole toolkit, and this assertion is about the tile. A *border* may
    // carry a literal anyway: `.artifact-action[data-action-tier="outward"]`
    // sets 55% deliberately, and its contrast argument is about an outline
    // against a surface, not about a tint sitting under text.
    const rules = (TOOLKIT_CSS.match(/\.artifact-badge\[[^{]*\{[^}]*\}/g) || [])
      .flatMap((block) => block.match(/background:\s*color-mix\([^)]*\)[^;]*/g) || []);
    expect(utilities.length + rules.length).toBeGreaterThan(3);
    for (const t of utilities) expect(t, t).toMatch(/var\(--tile-tint\)/);
    for (const r of rules) expect(r, r).toMatch(/var\(--tile-tint\)/);
  });

  it("tints the whole key badge family as one, in one rule set", () => {
    // The defect this guards: `KIND_GLYPHS` gives all six key roles the same
    // `KeyRound`, but the tint was a ternary that named two of them, so
    // PUBLIC-KEY, SECRET-KEY, SSH-PUBLIC and SSH-PRIVATE rendered in the same
    // rgb(88,166,255) as TEXT and RECEIPT while wearing a key. Measured after:
    // all six at rgb(76,222,130), 8.74:1 on rgb(13,17,23).
    for (const family of ["key", "diag", "plain"]) {
      expect(TOOLKIT_CSS, family).toMatch(
        new RegExp(`\\.artifact-badge\\[data-badge-family="${family}"\\]`)
      );
    }
    // The tile asks the shared helper rather than deciding for itself — which
    // is what makes a newly added key role impossible to miss.
    expect(OUTPUT_LIST).toMatch(/data-badge-family=\{badgeFamily\(a\.kind\)\}/);
  });

  it("keeps the disabled mark above the 3:1 floor it is the sole carrier of", () => {
    // A disabled inert action is pixel-identical to an enabled one apart from
    // this underline — same colour, no border, no fill — so it is the "visual
    // information required to identify the state" 1.4.11 sets a floor for.
    // Measured on rgb(13,17,23): 60% gave 2.96:1, 78% gives 4.18:1.
    const rule = TOOLKIT_CSS.match(/\.artifact-action:disabled\s*\{[\s\S]*?\n\}/);
    expect(rule, "disabled rule not found").toBeTruthy();
    const pct = rule[0].match(/var\(--muted-foreground\)\s+(\d+)%/);
    expect(pct, "underline tint not found").toBeTruthy();
    expect(Number(pct[1])).toBeGreaterThanOrEqual(78);
    // And it still does not dim: the label is the reason's carrier, and the
    // last polish pass found it at 2.20:1 behind `disabled:opacity-50`.
    expect(rule[0]).toMatch(/opacity:\s*1/);
  });
});
