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
    // `\s+` rather than one space: the assertion is that a `<code>` element
    // carries the class, and the element grew a second attribute (`title`, so
    // a truncated label is still readable) and with it a line break. A regex
    // that also pins the formatting is a regex that fails on a prettier run.
    expect(OUTPUT_LIST).toMatch(/<code\s+className="artifact-label/);
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

  /**
   * The sensitivity axis (§35, sensitivity pass).
   *
   * The family rules above are right and stay: six key roles wear one glyph,
   * so they take one hue. But that was the *only* axis the badge had, so a
   * PUBLIC-KEY and an SSH-PRIVATE rendered identically at rgb(76,222,130) —
   * one commit's correct fix leaving the more expensive confusion in place.
   *
   * Measured on the built page, dark rgb(13,17,23) unless stated:
   *   secret badge text  6.47:1  (5.76:1 light)
   *   ring, outside edge 4.21:1  (3.49:1 light)
   *   ring, inside edge  3.56:1  (3.18:1 light)
   *   public badge text  8.71:1  (4.67:1 light) — unchanged
   */
  it("splits the key family by sensitivity, in a second enumerated attribute", () => {
    expect(TOOLKIT_CSS).toMatch(/\.artifact-badge\[data-badge-tier="secret"\]/);
    // The family rules survive intact — this is an extension, not a rewrite.
    for (const family of ["key", "diag", "plain"]) {
      expect(TOOLKIT_CSS, family).toMatch(
        new RegExp(`\\.artifact-badge\\[data-badge-family="${family}"\\]`)
      );
    }
    // The tile asks the shared helper for both, so a new role or a new kind
    // cannot acquire a hue by accident at the call site.
    expect(OUTPUT_LIST).toMatch(/data-badge-family=\{badgeFamily\(a\.kind\)\}/);
    expect(OUTPUT_LIST).toMatch(
      /data-badge-tier=\{badgeTier\(resolvedKind\.sensitivity, a\.sensitive\)\}/
    );
  });

  it("says the kind's name but keeps colouring by the role", () => {
    // The two answer different questions. The chip's *text* is a name, and
    // the role was the wrong one — a TOTP code badged TEXT. The chip's *hue*
    // answers "is this key material" and "is it secret", which the role is
    // still the right input for. Repointing the attributes at the rendered
    // string would tie a colour to a name.
    expect(OUTPUT_LIST).toMatch(/\{badgeNameFor\(resolvedKind, a, a\.kind\)\}/);
    expect(OUTPUT_LIST).toMatch(/data-badge-family=\{badgeFamily\(a\.kind\)\}/);
    expect(OUTPUT_LIST).toMatch(
      /data-badge-tier=\{badgeTier\(resolvedKind\.sensitivity, a\.sensitive\)\}/
    );
    // And the glyph follows the kind, falling back to the role. It was
    // declared on fourteen kinds and rendered by none, so a `token` drew no
    // glyph while declaring `signature`.
    expect(OUTPUT_LIST).toMatch(/<KindGlyph kind=\{resolvedKind\.glyph \|\| a\.kind\} \/>/);
  });

  it("does not let colour be the only carrier of the axis (1.4.1)", () => {
    // A reader who cannot separate the two hues still has to be able to
    // separate a private key from a public one. Three non-colour channels:
    // the ring, the weight step, and the word — in the badge for four of the
    // six roles, and in the `sensitive` chip for `KEY` and `KEYPAIR`, which
    // name no half. This asserts the two that live in CSS.
    const rule = TOOLKIT_CSS.match(
      /\.artifact-badge\[data-badge-tier="secret"\]\s*\{[\s\S]*?\n\}/
    );
    expect(rule, "secret tier rule not found").toBeTruthy();
    // A ring, not a border: a border would make the secret badge 2px larger
    // than the public one and reflow the row. Measured: both 18.4px tall.
    expect(rule[0]).toMatch(/box-shadow:\s*inset 0 0 0 1px/);
    expect(rule[0]).not.toMatch(/^\s*border:/m);
    expect(rule[0]).toMatch(/font-weight:\s*600/);
  });

  it("leaves exactly one amber, meaning one thing", () => {
    // The standing complaint was three ambers with three meanings on one row:
    // the `sensitive` chip (`--accent` gold, ΔE 9.6 from `--warn`), `Reveal`
    // (a `--warn` outline) and `Publish` (the outward tier's `--warn`
    // outline). The first two now speak `--secret`, so `--warn` is left
    // saying only "this leaves the machine".
    const secretRules = ["\\.artifact-sensitive", "\\.artifact-reveal"];
    for (const sel of secretRules) {
      const rule = TOOLKIT_CSS.match(new RegExp(`${sel}\\s*\\{[\\s\\S]*?\\n\\}`));
      expect(rule, `${sel} rule not found`).toBeTruthy();
      expect(rule[0], sel).toMatch(/var\(--secret\)/);
      expect(rule[0], `${sel} must not wear the outward tier's amber`).not.toMatch(
        /var\(--warn\)/
      );
    }
    // Reveal's outline is its whole boundary, so it clears 3:1: 45% measured
    // 2.44:1 dark and 2.23:1 light — carried over from a hue with a different
    // luminance. 65% gives 3.85:1 and 3.35:1.
    const reveal = TOOLKIT_CSS.match(/\.artifact-reveal\s*\{[\s\S]*?\n\}/)[0];
    const pct = reveal.match(/border:[^;]*var\(--secret\)\s+(\d+)%/);
    expect(pct, "Reveal border tint not found").toBeTruthy();
    expect(Number(pct[1])).toBeGreaterThanOrEqual(65);
  });

  it("defines --secret in both themes, and never identity-maps it", () => {
    expect(SITE_CSS).toMatch(/--secret:\s*#e879f9/);
    const light = SITE_CSS.match(/@media \(prefers-color-scheme: light\)[\s\S]*?\n\}/);
    expect(light[0]).toMatch(/--secret:\s*#a21caf/);
    // `--x: var(--x)` in this stylesheet once killed a shared token page-wide.
    expect(SITE_CSS).not.toMatch(/--secret:\s*var\(--secret\)/);
  });

  it("keeps the disabled mark above the 3:1 floor it is the sole carrier of", () => {
    // A disabled inert action is pixel-identical to an enabled one apart from
    // this underline — same colour, no border, no fill — so it is the "visual
    // information required to identify the state" 1.4.11 sets a floor for.
    // Measured on rgb(13,17,23): 60% gave 2.96:1, 78% gives 4.18:1.
    // Keyed on `aria-disabled` since the refusal became keyboard-reachable —
    // `disabled` was what removed the button from the tab order, and with it
    // the `aria-describedby` sentence that is the whole feature. The treatment
    // is unchanged; only the selector moved.
    const rule = TOOLKIT_CSS.match(/\.artifact-action\[aria-disabled="true"\]\s*\{[\s\S]*?\n\}/);
    expect(rule, "disabled rule not found").toBeTruthy();
    const pct = rule[0].match(/var\(--muted-foreground\)\s+(\d+)%/);
    expect(pct, "underline tint not found").toBeTruthy();
    expect(Number(pct[1])).toBeGreaterThanOrEqual(78);
    // And it still does not dim: the label is the reason's carrier, and the
    // last polish pass found it at 2.20:1 behind `disabled:opacity-50`.
    expect(rule[0]).toMatch(/opacity:\s*1/);
  });
});
