/**
 * Artifact actions: tiers, disabled reasons, and the mask (§33b/§33d/§34b).
 *
 * The tiers encode what happens if you click — local, durable, or outward and
 * possibly irreversible — so flattening them into equal buttons is how a
 * mis-click becomes unrecoverable. The reason strings are the feature, not an
 * afterthought, which makes both their wording and their *readability* worth
 * asserting.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ACTION_REASONS } from "../lib/toolkit/artifact-reasons.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const ACTION = read("../toolkit/widgets/ArtifactAction.tsx");
const OUTPUT_LIST = read("../toolkit/widgets/OutputList.tsx");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const CSS = read("../css/toolkit.css");

describe("a disabled action always carries a reason (§33d)", () => {
  it("derives disabled from the reason, so the two cannot drift apart", () => {
    // Not two independent props. "Disabled but no reason" should be
    // unrepresentable, because that state is the thing the rule forbids.
    expect(ACTION).toMatch(/const disabled = !!reason;/);
    expect(ACTION).toMatch(/disabled=\{disabled\}/);
  });

  it("exposes the reason to assistive tech, not only as a title", () => {
    // `title` is unreachable by keyboard and by touch, so a title-only reason
    // is a reason most affected users never get.
    expect(ACTION).toMatch(/aria-describedby=\{reasonId\}/);
    expect(ACTION).toMatch(/className="sr-only"/);
  });

  it("writes every reason as a sentence with a remedy where one exists", () => {
    for (const [key, text] of Object.entries(ACTION_REASONS)) {
      expect(text.length, key).toBeGreaterThan(30);
      expect(text, key).toMatch(/[.!]$/);
      // "Unavailable" restates the disabled attribute; it is not a reason.
      expect(text.toLowerCase(), key).not.toBe("unavailable");
    }
  });

  it("keeps the wording verbatim, because the wording is the feature", () => {
    expect(ACTION_REASONS.maskedButRevealable).toBe(
      "Reveal this value first — a masked value cannot be copied."
    );
    expect(ACTION_REASONS.neverAskedFor).toBe(
      "This value was not asked for. Add `out @label` to the recipe to see or copy it."
    );
    expect(ACTION_REASONS.noVault).toBe(
      "My Keys is unavailable in this browser (no IndexedDB)."
    );
    expect(ACTION_REASONS.offline).toBe(
      "Publishing needs a connection to this site's directory."
    );
  });
});

describe("disabled does not dim (§41d)", () => {
  it("holds full-strength muted text instead of halving opacity", () => {
    // The shipped `disabled:opacity-50` puts the reason at 2.20:1 in light.
    // A reason nobody can read is the same as no reason — the exact failure
    // §33d exists to prevent, and the same class of defect the last polish
    // pass found here at 1.97:1 and 1.59:1.
    const rule = CSS.match(/\.artifact-action:disabled\s*\{[^}]*\}/);
    expect(rule, ".artifact-action:disabled rule not found").toBeTruthy();
    expect(rule[0]).toMatch(/opacity:\s*1/);
    expect(rule[0]).toMatch(/color:\s*var\(--muted-foreground\)/);
    expect(rule[0]).toMatch(/cursor:\s*not-allowed/);
    // The affordance is what goes away: no fill, no border.
    expect(rule[0]).toMatch(/background:\s*transparent/);
    expect(rule[0]).toMatch(/border-color:\s*transparent/);
  });

  it("marks that a reason is attached, so it reads as explained not broken", () => {
    const rule = CSS.match(/\.artifact-action:disabled\s*\{[^}]*\}/);
    expect(rule[0]).toMatch(/text-decoration:\s*underline dotted/);
  });
});

describe("the three tiers are declared, not styled per call site (§33b)", () => {
  it("enumerates exactly inert, local and outward", () => {
    const tiers = [...CSS.matchAll(/\.artifact-action\[data-action-tier="([a-z]+)"\]/g)].map(
      (m) => m[1]
    );
    expect([...new Set(tiers)].sort()).toEqual(["inert", "local", "outward"]);
  });

  it("gives outward an outline rather than a fill", () => {
    // The shipped --warn *fill* measures 3.76:1 in light. The outline keeps
    // the promise the colour makes — "this leaves the machine" — without it.
    const outward = CSS.match(/\.artifact-action\[data-action-tier="outward"\]\s*\{[^}]*\}/);
    expect(outward[0]).toMatch(/background:\s*transparent/);
    expect(outward[0]).toMatch(/border-color:\s*color-mix\(in srgb, var\(--warn\)/);
  });

  it("runs its hover tint through the per-theme token", () => {
    expect(CSS).toMatch(
      /\.artifact-action\[data-action-tier="outward"\]:hover[^}]*var\(--tile-tint\)/
    );
  });
});

describe("in-flight is busy, not disabled (§41e)", () => {
  it("uses aria-busy so the accessible name survives", () => {
    // A disabled control loses its accessible name in some screen-reader
    // pairings at exactly the moment the user most wants to know what is
    // happening.
    expect(ACTION).toMatch(/aria-busy=\{busy \|\| undefined\}/);
    expect(ACTION).not.toMatch(/disabled=\{busy/);
  });

  it("slows the spinner under reduced motion rather than freezing it", () => {
    // A frozen spinner reads as a hang.
    const rm = CSS.match(/@media \(prefers-reduced-motion: reduce\)\s*\{[\s\S]*?artifact-action-spin[\s\S]*?\}\s*\}/);
    expect(rm, "reduced-motion rule not found").toBeTruthy();
    expect(rm[0]).toMatch(/animation-duration:\s*2\.4s/);
    expect(rm[0]).not.toMatch(/animation:\s*none/);
  });
});

describe("Copy is gated on the mask, never bypasses it (§34b)", () => {
  it("disables rather than revealing on the user's behalf", () => {
    expect(OUTPUT_LIST).toMatch(/reason=\{copyReason\(a, revealed\.has\(a\.label\)\)\}/);
    // No code path may set `revealed` from inside an action handler — that is
    // the bypass, however convenient.
    const helper = OUTPUT_LIST.match(/function copyReason[\s\S]*?\n\}/);
    expect(helper[0]).not.toMatch(/setRevealed/);
  });

  it("distinguishes 'reveal it first' from 'the recipe never asked'", () => {
    const helper = OUTPUT_LIST.match(/function copyReason[\s\S]*?\n\}/);
    expect(helper[0]).toMatch(/maskedButRevealable/);
    expect(helper[0]).toMatch(/neverAskedFor/);
    expect(helper[0]).toMatch(/a\.revealable && a\.content/);
  });
});

describe("both panes badge an artifact the same way (§33a)", () => {
  it("uses one mapping expression, not two", () => {
    const mappings = [
      ...SHELL.matchAll(/kind: a\.role === "diagnostic" \? "diag" : a\.role \|\| "text"/g),
    ];
    // The cell list and the tray Outputs tab. Previously the cell list added
    // `publishable ? "key"` and collapsed the rest to "text", so the same
    // artifact wore two different badges depending on the pane.
    expect(mappings.length).toBe(2);
  });

  it("no longer re-derives publishability for the badge", () => {
    // `role` already says "public-key"; the ternary was re-deriving it and
    // disagreeing with the other pane.
    expect(SHELL).not.toMatch(/\? "share"[\s\S]{0,120}publishable\s*\n?\s*\? "key"/);
  });
});
