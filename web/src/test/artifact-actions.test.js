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
import { ARTIFACT_ACTIONS, actionById, actionsFor } from "../lib/toolkit/artifact-actions.js";
import "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { ARTIFACT_KINDS } from "../toolkit/artifact-kinds/registry.tsx";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const ACTION = read("../toolkit/widgets/ArtifactAction.tsx");
const OUTPUT_LIST = read("../toolkit/widgets/OutputList.tsx");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const CSS = read("../css/toolkit.css");
const SRC = read("../lib/toolkit/artifact-actions.js");

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
  // Asserted against the table, which is where the decision lives now —
  // behaviourally, so a refactor of the tile cannot silently drop it.
  const copy = actionById("copy");

  it("is available on an unmasked artifact", () => {
    expect(copy.available({ artifact: { content: "x" }, masked: false })).toBe(true);
  });

  it("disables rather than revealing on the user's behalf", () => {
    const out = copy.available({
      artifact: { content: "secret", revealable: true },
      masked: true,
    });
    expect(out).not.toBe(true);
    expect(out.disabled).toBe(ACTION_REASONS.maskedButRevealable);
    // No code path may lift the mask from inside an action.
    expect(SRC).not.toMatch(/setRevealed|revealed\s*=\s*true/);
  });

  it("distinguishes 'reveal it first' from 'the recipe never asked'", () => {
    const revealable = copy.available({
      artifact: { content: "secret", revealable: true },
      masked: true,
    });
    const never = copy.available({
      artifact: { content: "secret", revealable: false },
      masked: true,
    });
    expect(revealable.disabled).toBe(ACTION_REASONS.maskedButRevealable);
    expect(never.disabled).toBe(ACTION_REASONS.neverAskedFor);
  });

  it("copies through the artifact's own handler, not a re-implementation", async () => {
    // The shipped handler fires the clipboard toast and knows this
    // artifact's serialization; the table exists to make gating uniform,
    // not to rewrite behaviour.
    let called = 0;
    await copy.run({ services: { copyArtifact: () => { called++; } } });
    expect(called).toBe(1);
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

describe("the table is the single definition (§33c)", () => {
  it("never returns a bare false — unavailable always carries a sentence", () => {
    // An action that cannot say why it is unavailable should not have been
    // declared by the kind at all; that is the kind's question, not this one's.
    for (const action of ARTIFACT_ACTIONS) {
      const out = action.available({ artifact: {}, masked: false });
      expect(out === true || typeof out?.disabled === "string", action.id).toBe(true);
      if (out !== true) expect(out.disabled.length, action.id).toBeGreaterThan(20);
    }
  });

  it("declares a tier for every action", () => {
    for (const a of ARTIFACT_ACTIONS) {
      expect(["inert", "local", "outward"], a.id).toContain(a.tier);
    }
  });

  it("imports no clipboard, vault, network or filesystem of its own", () => {
    // Services are injected so the table is testable with stubs and cannot
    // acquire a hidden dependency on a browser surface.
    expect(SRC).not.toMatch(/from "\.\.\/vault/);
    expect(SRC).not.toMatch(/navigator\./);
    expect(SRC).not.toMatch(/fetch\(/);
    expect(SRC).not.toMatch(/indexedDB/);
  });

  it("resolves every id a kind names", () => {
    // A kind naming an action with no definition is a silently missing
    // button — the tile must not be where that is discovered.
    for (const kind of ARTIFACT_KINDS) {
      for (const id of kind.actions || []) {
        expect(actionById(id), `${kind.id} names unknown action "${id}"`).toBeTruthy();
      }
      expect(actionsFor(kind).length).toBe((kind.actions || []).length);
    }
  });

  it("offers the key actions on key kinds and nowhere else", () => {
    const withPublicLine = ARTIFACT_KINDS.filter((k) =>
      (k.actions || []).includes("key.copyPublicLine")
    ).map((k) => k.id);
    // Absent on the private tile: the public half is one tile over, and on
    // non-key kinds entirely — SSH has no key type for a token or an sdp.
    expect(withPublicLine.sort()).toEqual(["key", "keypair-public"]);
  });
});

describe("the key actions against a real artifact", () => {
  /** The public half of a real generated keypair, as the engine emits it. */
  const publicHalf = async (alg) => {
    const { ast } = compileRecipe(`genkey ${alg} | out @kp`);
    const arts = await runRecipe(ast, {});
    return arts.find((a) => /public/.test(a.label));
  };

  it("copies a public line that is a real ssh-ed25519 line", async () => {
    const art = await publicHalf("ed25519");
    const action = actionById("key.copyPublicLine");
    expect(action.available({ artifact: art, masked: false })).toBe(true);
    let written = "";
    const res = await action.run({
      artifact: art,
      services: { clipboard: { write: (t) => { written = t; } } },
    });
    expect(written).toMatch(/^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5/);
    expect(res.receipt).toBe("Public line copied");
  });

  it("copies a fingerprint in ssh-keygen's own shape", async () => {
    const art = await publicHalf("ed25519");
    let written = "";
    await actionById("key.copyFingerprint").run({
      artifact: art,
      services: { clipboard: { write: (t) => { written = t; } } },
    });
    // SHA256: + 43 chars of unpadded base64 — comparable against a server's
    // log line character for character (§28a).
    expect(written).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it("refuses a public line for an algorithm SSH has no key type for", async () => {
    // x25519 does ECDH; SSH user keys sign. The action explains that rather
    // than emitting something that would not work.
    const art = await publicHalf("x25519");
    await expect(
      actionById("key.copyPublicLine").run({
        artifact: art,
        services: { clipboard: { write: () => {} } },
      })
    ).rejects.toThrow(/SSH has no key type for this algorithm/);
  });

  it("still fingerprints while the private half is masked", async () => {
    // The fingerprint is a public fact; masking it would be theatre (§34b).
    const { ast } = compileRecipe("genkey ed25519 | out @kp");
    const arts = await runRecipe(ast, {});
    const priv = arts.find((a) => /private/.test(a.label));
    expect(priv.sensitive).toBe(true);
    expect(actionById("key.copyFingerprint").available({ artifact: priv, masked: true })).toBe(
      true
    );
  });
});
