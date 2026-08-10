/**
 * **Upgrade recipe** — the button six error messages had been naming for
 * nothing.
 *
 * `legacyRemovalHint` ends five of its sentences with "(or Upgrade recipe to
 * migrate)", and `RETIRED_PARAM_VALUES` ends a sixth the same way, but
 * `migrateRecipe` had **no caller anywhere in the UI**: the wording had been
 * copied from one hint to the next since before there was anything to press.
 * That is the `723b95b` defect — an SSH passphrase message naming a field in
 * the Inputs panel that did not exist — and it is worse than saying nothing,
 * because a named remedy sends the reader hunting for a control.
 *
 * The tests here are in two halves, and the split is the point:
 *
 *  - **The promise.** Every message that names the button has a rewrite behind
 *    it, checked by running the migrator over a recipe that produces the
 *    message and compiling the result. A hint whose rewrite does not exist —
 *    or does not fix the thing it was hinting about — is the same defect one
 *    message later.
 *  - **The control.** The two render sites exist and are gated on
 *    `recipeUpgrade`, so the button is absent rather than inert where the
 *    migrator would change nothing (§33d — "is this meaningful for this
 *    object" is answered by omission, not by a disabled state).
 *
 * Rendering is out of scope (this suite runs in node with no React renderer),
 * so the second half reads source. The first half runs the real compiler.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { LEGACY_STEP_MIGRATE, legacyRemovalHint } from "../lib/toolkit/step-names.js";
import { recipeUpgrade } from "../toolkit/useNotebook";

const read = (rel) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
/** Comments stripped — a promise made in prose is not a wired control. */
const stripComments = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

const SHELL = stripComments(read("../toolkit/ToolkitShell.tsx"));
const BANNER = stripComments(read("../toolkit/widgets/CellTypeErrors.tsx"));
const HOOK = stripComments(read("../toolkit/useNotebook.ts"));

/** Every complaint one recipe raises, parse failures included. */
const complaints = (src) =>
  (compileRecipe(src).validation.errors || []).map((e) => e.message || String(e));

/**
 * Recipes that reach each of the six sentences.
 *
 * Five are parse failures — the token does not live-parse at all — and the
 * sixth (`file.read as=auto`) parses and fails validation, which is why the
 * button needed two homes rather than one. The pipeline view is where the
 * retired *param value* is complained about; the source view is where a
 * retired *token* can even be typed.
 */
const OFFERS = [
  ['random 8 | hex', "hex"],
  ['random 8 | unhex', "unhex"],
  ['random 8 | to base64', "to"],
  ['from $h | from base64', "from"],
  ['random 16 | encrypt aes-gcm key=$k', "encrypt"],
  ['file.read as=auto | out $b', "as=auto"],
  // A retired *op* name, and the most recent one: the channel ops went back to
  // `quorum.*` because they encrypt under the exchange's session key. Listed
  // here rather than only in `channel-ops.test.js` so the button's promise is
  // checked for it the same way it is for `hex` — the hint names the control,
  // and the control has to resolve the complaint.
  ["input | rtc.send", "rtc.send"],
];

describe("every message that names the button has a rewrite behind it", () => {
  for (const [src, what] of OFFERS) {
    it(`${what}: says "Upgrade recipe", and Upgrade fixes it`, () => {
      const said = complaints(src);
      expect(said.join(" · "), src).toMatch(/Upgrade recipe/);

      const upgrade = recipeUpgrade(src);
      expect(upgrade, `nothing to rewrite for: ${src}`).toBeTruthy();
      expect(upgrade.recipe).not.toBe(src);
      // The rewrite must actually resolve the complaint. A migration that
      // changes the text and leaves the error standing would put a button on
      // screen that appears to do nothing, which is where this started.
      expect(complaints(upgrade.recipe).join(" · "), upgrade.recipe).not.toMatch(
        /Upgrade recipe/
      );
      // Named changes, so the status line can say what happened rather than
      // swapping the text under the cursor in silence.
      expect(upgrade.changes.length).toBeGreaterThan(0);
      for (const c of upgrade.changes) {
        expect(c.from, JSON.stringify(c)).toBeTruthy();
        expect(c.to, JSON.stringify(c)).toBeTruthy();
        expect(c.count).toBeGreaterThan(0);
      }
    });
  }

  it("names a target for every rewrite it counts", () => {
    // `changes` was returned to nobody while `migrateRecipe` had no UI caller,
    // so three count keys — `to`, `from` and `bare-slot-@` — carried an
    // **undefined** target and no test had reason to look. On a status line
    // that reads "to → undefined". One recipe that trips as many rewrites at
    // once as it can, so the guard covers the keys rather than the examples.
    const everything = [
      "paste | utf8 | hex",
      "random 8 | to base64 | out kp",
      "from $h | from base64 | out name=x",
      "random 16 | encrypt aes-gcm key=k",
      'file.read ".pem" as=auto | unhex',
    ].join("\n\n");
    const upgrade = recipeUpgrade(everything);
    expect(upgrade).toBeTruthy();
    expect(upgrade.changes.length).toBeGreaterThan(4);
    for (const c of upgrade.changes) {
      expect(typeof c.to, `no target for "${c.from}"`).toBe("string");
      expect(c.to.length, `empty target for "${c.from}"`).toBeGreaterThan(0);
    }
  });

  it("offers the upgrade on every legacy token the hint speaks for", () => {
    // The map that drives the hint is the same map that drives the rewrite,
    // and this is what keeps them one map: a token that earns a sentence must
    // earn a migration target too.
    for (const token of Object.keys(LEGACY_STEP_MIGRATE)) {
      const hint = legacyRemovalHint(token);
      expect(hint, token).toBeTruthy();
      expect(hint, token).toMatch(/Upgrade recipe/);
      expect(LEGACY_STEP_MIGRATE[token], token).toBeTruthy();
    }
  });
});

describe("the button is absent where there is nothing to do (§33d)", () => {
  it("returns null for a recipe the migrator would leave alone", () => {
    expect(recipeUpgrade("random 32 | encode base64 | out $secret")).toBeNull();
    expect(recipeUpgrade("")).toBeNull();
    expect(recipeUpgrade("genkey ec/p256 | out $kp")).toBeNull();
  });

  it("does not fire on an ordinary type error, which upgrading cannot fix", () => {
    // The complaint has to be a *retired name*, not any complaint. A cast
    // error is a real problem the migrator has no answer for, and a button
    // there would be advice that does not apply.
    const said = complaints('"x" | utf8 | sss.split threshold=2 shares=3');
    expect(said.length).toBeGreaterThan(0);
    expect(said.join(" · ")).not.toMatch(/Upgrade recipe/);
    expect(recipeUpgrade('"x" | utf8 | sss.split threshold=2 shares=3')).toBeNull();
  });

  it("gates availability on the rewrite, never on the wording", () => {
    // The messages are hand-written and a seventh could name the button with
    // nothing behind it. `recipeUpgrade` asks the migrator instead, so such a
    // message renders a sentence and no control.
    expect(HOOK).toMatch(/export function recipeUpgrade/);
    expect(HOOK).toMatch(/if \(recipe === before \|\| !changes\.length\) return null/);
  });
});

describe("the control exists, in both places the messages appear", () => {
  it("is wired to migrateRecipe and to nothing else", () => {
    expect(HOOK).toMatch(/migrateRecipe/);
    expect(HOOK).toMatch(/const upgradeCellRecipe = useCallback/);
    // Applied through the same path a hand edit takes, so a migrated recipe
    // is parsed and validated exactly as typed text would be.
    expect(HOOK).toMatch(/applyCellRecipeText\(cellIndex, upgrade\.recipe\)/);
  });

  it("renders in the per-cell error banner, where a retired param value lands", () => {
    expect(BANNER).toMatch(/Upgrade recipe/);
    expect(BANNER).toMatch(/data-upgrade-recipe/);
    // Two conditions, both required: the caller had something to rewrite, and
    // this particular message is the one that promised the button.
    expect(BANNER).toMatch(/onUpgradeRecipe && OFFERS_UPGRADE\.test\(e\.message\)/);
    expect(SHELL).toMatch(/onUpgradeRecipe=\{[\s\S]{0,200}recipeUpgrade\(/);
  });

  it("renders in the source view, where a retired token can be typed", () => {
    // The draft, not the cell source: `applyCellRecipeText` refuses a parse
    // failure, so legacy tokens never reach `chains` and the textarea holds
    // the only copy.
    expect(SHELL).toMatch(/recipeUpgrade\(rawDrafts\[i\] \?\? nb\.cellRecipeSource\(i\)\)/);
    expect(SHELL).toMatch(
      /applyRecipeUpgrade\([\s\S]{0,120}rawDrafts\[i\] \?\? nb\.cellRecipeSource\(i\)/
    );
  });

  it("says what it rewrote rather than swapping the text in silence", () => {
    expect(HOOK).toMatch(/setRunStatus\(\s*`Upgraded:/);
  });

  it("clears the stale draft, so the box shows what the notebook holds", () => {
    expect(SHELL).toMatch(
      /const applyRecipeUpgrade[\s\S]{0,400}setRawDrafts\([\s\S]{0,200}delete next\[i\]/
    );
  });
});
