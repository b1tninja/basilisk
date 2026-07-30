/**
 * Type-error banner logic (§33c) — the part that can be wrong on its own.
 *
 * The banner's rendering is not covered here (this suite runs in node, with no
 * React renderer configured). What *is* covered is the fix suggestion, because
 * that is the piece that can mislead: it reads a type out of prose and then
 * claims an op produces it.
 */
import { describe, expect, it } from "vitest";
import { expectedTypeFrom } from "../lib/toolkit/type-error-hints.js";
import { producersOf } from "../lib/toolkit/type-registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("expectedTypeFrom", () => {
  it("reads the wanted type out of the registry's real phrasings", () => {
    expect(
      expectedTypeFrom('"sss.split" does not accept text/opaque (accepted: bytes/master/16B)')
    ).toBe("bytes");
    expect(expectedTypeFrom('"digest" expects DER bytes')).toBe("bytes");
  });

  it("defers to a fix the validator already named", () => {
    // The generic suggestion comes from the producer list in registry order,
    // so for `bytes` it proposes `aes-cbc` — a real producer and terrible
    // advice next to "add export pkcs8". Silence beats a second worse answer.
    expect(expectedTypeFrom('"digest" expects DER bytes — add export pkcs8')).toBeNull();
    expect(expectedTypeFrom("shares/raw needs blip39 -d — use blip39.decode")).toBeNull();
  });

  it("returns null rather than guessing", () => {
    // A miss costs a suggestion; a wrong hit sends the user to an op that
    // cannot help. Prefer silence.
    expect(expectedTypeFrom("something went wrong")).toBeNull();
    expect(expectedTypeFrom("")).toBeNull();
  });

  it("only names types the registry can actually produce", () => {
    for (const msg of [
      '"digest" expects DER bytes',
      '"sss.split" does not accept text (accepted: bytes/master)',
    ]) {
      const t = expectedTypeFrom(msg);
      expect(t, msg).toBeTruthy();
      // The banner only offers a fix when this list is non-empty, so a parsed
      // type that nothing produces simply yields no suggestion.
      expect(producersOf(t).length, `${t} producers`).toBeGreaterThan(0);
    }
  });
});

describe("validator errors stay parseable", () => {
  it("still carries stepIndex, which anchors the banner to a chip", () => {
    const { validation } = compileRecipe("genkey ec/p256 | digest");
    expect(validation.ok).toBe(false);
    const err = validation.errors[0];
    expect(err.stepIndex).toBe(1);
    // This particular error already names its own fix, so the banner shows the
    // message alone. Pinned because the *reason* matters: if the wording ever
    // drops the "add export pkcs8" clause, a generic hint would reappear and
    // this assertion is what surfaces that.
    expect(err.message).toMatch(/add export/);
    expect(expectedTypeFrom(err.message)).toBeNull();
  });
});
