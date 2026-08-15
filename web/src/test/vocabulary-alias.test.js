/**
 * The vocabulary aliases (LANGUAGE.md, "Vocabulary"): `split` → `sss.split`,
 * `words` → `blip39`, `send` → `quorum.send`.
 *
 * They are **parse-only** — the canonical text keeps the namespaced names.
 * The doc frames the short names as canonical; the sweep said no, and the
 * decisive fact is `send`: bare `send` refuses (a recipient must be named)
 * while bare `quorum.send` broadcasts, so a broadcast serialized as `send`
 * would be canonical text that does not parse back — a serializer that emits
 * text its own parser refuses has lost the fixed point. Every refusal in the
 * codebase also quotes the registry names; canonical-short would leave errors
 * naming a spelling the canonical text never contains.
 *
 * What is pinned here: the aliases read, they converge on one canonical text
 * (no second dialect), and the one behavioural asymmetry — bare `send` — says
 * what is missing without mentioning machinery that does not exist yet.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";

const FPR = "AABBCCDDEEFF00112233445566778899AABBCCDD";

const canonical = (src) => {
  const c = compileRecipe(src);
  expect(c.validation.errors, src).toEqual([]);
  return serializeRecipe(c.ast);
};

describe("the short names read and converge on the namespaced canonical", () => {
  it("split / words spell the whole SSS pipeline", () => {
    const text = canonical("random 32 | split 2/3 | words | out $set");
    expect(text).toBe(
      canonical("random 32 | sss.split 2/3 | blip39 | out $set")
    );
    expect(text).toContain("sss.split 2/3");
    expect(text).toContain("blip39.encode");
    // No second dialect: the short name never appears in canonical text.
    expect(text).not.toMatch(/(?<!\.)\bsplit\b/);
  });

  it("split takes the majority input form too", () => {
    expect(canonical("random 32 | split 3 | out $set")).toContain(
      "sss.split 2/3"
    );
  });

  it("words carries the decode direction in every spelling", () => {
    for (const src of [
      "shares | words -d | sss.combine | out $secret",
      "shares | words.decode | sss.combine | out $secret",
    ]) {
      const text = canonical(src);
      expect(text, src).toContain("blip39.decode");
      expect(text, src).not.toContain("words");
    }
  });

  it("send with a recipient is quorum.send, spelled as quorum.send", () => {
    const text = canonical(`"hi" | send ${FPR}`);
    expect(text).toBe(canonical(`"hi" | quorum.send to=${FPR}`));
    expect(text).toContain(`quorum.send ${FPR}`);
  });

  it("the degenerate quorums refuse through the alias too", () => {
    const c = compileRecipe("random 32 | split 1/3 | out $set");
    expect(c.validation.errors.map((e) => e.message).join(" ")).toContain(
      "a copy, not a quorum"
    );
  });
});

describe("bare send refuses, naming the missing recipient", () => {
  it("refuses and says what to write", () => {
    const c = compileRecipe('"hi" | send');
    const msgs = c.validation.errors.map((e) => e.message);
    expect(msgs.length).toBeGreaterThan(0);
    const msg = msgs.join(" ");
    expect(msg).toContain("`send` names no recipient");
    expect(msg).toContain("to=<fingerprint>");
    // The refusal names the state that is true *today*. `scatter` does not
    // exist; a refusal pointing at it would name a remedy that cannot be
    // performed.
    expect(msg.toLowerCase()).not.toContain("scatter");
  });

  it("send to= with an empty value is the same missing recipient", () => {
    const c = compileRecipe('"hi" | send to=');
    expect(
      c.validation.errors.map((e) => e.message).join(" ")
    ).toContain("`send` names no recipient");
  });

  it("bare quorum.send still broadcasts — the alias is narrower, not a rename", () => {
    const c = compileRecipe('"hi" | quorum.send');
    expect(c.validation.errors).toEqual([]);
    // And its canonical spelling is itself, so the broadcast form always
    // serializes to text that parses back.
    expect(serializeRecipe(c.ast)).toContain("quorum.send");
  });
});
