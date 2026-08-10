/**
 * Artifact display policy — what may be unmasked, and in what representation.
 */
import { describe, expect, it } from "vitest";
import { runRecipe } from "../lib/toolkit/engine.js";
import { parseRecipeSource } from "../lib/toolkit/recipe-parse.js";

/** Run a recipe and return its artifacts. */
async function arts(src, bindings = {}) {
  const { ast } = parseRecipeSource(src);
  expect(ast, `${src} should parse`).toBeTruthy();
  return runRecipe(ast, bindings);
}

const pastedPublicKey = {
  inputs: { text: { value: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmDMEZ..." } },
};

describe("reveal is gated on an explicit request to display", () => {
  it("marks tiles from out / text / inspect as revealable", async () => {
    // Writing one of these verbs *is* the request to see the value, so the
    // tile may offer Reveal even when the value is sensitive.
    for (const src of [
      "random 8 | encode hex | out $r",
      "random 8 | encode hex | text note",
      "random 8 | inspect",
    ]) {
      const [a] = await arts(src);
      expect(a.revealable, src).toBe(true);
    }
  });

  it("leaves incidental tiles unrevealable", async () => {
    // A value that merely reached the end of the pipeline was never asked to
    // be displayed. Masked, with no way to unmask — that is what stops a
    // secret from being exposed implicitly.
    for (const src of ["random 8 | encode hex", "random 8"]) {
      const [a] = await arts(src);
      expect(a.sensitive, src).toBe(true);
      expect(a.revealable, src).toBeFalsy();
    }
  });

  it("keeps the content on masked tiles, so revealing needs no re-run", async () => {
    const [a] = await arts("random 8 | encode hex | out $r");
    expect(a.sensitive).toBe(true);
    expect(String(a.content)).toMatch(/^[0-9a-f]{16}$/);
  });

  it("still marks a non-sensitive out as revealable, harmlessly", async () => {
    // `revealable` records intent, not secrecy; the UI only acts on it when
    // there is something masked to unmask.
    const [a] = await arts("bytes deadbeef | out $b");
    expect(a.sensitive).toBe(false);
    expect(a.revealable).toBe(true);
  });
});

describe("input marks pasted material sensitive", () => {
  it("assumes the worst about anything pasted, even a public key", async () => {
    // `input` cannot know what you pasted, so it errs toward secret and the
    // flag propagates. That default is only tolerable because the tile can be
    // revealed — which is why `text`/`out`/`inspect` set `revealable`.
    const [a] = await arts("input | text note", pastedPublicKey);
    expect(a.sensitive).toBe(true);
    expect(a.revealable).toBe(true);
  });

  it("clears sensitivity through a one-way function", async () => {
    const [a] = await arts("input | utf8 | digest | encode hex | out $d", pastedPublicKey);
    expect(a.sensitive).toBe(false);
  });
});
