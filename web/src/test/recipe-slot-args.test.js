/**
 * Named slot args (key=@cek) and `as` cast.
 */
import { describe, expect, it } from "vitest";
import { runRecipe } from "../lib/toolkit/engine.js";
import {
  canonicalizeRecipe,
  compileRecipe,
  parseRecipe,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";

describe("named slot args", () => {
  it("canonicalizes key=cek to key=@cek", () => {
    const { text, errors } = canonicalizeRecipe(
      "genkey aes/256 | out @cek\n\nrandom 32 | aesgcm key=cek"
    );
    expect(errors).toEqual([]);
    expect(text).toContain("aesgcm key=@cek");
  });

  it("rejects forward key=@slot refs", () => {
    const { validation } = compileRecipe("random 32 | aesgcm key=@cek");
    expect(validation.ok).toBe(false);
    expect(
      validation.errors.some((e) => /unknown slot|@cek/i.test(e.message))
    ).toBe(true);
  });

  it("clears key panel need when key=@slot is bound", () => {
    const { validation } = compileRecipe(
      "genkey aes/256 | out @cek\n\nrandom 32 | aesgcm key=@cek | out @ct"
    );
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds || []).not.toContain("key");
  });

  it("still needs key panel when slot arg omitted", () => {
    const { validation } = compileRecipe("random 32 | aesgcm | hex");
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds).toContain("key");
  });

  it("round-trips aesgcm with key=@cek across chains", async () => {
    const split = compileRecipe(`genkey aes/256 | out @cek

random 32 | out @msg

in @msg | aesgcm key=@cek | out @ct

in @ct | aesgcm -d key=@cek | hex`);
    expect(split.validation.ok).toBe(true);
    expect(split.validation.inputNeeds || []).not.toContain("key");
    const arts = await runRecipe(split.ast);
    const hex = arts.find((a) => /^[0-9a-f]{64}$/i.test(String(a.content || "")));
    expect(hex).toBeTruthy();
  }, 30_000);

  it("serializes slot args with @", () => {
    const { ast, errors } = parseRecipe(
      "genkey aes/256 | out @cek\n\nrandom 32 | aesgcm key=@cek"
    );
    expect(errors).toEqual([]);
    expect(serializeRecipe(ast)).toContain("key=@cek");
  });
});

describe("as cast", () => {
  it("retags opaque digest bytes as master for sss", () => {
    const { validation } = compileRecipe(
      "random 32 | digest | as master | sss threshold=2 shares=3"
    );
    expect(validation.ok).toBe(true);
  });

  it("rejects as master on wrong length", () => {
    const { validation } = compileRecipe(
      "random 8 | as master | sss threshold=2 shares=3"
    );
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /16 or 32/i.test(e.message))).toBe(
      true
    );
  });

  it("runs as master | sss | blip39", async () => {
    const { ast, validation } = compileRecipe(
      "random 32 | digest | as master | sss threshold=2 shares=3 | blip39 | foreach\n  - out @share"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.filter((a) => a.shareIndex).length).toBe(3);
  }, 30_000);

  it("canonicalizes as MASTER", () => {
    const { text, errors } = canonicalizeRecipe("random 32 | digest | AS MASTER");
    expect(errors).toEqual([]);
    expect(text).toContain("as master");
    expect(text.toLowerCase()).toContain("digest");
  });
});

describe("ecdh / wrap slot args (validate)", () => {
  it("ecdh with private+peer slots clears key panel", () => {
    const src = `genkey ec/p256 usage=derive | out @local

genkey ec/p256 usage=derive | .public | export jwk | out @peer

ecdh private=@local peer=@peer | hex`;
    const { validation } = compileRecipe(src);
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds || []).not.toContain("key");
  });

  it("wrap needs both key and target slots to clear panel", () => {
    const partial = compileRecipe(
      "genkey aes/256 | out @kek\n\nwrap key=@kek | hex"
    );
    expect(partial.validation.inputNeeds).toContain("key");

    const full = compileRecipe(`genkey aes/256 | out @kek

genkey aes/256 | out @cek

wrap key=@kek target=@cek | hex`);
    expect(full.validation.ok).toBe(true);
    expect(full.validation.inputNeeds || []).not.toContain("key");
  });
});
