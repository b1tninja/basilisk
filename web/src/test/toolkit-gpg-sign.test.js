import { describe, expect, it } from "vitest";
import { generateKey } from "openpgp";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("gpg.sign / gpg.verify", () => {
  it("round-trips cleartext with a vault private key", async () => {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Toolkit Test", email: "test@example.com" }],
      format: "object",
    });
    const sign = compileRecipe("input | gpg.sign | out @signed");
    expect(sign.validation.ok).toBe(true);
    const signedArts = await runRecipe(sign.ast, {
      inputs: {
        text: { value: "hello basilisk" },
        gpg: {
          privateKeyArmored: privateKey.armor(),
          publicKeyArmored: publicKey.armor(),
          passphrase: "",
        },
      },
    });
    const signed = signedArts.find((a) => /signed/i.test(a.filename || a.label || "")) || signedArts[0];
    expect(signed.content).toMatch(/BEGIN PGP SIGNED MESSAGE/);

    const verify = compileRecipe("input | gpg.verify | out @ok");
    const out = await runRecipe(verify.ast, {
      inputs: {
        text: { value: String(signed.content) },
        gpg: {
          privateKeyArmored: privateKey.armor(),
          publicKeyArmored: publicKey.armor(),
          passphrase: "",
        },
      },
    });
    expect(out[0].content).toMatch(/verified/i);
  }, 60_000);

  it("detached sign + verify via signature=@slot", async () => {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Toolkit Test", email: "test@example.com" }],
      format: "object",
    });
    const recipe = `input | out @msg

in @msg | gpg.sign format=detached | out @sig

in @msg | gpg.verify signature=@sig | out @ok`;
    const { ast, validation } = compileRecipe(recipe);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: {
        text: { value: "detached payload" },
        gpg: {
          privateKeyArmored: privateKey.armor(),
          publicKeyArmored: publicKey.armor(),
          passphrase: "",
        },
      },
    });
    const ok = arts.find((a) => /ok/i.test(a.filename || a.label || "")) || arts.at(-1);
    expect(String(ok.content)).toMatch(/verified/i);
  }, 60_000);
});
