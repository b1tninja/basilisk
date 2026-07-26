import { describe, expect, it } from "vitest";
import { decrypt, generateKey, readMessage } from "openpgp";
import { base32ToBytes, bytesToBase32 } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("gpg.genkey", () => {
  it("emits armored private + public artifact", async () => {
    const { ast, validation } = compileRecipe(
      'gpg.genkey email="alice@example.com" name=Alice | out @priv'
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const priv = arts.find((a) => /priv/i.test(a.filename || a.label || ""));
    const pub = arts.find((a) => /public/i.test(a.filename || a.label || ""));
    expect(String(priv?.content || "")).toMatch(/BEGIN PGP PRIVATE KEY BLOCK/);
    expect(String(pub?.content || "")).toMatch(/BEGIN PGP PUBLIC KEY BLOCK/);
  }, 60_000);
});

describe("gpg.inspect", () => {
  it("summarizes encrypted ciphertext", async () => {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Inspect", email: "inspect@example.com" }],
      format: "object",
    });
    const enc = compileRecipe("input | gpg.encrypt");
    const encArts = await runRecipe(enc.ast, {
      recipients: [publicKey],
      recipientFingerprints: [publicKey.getFingerprint().toUpperCase()],
      inputs: { text: { value: "secret payload" } },
    });
    const armored = String(encArts[0].content);
    const insp = compileRecipe("input | gpg.inspect | out @report");
    const out = await runRecipe(insp.ast, {
      inputs: { text: { value: armored } },
    });
    expect(String(out[0].content)).toMatch(/type:\s*encrypted/);
    expect(String(out[0].content)).toMatch(/hasPkesk:\s*true/);
    void privateKey;
  }, 60_000);
});

describe("gpg.encrypt -s sign+encrypt", () => {
  it("produces a signed encrypted message", async () => {
    const alice = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Alice", email: "alice@example.com" }],
      format: "object",
    });
    const bob = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Bob", email: "bob@example.com" }],
      format: "object",
    });
    const { ast, validation } = compileRecipe("input | gpg.encrypt -s");
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds).toContain("gpg");
    const arts = await runRecipe(ast, {
      recipients: [bob.publicKey],
      recipientFingerprints: [bob.publicKey.getFingerprint().toUpperCase()],
      inputs: {
        text: { value: "signed secret" },
        gpg: {
          privateKeyArmored: alice.privateKey.armor(),
          publicKeyArmored: alice.publicKey.armor(),
          passphrase: "",
        },
      },
    });
    const armored = String(arts[0].content);
    expect(armored).toMatch(/BEGIN PGP MESSAGE/);
    const dec = await decrypt({
      message: await readMessage({ armoredMessage: armored }),
      decryptionKeys: bob.privateKey,
      verificationKeys: [alice.publicKey],
      format: "utf8",
    });
    expect(dec.data).toBe("signed secret");
    expect(dec.signatures?.length).toBeGreaterThan(0);
    await dec.signatures[0].verified;
  }, 60_000);
});

describe("passphrase mode=char", () => {
  it("emits a long character passphrase", async () => {
    const { ast, validation } = compileRecipe(
      "passphrase mode=char length=24 | out @pass"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(String(arts[0].content)).toHaveLength(24);
  });
});

describe("base32", () => {
  it("round-trips encode/decode", async () => {
    const raw = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(base32ToBytes(bytesToBase32(raw))).toEqual(raw);
    const { ast, validation } = compileRecipe(
      "random 10 | base32 | out @b32\n\nin @b32 | base32 -d | hex | out @hex"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const hex = arts.find((a) => /hex/i.test(a.filename || a.label || ""));
    expect(String(hex?.content || "")).toMatch(/^[0-9a-f]{20}$/);
  });
});

describe("gpg.sign inputNeeds", () => {
  it("reports gpg panel for sign recipes", () => {
    const { validation } = compileRecipe("input | gpg.sign | out @signed");
    expect(validation.inputNeeds).toEqual(
      expect.arrayContaining(["text", "gpg"])
    );
  });
});
