/**
 * Inverse toolkit pipelines: combine, decode flags, envelope emission, GPG round-trip.
 */
import { generateKey, readKey } from "openpgp";
import { describe, expect, it } from "vitest";
import { base64ToBytes } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { combineShares } from "../lib/slip39/slip39.js";

describe("toolkit recover / combine", () => {
  it("round-trips random 32 via slip39 then input|combine|hex", async () => {
    const split = compileRecipe(
      "random 32 | slip39 threshold=2 shares=3 | foreach | out name=share"
    );
    expect(split.validation.ok).toBe(true);
    const arts = await runRecipe(split.ast);
    const shares = arts.filter((a) => a.shareIndex).map((a) => a.content);
    expect(shares.length).toBe(3);

    const recover = compileRecipe("input shares | combine | hex");
    expect(recover.validation.ok).toBe(true);
    const out = await runRecipe(recover.ast, {
      inputs: { shares: { mnemonics: [shares[0], shares[2]] } },
    });
    expect(out[0].content).toMatch(/^[0-9a-f]{64}$/);

    // Cross-check against library combine
    const direct = await combineShares([shares[0], shares[2]]);
    const hex = Array.from(direct)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(out[0].content).toBe(hex);
  }, 30_000);

  it("emits envelope ciphertext from foreach|encrypt pipeline", async () => {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Test", email: "test@example.com" }],
      format: "object",
    });
    void privateKey;
    const fpr = publicKey.getFingerprint().toUpperCase();

    const { ast, validation } = compileRecipe(
      "genkey ec/p256 | export pkcs8 | pem | slip39 threshold=2 shares=3 | foreach | encrypt gpg"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      recipients: [publicKey],
      recipientFingerprints: [fpr],
    });

    const envelope = arts.find((a) => /envelope/i.test(a.label) || /envelope/i.test(a.filename));
    expect(envelope).toBeTruthy();
    expect(envelope.sensitive).toBe(false);
    expect(base64ToBytes(envelope.content).length).toBeGreaterThan(12);

    const gpgShares = arts.filter((a) => a.mime === "application/pgp-encrypted");
    expect(gpgShares.length).toBe(3);
  }, 60_000);

  it("rebuilds P-256 PEM from shares (envelope path)", async () => {
    const split = compileRecipe(
      "genkey ec/p256 | export pkcs8 | pem | slip39 threshold=2 shares=3 | foreach | out name=share"
    );
    const arts = await runRecipe(split.ast);
    const shares = arts.filter((a) => a.shareIndex).map((a) => a.content);
    const envelope = arts.find((a) => /envelope/i.test(a.filename));
    expect(envelope).toBeTruthy();

    const recover = compileRecipe(
      "input shares | combine | utf8 | pem -d | import pkcs8 alg=ec/p256 | export pkcs8 | pem"
    );
    expect(recover.validation.ok).toBe(true);
    const out = await runRecipe(recover.ast, {
      inputs: {
        shares: {
          mnemonics: [shares[0], shares[1]],
          envelopeB64: envelope.content,
        },
      },
    });
    expect(out[0].content).toContain("BEGIN PRIVATE KEY");

    const b64 = out[0].content
      .replace(/-----[^-]+-----/g, "")
      .replace(/\s+/g, "");
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
    );
    expect(key).toBeInstanceOf(CryptoKey);
  }, 60_000);

  it("full inverse: encrypt gpg shares → decrypt gpg → rebuild PEM", async () => {
    const { privateKey: pgpPriv, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Quorum", email: "q@example.com" }],
      format: "object",
    });
    const fpr = publicKey.getFingerprint().toUpperCase();

    const split = compileRecipe(
      "genkey ec/p256 | export pkcs8 | pem | slip39 threshold=2 shares=3 | foreach | encrypt gpg"
    );
    const arts = await runRecipe(split.ast, {
      recipients: [publicKey],
      recipientFingerprints: [fpr],
    });
    const ciphertexts = arts
      .filter((a) => a.mime === "application/pgp-encrypted")
      .map((a) => a.content);
    const envelope = arts.find((a) => /envelope/i.test(a.filename));
    expect(ciphertexts.length).toBe(3);
    expect(envelope).toBeTruthy();

    const armoredPrivate = pgpPriv.armor();
    const recover = compileRecipe(
      "decrypt gpg | combine | utf8 | pem -d | import pkcs8 alg=ec/p256 | export pkcs8 | pem"
    );
    expect(recover.validation.ok).toBe(true);
    const out = await runRecipe(recover.ast, {
      inputs: {
        gpg: {
          armoredMessages: [ciphertexts[0], ciphertexts[2]],
          privateKeyArmored: armoredPrivate,
          passphrase: "",
          envelopeB64: envelope.content,
        },
        shares: { mnemonics: [], envelopeB64: envelope.content },
      },
    });
    expect(out[0].content).toContain("BEGIN PRIVATE KEY");
  }, 90_000);
});
