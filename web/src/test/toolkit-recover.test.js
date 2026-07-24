/**
 * Inverse toolkit pipelines: recover, scalar SSS, OpenPGP envelope, GPG round-trip.
 */
import { generateKey } from "openpgp";
import { describe, expect, it } from "vitest";
import { PROFILE_COMPATIBLE } from "../lib/pgp/encrypt.js";
import { base64ToBytes } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe, PRESETS } from "../lib/toolkit/recipe.js";
import { validateShareMnemonic } from "../lib/slip39/blip39.js";
import { combineShares } from "../lib/slip39/slip39.js";

describe("toolkit recover / shares", () => {
  it("round-trips random 32 via sss|blip39 then shares|recover|hex", async () => {
    const split = compileRecipe(
      "random 32 | sss threshold=2 shares=3 | blip39 | foreach | out name=share"
    );
    expect(split.validation.ok).toBe(true);
    const arts = await runRecipe(split.ast);
    const shares = arts.filter((a) => a.shareIndex).map((a) => a.content);
    expect(shares.length).toBe(3);

    const recover = compileRecipe("shares | blip39 -d | recover | hex");
    expect(recover.validation.ok).toBe(true);
    const out = await runRecipe(recover.ast, {
      inputs: { shares: { mnemonics: [shares[0], shares[2]] } },
    });
    expect(out[0].content).toMatch(/^[0-9a-f]{64}$/);

    const direct = await combineShares([shares[0], shares[2]]);
    const hex = Array.from(direct)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(out[0].content).toBe(hex);
  }, 30_000);

  it("export/import scalar round-trips P-256", async () => {
    const { ast, validation } = compileRecipe(
      "genkey ec/p256 | export scalar | import scalar alg=ec/p256 | export pkcs8 | pem"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
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
  }, 30_000);

  it("fanout emits public key and does not consume keypair for scalar export", async () => {
    const { ast, validation } = compileRecipe(
      "genkey ec/p256 | fanout format=spki which=public name=public-key ext=spki | export scalar | hex"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const pub = arts.find((a) => a.role === "key" || /public-key/i.test(a.filename || ""));
    expect(pub).toBeTruthy();
    expect(pub.sensitive).toBe(false);
    expect(pub.tags).toEqual(expect.arrayContaining(["public"]));
    const hex = arts.find((a) => /^[0-9a-f]{64}$/.test(a.content));
    expect(hex).toBeTruthy();
  }, 30_000);

  it("direct scalar SSS: fanout → slip39 → recover → import scalar", async () => {
    const split = compileRecipe(
      "genkey ec/p256 | fanout format=spki which=public name=public-key | export scalar | sss threshold=2 shares=3 | blip39 | foreach | out name=share"
    );
    expect(split.validation.ok).toBe(true);
    const arts = await runRecipe(split.ast);
    expect(arts.some((a) => a.role === "envelope")).toBe(false);
    const shares = arts.filter((a) => a.role === "share" || a.shareIndex);
    expect(shares.length).toBe(3);
    expect(shares.every((a) => a.role === "share")).toBe(true);

    const recover = compileRecipe(
      "shares | blip39 -d | recover | import scalar alg=ec/p256 | export pkcs8 | pem"
    );
    const out = await runRecipe(recover.ast, {
      inputs: {
        shares: { mnemonics: [shares[0].content, shares[1].content] },
      },
    });
    expect(out[0].content).toContain("BEGIN PRIVATE KEY");
  }, 60_000);

  it("sss rejects PEM at compile time (refined types)", () => {
    const { validation } = compileRecipe(
      "genkey ec/p256 | export pkcs8 | pem | sss threshold=2 shares=3"
    );
    expect(validation.ok).toBe(false);
    expect(
      validation.errors.some((e) => /export scalar|symencrypt|does not accept/i.test(e.message))
    ).toBe(true);
  });

  it("OpenPGP envelope path: pem → symencrypt → slip39 → recover → symdecrypt", async () => {
    const split = compileRecipe(
      "genkey ec/p256 | export pkcs8 | pem | symencrypt | sss threshold=2 shares=3 | blip39 | foreach | out name=share"
    );
    expect(split.validation.ok).toBe(true);
    const arts = await runRecipe(split.ast, {
      encryption: { profile: PROFILE_COMPATIBLE },
    });
    const envelope = arts.find((a) => a.role === "envelope");
    expect(envelope).toBeTruthy();
    expect(envelope.filename).toMatch(/\.asc$/i);
    expect(envelope.content).toContain("BEGIN PGP MESSAGE");
    expect(envelope.sensitive).toBe(false);
    expect(envelope.stepName).toBe("symencrypt");
    const shares = arts.filter((a) => a.shareIndex).map((a) => a.content);
    expect(shares.length).toBe(3);

    const recover = compileRecipe("shares | blip39 -d | recover | symdecrypt | utf8");
    expect(recover.validation.inputNeeds).toEqual(
      expect.arrayContaining(["shares", "envelope"])
    );
    const out = await runRecipe(recover.ast, {
      inputs: {
        shares: { mnemonics: [shares[0], shares[2]] },
        envelope: { armored: envelope.content },
      },
    });
    expect(out[0].content).toContain("BEGIN PRIVATE KEY");
  }, 60_000);

  it("foreach|encrypt on scalar shares emits GPG artifacts without SSS envelope", async () => {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Test", email: "test@example.com" }],
      format: "object",
    });
    void privateKey;
    const fpr = publicKey.getFingerprint().toUpperCase();

    const { ast, validation } = compileRecipe(
      "genkey ec/p256 | fanout format=spki which=public name=public-key | export scalar | sss threshold=2 shares=3 | blip39 | foreach | encrypt gpg"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      recipients: [publicKey],
      recipientFingerprints: [fpr],
      encryption: {
        profile: PROFILE_COMPATIBLE,
        hideRecipients: true,
      },
    });

    expect(arts.some((a) => a.role === "envelope")).toBe(false);
    const gpgShares = arts.filter((a) => a.mime === "application/pgp-encrypted");
    expect(gpgShares.length).toBe(3);
    expect(gpgShares.every((a) => a.role === "share")).toBe(true);
    expect(gpgShares.every((a) => /SEIPD v1/.test(a.cryptoSummary))).toBe(true);
  }, 60_000);

  it("full inverse: encrypt gpg scalar shares → decrypt gpg → rebuild PEM", async () => {
    const { privateKey: pgpPriv, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Quorum", email: "q@example.com" }],
      format: "object",
    });
    const fpr = publicKey.getFingerprint().toUpperCase();

    const split = compileRecipe(
      "genkey ec/p256 | export scalar | sss threshold=2 shares=3 | blip39 | foreach | encrypt gpg"
    );
    const arts = await runRecipe(split.ast, {
      recipients: [publicKey],
      recipientFingerprints: [fpr],
    });
    const ciphertexts = arts
      .filter((a) => a.mime === "application/pgp-encrypted")
      .map((a) => a.content);
    expect(ciphertexts.length).toBe(3);

    const recover = compileRecipe(
      "decrypt gpg | blip39 -d | recover | import scalar alg=ec/p256 | export pkcs8 | pem"
    );
    expect(recover.validation.ok).toBe(true);
    expect(recover.validation.inputNeeds).toEqual(
      expect.arrayContaining(["gpg", "shares"])
    );
    const out = await runRecipe(recover.ast, {
      inputs: {
        gpg: {
          armoredMessages: [ciphertexts[0], ciphertexts[2]],
          privateKeyArmored: pgpPriv.armor(),
          passphrase: "",
        },
        shares: { mnemonics: [] },
      },
    });
    expect(out[0].content).toContain("BEGIN PRIVATE KEY");
  }, 90_000);

  it("hybrid: one in-browser decrypt + one externally-decrypted mnemonic", async () => {
    const { privateKey: pgpPriv, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Hybrid", email: "h@example.com" }],
      format: "object",
    });
    const fpr = publicKey.getFingerprint().toUpperCase();

    const split = compileRecipe(
      "genkey ec/p256 | export scalar | sss threshold=2 shares=3 | blip39 | foreach | encrypt gpg"
    );
    const arts = await runRecipe(split.ast, {
      recipients: [publicKey],
      recipientFingerprints: [fpr],
    });
    const ciphertexts = arts
      .filter((a) => a.mime === "application/pgp-encrypted")
      .map((a) => a.content);

    const { decrypt, readMessage } = await import("openpgp");
    const external = await decrypt({
      message: await readMessage({ armoredMessage: ciphertexts[0] }),
      decryptionKeys: pgpPriv,
      config: { allowInsecureDecryptionWithSigningKeys: true },
    });
    const externalMnemonic = String(external.data).trim();
    expect(validateShareMnemonic(externalMnemonic).ok).toBe(true);

    const recover = compileRecipe(
      "decrypt gpg | blip39 -d | recover | import scalar alg=ec/p256 | export pkcs8 | pem"
    );
    const out = await runRecipe(recover.ast, {
      inputs: {
        gpg: {
          armoredMessages: [ciphertexts[2]],
          privateKeyArmored: pgpPriv.armor(),
          passphrase: "",
        },
        shares: {
          mnemonics: [externalMnemonic],
        },
      },
    });
    expect(out[0].content).toContain("BEGIN PRIVATE KEY");
  }, 90_000);

  it("bare random 32 | sss | blip39 has no envelope and recovers", async () => {
    const split = compileRecipe("random 32 | sss threshold=2 shares=3 | blip39");
    const arts = await runRecipe(split.ast);
    const mnemonics = arts
      .filter((a) => a.shareIndex || /^Share\s+\d+/i.test(a.label || ""))
      .map((a) => a.content);
    expect(mnemonics.length).toBe(3);
    expect(arts.some((a) => a.role === "envelope")).toBe(false);

    const recover = compileRecipe("shares | blip39 -d | recover | hex");
    const out = await runRecipe(recover.ast, {
      inputs: { shares: { mnemonics: [mnemonics[0], mnemonics[1]] } },
    });
    expect(out[0].content).toMatch(/^[0-9a-f]{64}$/);
  }, 30_000);

  it("passphrase path: wrong passphrase fails to recover secret", async () => {
    const split = compileRecipe(
      "random 32 | sss threshold=2 shares=3 passphrase=correct-horse | blip39 | foreach | out name=share"
    );
    const arts = await runRecipe(split.ast);
    const mnemonics = arts.filter((a) => a.shareIndex).map((a) => a.content);

    const wrong = compileRecipe("shares | blip39 -d | recover | hex");
    const wrongOut = await runRecipe(wrong.ast, {
      inputs: {
        shares: {
          mnemonics: [mnemonics[0], mnemonics[1]],
          passphrase: "wrong",
        },
      },
    });
    const ok = await runRecipe(wrong.ast, {
      inputs: {
        shares: {
          mnemonics: [mnemonics[0], mnemonics[1]],
          passphrase: "correct-horse",
        },
      },
    });
    expect(ok[0].content).toMatch(/^[0-9a-f]{64}$/);
    expect(wrongOut[0].content).not.toBe(ok[0].content);
  }, 30_000);

  it("preset slip39-split round-trips via recover-shares", async () => {
    const splitPreset = PRESETS.find((p) => p.id === "slip39-split");
    const recoverPreset = PRESETS.find((p) => p.id === "recover-shares");
    expect(splitPreset && recoverPreset).toBeTruthy();

    const split = compileRecipe(splitPreset.recipe);
    const arts = await runRecipe(split.ast);
    const mnemonics = arts.filter((a) => a.shareIndex).map((a) => a.content);

    const recover = compileRecipe(recoverPreset.recipe);
    const out = await runRecipe(recover.ast, {
      inputs: {
        shares: {
          mnemonics: [mnemonics[0], mnemonics[2]],
        },
      },
    });
    expect(out[0].content.length).toBeGreaterThan(20);
    expect(base64ToBytes(out[0].content).length).toBe(32);
  }, 30_000);

  it("preset rebuild-p256 recovers scalar split", async () => {
    const rebuild = PRESETS.find((p) => p.id === "rebuild-p256");
    expect(rebuild).toBeTruthy();

    const split = compileRecipe(
      "genkey ec/p256 | export scalar | sss threshold=2 shares=3 | blip39"
    );
    const arts = await runRecipe(split.ast);
    const mnemonics = arts
      .filter((a) => a.shareIndex || /^Share\s+\d+/i.test(a.label || ""))
      .map((a) => a.content);

    const recover = compileRecipe(rebuild.recipe);
    const out = await runRecipe(recover.ast, {
      inputs: {
        shares: {
          mnemonics: [mnemonics[1], mnemonics[2]],
        },
      },
    });
    expect(out[0].content).toContain("BEGIN PRIVATE KEY");
  }, 60_000);

  it("preset pem-envelope-rebuild recovers symencrypt split", async () => {
    const rebuild = PRESETS.find((p) => p.id === "pem-envelope-rebuild");
    const splitPreset = PRESETS.find((p) => p.id === "pem-envelope-split");
    expect(rebuild && splitPreset).toBeTruthy();

    const split = compileRecipe(splitPreset.recipe);
    const arts = await runRecipe(split.ast, {
      encryption: { profile: PROFILE_COMPATIBLE },
    });
    const envelope = arts.find((a) => a.role === "envelope");
    const mnemonics = arts.filter((a) => a.shareIndex).map((a) => a.content);
    expect(envelope).toBeTruthy();

    const recover = compileRecipe(rebuild.recipe);
    const out = await runRecipe(recover.ast, {
      inputs: {
        shares: { mnemonics: [mnemonics[0], mnemonics[1]] },
        envelope: { armored: envelope.content },
      },
    });
    expect(out[0].content).toContain("BEGIN PRIVATE KEY");
  }, 60_000);
});
