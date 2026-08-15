import { describe, expect, it } from "vitest";
import { decrypt, generateKey, readMessage } from "openpgp";
import { base32ToBytes, bytesToBase32 } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { digestArtifact } from "../lib/toolkit/receipt.js";
import { actionById } from "../lib/toolkit/artifact-actions.js";

describe("gpg.genkey", () => {
  it("emits armored private + public artifact", async () => {
    const { ast, validation } = compileRecipe(
      'gpg.genkey email="alice@example.com" name=Alice | out $priv'
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const priv = arts.find((a) => /priv/i.test(a.filename || a.label || ""));
    const pub = arts.find((a) => /public/i.test(a.filename || a.label || ""));
    expect(String(priv?.content || "")).toMatch(/BEGIN PGP PRIVATE KEY BLOCK/);
    expect(String(pub?.content || "")).toMatch(/BEGIN PGP PUBLIC KEY BLOCK/);
  }, 60_000);
});

/**
 * The private half's fingerprint.
 *
 * A fingerprint is a public fact about a key, so it is what §34b keeps
 * available while the secret stays masked — the rule is about where a value
 * lands, not how sensitive the thing next to it is. The public tile carried it
 * from the start, because `gpg.genkey` pushes that artifact itself with the
 * fingerprint it had just computed. The private half does not go through that
 * push: it is the pipeline value, and its tile is built downstream.
 *
 * Which meant there were two of them, and only one was right. `| out $priv`
 * lands in `materializeOutArtifacts`, which copies `meta.fingerprint` into
 * traits; a bare `gpg.genkey` lands in `valueToArtifacts`, which did not. Same
 * key, same run, same kind — and on the second one Copy fingerprint sat
 * disabled saying the artifact carried no key to fingerprint, next to a public
 * tile displaying that very fingerprint.
 */
describe("gpg.genkey's private half carries its fingerprint", () => {
  const bare = async () => {
    const { ast } = compileRecipe('gpg.genkey email="fp@example.com"');
    const arts = await runRecipe(ast);
    return {
      arts,
      pub: arts.find((a) => a.role === "public-key"),
      priv: arts.find((a) => (a.tags || []).includes("private")),
    };
  };

  it("stamps it on the auto-emitted tip, not only on `out`", async () => {
    const { pub, priv } = await bare();
    expect(priv.traits?.fingerprint).toBeTruthy();
    // The same key, so necessarily the same fingerprint — a private tile
    // showing a different one would be worse than showing none.
    expect(priv.traits.fingerprint).toBe(pub.traits.fingerprint);
    expect(priv.traits.fingerprint).toMatch(/^[0-9A-F]{40}$/);
  }, 60_000);

  it("agrees with what `| out $priv` produces", async () => {
    const { ast } = compileRecipe('gpg.genkey email="fp@example.com" | out $priv');
    const arts = await runRecipe(ast);
    const priv = arts.find((a) => a.label === "priv");
    const pub = arts.find((a) => a.role === "public-key");
    expect(priv.traits.fingerprint).toBe(pub.traits.fingerprint);
    expect(priv.traits.which).toBe("private");
  }, 60_000);

  it("enables Copy fingerprint on the masked private tile", async () => {
    // Masked is the state this is *for*: the action is declared by the kind
    // and gated by `available`, and before the trait existed it answered with
    // a disabled reason about a key it was holding.
    const { priv } = await bare();
    const action = actionById("key.copyFingerprint");
    expect(action.available({ artifact: priv, masked: true })).toBe(true);
  }, 60_000);

  it("changes nothing a reader can see — only what the tile knows", async () => {
    const { arts, priv } = await bare();
    expect(arts).toHaveLength(2);
    expect(arts.map((a) => a.label)).toEqual(["OpenPGP public key", "artifact"]);
    expect(arts.map((a) => a.filename)).toEqual(["public.asc", "artifact.asc"]);
    expect(String(priv.content)).toMatch(/^-----BEGIN PGP PRIVATE KEY BLOCK-----/);
    expect(priv.sensitive).toBe(true);
  }, 60_000);

  it("leaves receipt digests where they were", async () => {
    // `traits` is not in `digestArtifact`'s row and is not in
    // SAFE_ARTIFACT_FIELDS, so this is metadata a receipt never described. It
    // matters because RECEIPT_VERSION 2 is on this branch and unshipped: a
    // change that *did* move digests would have to land inside that boundary
    // or open a second one, and `run.verify` would call an honest receipt a
    // mismatch in between. Asserted by digesting the same artifact with and
    // without the new trait rather than by reading the field list, which is
    // the thing that would drift.
    const { priv } = await bare();
    const { traits, ...withoutTraits } = priv;
    expect(traits.fingerprint).toBeTruthy();
    expect(await digestArtifact(priv)).toEqual(await digestArtifact(withoutTraits));
    expect(Object.keys(await digestArtifact(priv))).not.toContain("traits");
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
    const insp = compileRecipe("input | gpg.inspect | out $report");
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
      "passphrase mode=char length=24 | out $pass"
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
      "random 10 | base32 | out $b32\n\nin $b32 | base32 -d | encode hex | out $hex"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const hex = arts.find((a) => /hex/i.test(a.filename || a.label || ""));
    expect(String(hex?.content || "")).toMatch(/^[0-9a-f]{20}$/);
  });
});

describe("gpg.sign inputNeeds", () => {
  it("reports gpg panel for sign recipes", () => {
    const { validation } = compileRecipe("input | gpg.sign | out $signed");
    expect(validation.inputNeeds).toEqual(
      expect.arrayContaining(["text", "gpg"])
    );
  });
});

describe("gpg.symencrypt passphrase (gpg -c)", () => {
  it("round-trips with mode=passphrase passphrase=$slot", async () => {
    const { ast, validation } = compileRecipe(`"correct horse" | out $pw

"hello gpg-c" | utf8 | gpg.symencrypt mode=passphrase passphrase=$pw | out $msg

in $msg | gpg.symdecrypt mode=passphrase passphrase=$pw | utf8 | out $pt`);
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds || []).not.toContain("envelope");
    const arts = await runRecipe(ast);
    expect(arts.find((a) => /pt/i.test(a.filename || a.label || ""))?.content).toBe(
      "hello gpg-c"
    );
  }, 60_000);

  it("rejects passphrase= without mode=passphrase", () => {
    const { validation } = compileRecipe(
      `"pw" | out $pw

"hi" | utf8 | gpg.symencrypt passphrase=$pw`
    );
    expect(validation.ok).toBe(false);
    expect(
      validation.errors.some((e) => /mode=passphrase/i.test(e.message))
    ).toBe(true);
  });
});

/**
 * Decrypting an ordinary message.
 *
 * There was no test for this, which is how the defect shipped. `gpg.decrypt`
 * declared `output: "shares"` and ran every plaintext through the BLIP39
 * checksum, falling back to the raw text when it failed — so a letter still
 * came out of the pipe and the CLI's own round-trip passed. What was wrong was
 * the *type*: the tip was a share bundle, `gpg.decrypt` alone warned the reader
 * to append `sss.combine`, and `gpg.decrypt | out $msg` bound `$msg` as
 * `shares/mnemonic` to everything downstream. Nothing asserted the type, so
 * nothing caught it.
 */
describe("gpg.decrypt yields plaintext", () => {
  /** A message encrypted to a fresh key, with the key to open it. */
  async function sealed(text) {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Reader", email: "reader@example.com" }],
      format: "object",
    });
    const { encrypt, createMessage } = await import("openpgp");
    const armoredMessage = await encrypt({
      message: await createMessage({ text }),
      encryptionKeys: publicKey,
    });
    return { armoredMessage: String(armoredMessage), privateKeyArmored: privateKey.armor() };
  }

  it("decrypts an ordinary letter — no mnemonic anywhere in the value", async () => {
    // Prose, deliberately: not a mnemonic, not decodable as one, and the thing
    // a person most often decrypts.
    const letter = "Meet me at the usual place on Thursday. Burn this.";
    const s = await sealed(letter);
    const { ast, validation } = compileRecipe("gpg.decrypt | out $plain");
    expect(validation.ok).toBe(true);
    expect(validation.warnings).toEqual([]);

    const arts = await runRecipe(ast, {
      inputs: {
        gpg: {
          armoredMessages: [s.armoredMessage],
          privateKeyArmored: s.privateKeyArmored,
          passphrase: "",
        },
      },
    });
    const plain = arts.find((a) => /plain/i.test(a.filename || a.label || ""));
    expect(String(plain?.content || "")).toBe(letter);
  }, 60_000);

  it("binds the slot as text, not as a share set", async () => {
    // The regression that has teeth: a downstream step reads the slot's type,
    // and `shares` there meant a letter could not be handed to anything that
    // takes text. `utf8` accepts text and refuses shares, so it is the cheapest
    // honest witness that the tip is what it says.
    const s = await sealed("plain words");
    const { ast, validation } = compileRecipe(
      "gpg.decrypt | out $plain\n\nin $plain | utf8 | encode hex | out $hex"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: {
        gpg: {
          armoredMessages: [s.armoredMessage],
          privateKeyArmored: s.privateKeyArmored,
          passphrase: "",
        },
      },
    });
    const hex = arts.find((a) => /hex/i.test(a.filename || a.label || ""));
    expect(String(hex?.content || "")).toBe(
      Buffer.from("plain words", "utf8").toString("hex")
    );
  }, 60_000);

  it("refuses a second message rather than silently taking one", async () => {
    // `count=1` is a claim about the panel, and two messages falsify it. The
    // old code merged everything it was given into one share set, so a reader
    // who pasted two letters got a value describing neither.
    const a = await sealed("first letter");
    const b = await sealed("second letter");
    const { ast } = compileRecipe("gpg.decrypt | out $plain");
    await expect(
      runRecipe(ast, {
        inputs: {
          gpg: {
            armoredMessages: [a.armoredMessage, b.armoredMessage],
            privateKeyArmored: a.privateKeyArmored,
            passphrase: "",
          },
        },
      })
    ).rejects.toThrow(/panel holds 2 OpenPGP message\(s\).*count=all/s);
  }, 60_000);

  it("refuses a pasted block that is not armor, and does not call it a share", async () => {
    const s = await sealed("hi");
    const { ast } = compileRecipe("gpg.decrypt | out $plain");
    await expect(
      runRecipe(ast, {
        inputs: {
          gpg: {
            armoredMessages: [s.armoredMessage, "not armor at all"],
            privateKeyArmored: s.privateKeyArmored,
            passphrase: "",
          },
        },
      })
    ).rejects.toThrow(/is not an OpenPGP message/);
  }, 60_000);
});
