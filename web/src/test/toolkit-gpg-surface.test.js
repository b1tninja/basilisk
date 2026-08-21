import { describe, expect, it } from "vitest";
import { decrypt, generateKey, readMessage } from "openpgp";
import { base32ToBytes, bytesToBase32 } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";
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

/**
 * The two roads into `gpg.decrypt`, and the one rule they are held to.
 *
 * The pipe road is why this exists: `quorum.recv from=<dealer> | gpg.decrypt`
 * is a holder opening the share a room sealed to their own key, and until the
 * step collected its input that sentence compiled, warned that the received
 * value was being discarded, and then decrypted whatever happened to be pasted
 * into Inputs → OpenPGP. A sealed share could be sent and not opened, which is
 * exactly why the generated ceremony sealed nothing.
 *
 * The rule for both roads being full is `635fd58`'s, reused rather than
 * re-decided — the same shape `shares tray=merge` settled hours earlier. The
 * value the recipe brought beats a panel that answers only when nothing was
 * brought; the panel joins instead of yielding when the *text* says so; and
 * the unspelled pairing refuses with both remedies performable on the screen
 * the reader is looking at. A second, differently-shaped answer to "pipe or
 * panel?" would be the divergence this codebase keeps rediscovering under new
 * names.
 */
describe("gpg.decrypt reads the pipe, and says so when the panel is full too", () => {
  /** One holder's key, minted once — every message below is addressed to it. */
  let holder = null;
  const holderKey = async () => {
    if (!holder) {
      holder = await generateKey({
        type: "ecc",
        curve: "curve25519",
        userIDs: [{ name: "Holder", email: "holder@example.com" }],
        format: "object",
      });
    }
    return holder;
  };

  /** A message encrypted to that holder, with the key to open it. */
  async function sealed(text) {
    const { privateKey, publicKey } = await holderKey();
    const { encrypt, createMessage } = await import("openpgp");
    const armoredMessage = await encrypt({
      message: await createMessage({ text }),
      encryptionKeys: publicKey,
    });
    return { armoredMessage: String(armoredMessage), privateKeyArmored: privateKey.armor() };
  }

  it("opens what arrives on the pipe, with no panel asked for at all", async () => {
    const s = await sealed("the share that crossed the room");
    const { ast, validation } = compileRecipe("input | gpg.decrypt | out $plain");
    expect(validation.errors).toEqual([]);
    // **No discard warning and no `gpg` need.** Both used to be there, and the
    // second is what would have stopped a run to demand a paste for a message
    // that had already arrived.
    expect(validation.warnings).toEqual([]);
    expect(validation.inputNeeds).not.toContain("gpg");

    const arts = await runRecipe(ast, {
      inputs: {
        text: { value: s.armoredMessage },
        gpg: { privateKeyArmored: s.privateKeyArmored, passphrase: "" },
      },
    });
    const plain = arts.find((a) => /plain/i.test(a.filename || a.label || ""));
    expect(String(plain?.content || "")).toBe("the share that crossed the room");
  }, 60_000);

  it("refuses a piped message and a full panel, naming both remedies", async () => {
    const a = await sealed("piped");
    const b = await sealed("pasted");
    const { ast } = compileRecipe("input | gpg.decrypt | out $plain");
    await expect(
      runRecipe(ast, {
        inputs: {
          text: { value: a.armoredMessage },
          gpg: {
            armoredMessages: [b.armoredMessage],
            privateKeyArmored: a.privateKeyArmored,
            passphrase: "",
          },
        },
      })
    ).rejects.toThrow(/will not choose between them/);

    // Both remedies, and both performable where the reader is standing: write
    // the word, or clear the panel. Neither is "go and decrypt it elsewhere".
    await expect(
      runRecipe(ast, {
        inputs: {
          text: { value: a.armoredMessage },
          gpg: {
            armoredMessages: [b.armoredMessage],
            privateKeyArmored: a.privateKeyArmored,
            passphrase: "",
          },
        },
      })
    ).rejects.toThrow(/pasted=merge.*or clear the OpenPGP panel/s);
  }, 60_000);

  it("merges both roads when the text says so, pipe first", async () => {
    const a = await sealed("piped");
    const b = await sealed("pasted");
    const { ast, validation } = compileRecipe(
      "input | gpg.decrypt count=2 pasted=merge | foreach\n  - out $plain"
    );
    expect(validation.errors).toEqual([]);
    // The merge spelling wants the panel however full the pipe is — the same
    // unguarded declaration `shares tray=merge` makes, and for the same reason:
    // a panel the merge exists to read must not be hidden behind the pipe it
    // is meant to join.
    expect(validation.inputNeeds).toContain("gpg");

    const arts = await runRecipe(ast, {
      inputs: {
        text: { value: a.armoredMessage },
        gpg: {
          armoredMessages: [b.armoredMessage],
          privateKeyArmored: a.privateKeyArmored,
          passphrase: "",
        },
      },
    });
    // Both roads' plaintexts, and **the pipe's first**: a merge that yielded to
    // the panel would be the old discard wearing a new word, and the order is
    // the only thing that tells the two apart when both succeed.
    const said = arts
      .filter((x) => /plain/i.test(x.filename || x.label || ""))
      .map((x) => String(x.content));
    expect(said).toEqual(["piped", "pasted"]);
  }, 60_000);

  it("does not change the tip's shape — count= still decides that alone", () => {
    // The constraint `a0c34cf` bought: the checker knows the output type before
    // the run, from a parameter in the text. A piped message must not move that
    // boundary, or a bundle-or-text decision would depend on what a wire
    // happened to deliver.
    const one = compileRecipe("input | gpg.decrypt | out $plain");
    const many = compileRecipe("input | gpg.decrypt count=all | shares");
    expect(one.validation.errors).toEqual([]);
    expect(many.validation.errors).toEqual([]);
    expect(getStep("gpg.decrypt").effectiveIo({ count: "1" }).output).toBe("text");
    expect(getStep("gpg.decrypt").effectiveIo({ count: "all" }).output).toBe("bundle");
    // And the pipe changes neither answer, because `effectiveIo` never sees it.
    expect(getStep("gpg.decrypt").effectiveIo({ count: "1", pasted: "merge" }).output).toBe(
      "text"
    );
  });

  it("keeps the fingerprint the message arrived under on the plaintext", async () => {
    // **Decrypting is not a change of origin.** `meta.from` is what the cell's
    // provenance line reads to say "$share-2 — from <dealer>", and it is set by
    // the verb that took the message off the room. A decrypt that dropped it
    // would leave the one machine that ends up holding a share with no
    // readable record of who dealt it, which is `dealer-absent-recovery`'s
    // finding 7a arriving by a new road.
    const { createSlotRegistry } = await import("../lib/toolkit/slot-registry.js");
    const slotRegistry = createSlotRegistry();
    const dealer = "A1".repeat(20);
    const s = await sealed("a share that crossed a room");
    slotRegistry.register("$sealed", {
      type: "text",
      data: s.armoredMessage,
      meta: { sensitive: true, from: dealer },
    });

    const { ast } = compileRecipe("in $sealed | gpg.decrypt | out $plain");
    await runRecipe(
      ast,
      { inputs: { gpg: { privateKeyArmored: s.privateKeyArmored, passphrase: "" } } },
      { slotRegistry }
    );
    expect(slotRegistry.resolve("$plain").meta.from).toBe(dealer);
  }, 60_000);

  it("corrects the count against the road it is actually reading", async () => {
    // The panel road's remedy is "paste the missing message(s)", and on the
    // pipe road that is advice about a panel this cell is not reading — the
    // rule that a refusal never names a remedy that cannot be performed. So
    // the sentence says which road holds what, and asks for the move that road
    // has: send the missing message, or write the count that is true.
    const a = await sealed("one");
    const { ast } = compileRecipe("input | gpg.decrypt count=2 | foreach\n  - out $plain");
    await expect(
      runRecipe(ast, {
        inputs: {
          text: { value: a.armoredMessage },
          gpg: { privateKeyArmored: a.privateKeyArmored, passphrase: "" },
        },
      })
    ).rejects.toThrow(/the pipe carries 1 OpenPGP message\(s\).*send the missing/s);
  }, 60_000);

  it("names a piped value that is not armor, rather than reaching past it", async () => {
    const { ast } = compileRecipe("input | gpg.decrypt | out $plain");
    await expect(
      runRecipe(ast, { inputs: { text: { value: "abandon abandon abandon" } } })
    ).rejects.toThrow(/piped into gpg.decrypt is not an OpenPGP message/);
  }, 60_000);
});
