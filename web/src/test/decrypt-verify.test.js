/**
 * A decrypt says who signed what it opened, or says it could not tell.
 *
 * Before this, `verificationKeys` appeared nowhere in `engine.js`: the product
 * could report that a message decrypted and could not report that the person
 * you think wrote it did. `lib/pgp/intended-recipient.js` named the gap from
 * the other side — its surreptitious-forwarding check had no call site,
 * *"because this build has no live path that decrypts a signed message and
 * shows a signature verdict"* — and named the two things that would create one,
 * of which this is the second: `gpg.decrypt` gaining `verificationKeys`.
 *
 * ## What is asserted, and where the assertions point
 *
 * The verdict rides on `meta` and is copied onto the artifact the way the JOSE
 * body is, so every case below reads the **artifact** rather than the pipeline
 * value. That is deliberate, and it is the lesson `a0c34cf` paid for: a
 * declared field can be shadowed on the way to a reader, and a test that stops
 * at the value proves the producer works while the consumer sees nothing. The
 * tile is the consumer, so the tile is what is checked — and for `count=all`,
 * the consumer is `foreach … | out`, which is the only thing that turns a
 * bundle's parts into tiles at all.
 *
 * ## The five sentences
 *
 * A reader gets exactly one, and they are different claims:
 *
 * - `signed by <fpr> (named by signers=)` — the recipe said whose signature to
 *   expect, and it was that key's.
 * - `signed by <fpr> (in this room)` — nothing was written, a session was live,
 *   and the signer is one of the audience the room is derived from.
 * - `signed by <fpr>, who is not in this room — unverified` — a session was
 *   live and the signer is not in it. A *report*, not a refusal: see below.
 * - `signature present, no key to verify against — unverified` — there was a
 *   signature and nothing to check it with. **Not** guessed at from the bound
 *   recipients: who a recipe encrypts to is not who wrote what it received.
 * - `unsigned` — no claim was made, so none is reported.
 *
 * ## What refuses, and why the room does not
 *
 * **An explicit written claim that is violated is a refusal; an ambient default
 * that does not match is a report.** `signers=` is a claim the author wrote
 * into the recipe, so a message contradicting it stops the run. The room is not
 * a claim — it is ambient context that happens to be live, and it is not the
 * universe of legitimate signers, only whoever is in this ceremony.
 *
 * The first version of this file refused there, and it was wrong in a way worth
 * keeping written down: a friend's signed letter, pasted in during a custody
 * ceremony, threw. Worse, it inverted the ladder — tier 3, with *no session at
 * all*, reports unverified — so opening a session broke a decrypt that had
 * worked a minute earlier, off a recipe whose text had not changed by one
 * character. The equivalence test at the bottom of this file is that regression,
 * pinned.
 *
 * A **bad signature** still throws at every tier: that is a failed cryptographic
 * check rather than a question about set membership.
 */
import { describe, expect, it, vi } from "vitest";
import { createMessage, encrypt, generateKey } from "openpgp";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";
import { makeQuorumPair } from "./helpers/notebook-pair.js";

/** Three unrelated identities: Alice writes, Bob opens, Mallory is neither. */
async function cast() {
  const [alice, bob, mallory] = await Promise.all(
    ["alice", "bob", "mallory"].map((who) =>
      generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        userIDs: [{ email: `${who}@verify.test` }],
        format: "object",
      })
    )
  );
  return { alice, bob, mallory };
}

/** @param {import("openpgp").Key} k */
const fprOf = (k) => k.getFingerprint().toUpperCase();

/** How `formatFingerprint` spells one: whole, grouped in fours. */
const grouped = (fpr) => fpr.replace(/(.{4})(?=.)/g, "$1 ");

/**
 * One armored message for a recipient, optionally signed.
 * @param {{ to: import("openpgp").Key, by?: import("openpgp").PrivateKey, text?: string }} spec
 */
async function sealed({ to, by, text = "the letter" }) {
  return encrypt({
    message: await createMessage({ text }),
    encryptionKeys: to,
    ...(by ? { signingKeys: by } : {}),
    format: "armored",
  });
}

/**
 * A message carrying a **real signature over different bytes**.
 *
 * Signed first, then the literal packet is rewritten underneath the signature,
 * then the whole thing is encrypted. The signer's key id is untouched, so the
 * signer is nameable and the signature is genuinely bad — which is exactly the
 * pair of facts that separates the second refusal from the first. Nothing here
 * asks OpenPGP to mint an invalid signature; it makes a valid one describe
 * something else, which is what tampering is.
 *
 * @param {{ to: import("openpgp").Key, by: import("openpgp").PrivateKey,
 *   signedText: string, deliveredText: string }} spec
 */
async function tampered({ to, by, signedText, deliveredText }) {
  const signed = await (await createMessage({ text: signedText })).sign([by]);
  const literal = signed.packets.find((p) => typeof p.setText === "function");
  literal.setText(deliveredText);
  return encrypt({ message: signed, encryptionKeys: to, format: "armored" });
}

/**
 * Run a recipe over a panel of ciphertexts opened by one private key.
 * @param {string} src
 * @param {string[]} armoredMessages
 * @param {import("openpgp").PrivateKey} opener
 * @param {object} [extra]
 */
async function decryptWith(src, armoredMessages, opener, extra = {}) {
  const { ast, validation } = compileRecipe(src);
  expect(validation.ok, JSON.stringify(validation.errors)).toBe(true);
  const { inputs, ...rest } = extra;
  return runRecipe(ast, {
    // Merged rather than overwritten: a case that binds the text panel still
    // needs the ciphertext panel, and a spread would silently drop it.
    inputs: {
      gpg: { armoredMessages, privateKeyArmored: opener.armor() },
      ...(inputs || {}),
    },
    ...rest,
  });
}

/** @param {*[]} arts @param {string} label */
const tile = (arts, label) => arts.find((a) => a.label === label);

describe("tier 1 — `signers=` wins when it is written", () => {
  it("verifies against exactly that key and names it whole", async () => {
    const { alice, bob } = await cast();
    const arts = await decryptWith(
      `gpg.decrypt signers=${fprOf(alice.publicKey)} | out $plain`,
      [await sealed({ to: bob.publicKey, by: alice.privateKey })],
      bob.privateKey,
      { recipients: [alice.publicKey] }
    );
    const t = tile(arts, "plain");
    expect(t.content).toBe("the letter");
    expect(t.signature.state).toBe("verified");
    expect(t.signature.against).toBe("signers");
    expect(t.signature.signer).toBe(fprOf(alice.publicKey));
    expect(t.signature.sentence).toBe(
      `signed by ${grouped(fprOf(alice.publicKey))} (named by signers=)`
    );
    // Never truncated: every hex character of the fingerprint survives into the
    // sentence a person reads.
    expect(t.signature.sentence.replace(/[^0-9A-F]/g, "")).toBe(fprOf(alice.publicKey));
  }, 60_000);

  it("takes a `$slot` holding a public key, the way `gpg.verify key=` does", async () => {
    const { alice, bob } = await cast();
    // The slot has to be written by an earlier cell — that is the compiler's
    // rule for every `$slot`, and `signers=` is not exempt from it.
    const arts = await decryptWith(
      "input | out $signer\n\ngpg.decrypt signers=$signer | out $plain",
      [await sealed({ to: bob.publicKey, by: alice.privateKey })],
      bob.privateKey,
      { inputs: { text: { value: alice.publicKey.armor() } } }
    );
    const t = tile(arts, "plain");
    expect(t.signature.state).toBe("verified");
    expect(t.signature.signer).toBe(fprOf(alice.publicKey));
  }, 60_000);

  /**
   * A named fingerprint nothing holds is refused rather than narrowed to an
   * empty set. An empty set is tier 3, whose sentence is "no key to verify
   * against" — which would be said about a key the author *did* name, and is
   * the kind of quietly-wrong report this whole feature exists to stop.
   */
  it("refuses a fingerprint no key in hand answers to, rather than reading as tier 3", async () => {
    const { alice, bob, mallory } = await cast();
    await expect(
      decryptWith(
        `gpg.decrypt signers=${fprOf(mallory.publicKey)} | out $plain`,
        [await sealed({ to: bob.publicKey, by: alice.privateKey })],
        bob.privateKey
      )
    ).rejects.toThrow(/no public key for that fingerprint is in hand/i);
  }, 60_000);
});

describe("tier 3 — no `signers=`, no session, and no guessing", () => {
  it("reports a signature it cannot check as exactly that", async () => {
    const { alice, bob } = await cast();
    const arts = await decryptWith(
      "gpg.decrypt | out $plain",
      [await sealed({ to: bob.publicKey, by: alice.privateKey })],
      bob.privateKey
    );
    const t = tile(arts, "plain");
    expect(t.content).toBe("the letter");
    expect(t.signature.state).toBe("unverified");
    expect(t.signature.against).toBe("");
    expect(t.signature.sentence).toBe(
      "signature present, no key to verify against — unverified"
    );
  }, 60_000);

  /**
   * The decision this tier exists to make, asserted rather than described.
   *
   * `bindings.recipients` holds Alice's key and Alice really did sign this, so
   * a verification set taken from the recipients would produce a *correct*
   * verified verdict here — which is precisely why the test is written this
   * way. Passing would prove nothing about the rule. The rule is that the tip
   * must not verify at all, because the same code path reports a confident,
   * wrong signer on the message where the recipients are not the writer, and
   * at run time that message is indistinguishable from this one.
   */
  it("does not verify against the bound recipients even when they would be right", async () => {
    const { alice, bob } = await cast();
    const arts = await decryptWith(
      "gpg.decrypt | out $plain",
      [await sealed({ to: bob.publicKey, by: alice.privateKey })],
      bob.privateKey,
      {
        recipients: [alice.publicKey],
        recipientKeysArmored: [alice.publicKey.armor()],
        recipientFingerprints: [fprOf(alice.publicKey)],
      }
    );
    const t = tile(arts, "plain");
    expect(t.signature.state).toBe("unverified");
    expect(t.signature.signer).toBe("");
    expect(t.signature.against).toBe("");
  }, 60_000);

  it("says `unsigned` when nothing signed it, which is not a failure", async () => {
    const { bob } = await cast();
    const arts = await decryptWith(
      "gpg.decrypt | out $plain",
      [await sealed({ to: bob.publicKey })],
      bob.privateKey
    );
    const t = tile(arts, "plain");
    expect(t.signature.state).toBe("unsigned");
    expect(t.signature.sentence).toBe("unsigned");
    expect(t.signature.signer).toBe("");
  }, 60_000);
});

describe("the two refusals are two refusals", () => {
  it("a violated `signers=` refuses for being violated, and hands over a performable remedy", async () => {
    const { alice, bob, mallory } = await cast();
    // Mallory signs; the recipe expects Alice. Mallory's signature is perfect —
    // what is wrong is that the recipe made a claim this message contradicts.
    let raised = "";
    await decryptWith(
      `gpg.decrypt signers=${fprOf(alice.publicKey)} | out $plain`,
      [await sealed({ to: bob.publicKey, by: mallory.privateKey })],
      bob.privateKey,
      { recipients: [alice.publicKey] }
    ).catch((e) => {
      raised = e.message;
    });
    expect(raised).toContain("signed by a key `signers=` does not name");
    // The signature was fine, so the refusal must not say it failed.
    expect(raised).not.toMatch(/did not verify/);
    // The claimed fingerprint, whole, so the remedy can actually be performed —
    // the reader can copy it into `signers=` if it is a signer they meant.
    expect(raised).toContain(grouped(fprOf(mallory.publicKey)));
    expect(raised).toContain("which nothing here has checked");
    // A bare 16-hex key id is still never printed: it is the one fact in hand
    // that a reader cannot act on. A grouped fingerprint has no such run.
    expect(raised).not.toMatch(/[0-9A-F]{16}/);
  }, 60_000);

  it("a signature that does not hold is refused for not holding, and does name the signer", async () => {
    const { alice, bob } = await cast();
    let raised = "";
    await decryptWith(
      `gpg.decrypt signers=${fprOf(alice.publicKey)} | out $plain`,
      [
        await tampered({
          to: bob.publicKey,
          by: alice.privateKey,
          signedText: "the letter",
          deliveredText: "not the letter",
        }),
      ],
      bob.privateKey,
      { recipients: [alice.publicKey] }
    ).catch((e) => {
      raised = e.message;
    });
    expect(raised).toMatch(/did not verify/);
    // By here the signer is known, so it is named — whole, and this is the one
    // refusal of the two that can.
    expect(raised).toContain(grouped(fprOf(alice.publicKey)));
    expect(raised).not.toContain("does not name");
  }, 60_000);
});

describe("`-q` turns both refusals into verdicts, and neither looks verified", () => {
  it("keeps the plaintext and records the outside-set state without a signer", async () => {
    const { alice, bob, mallory } = await cast();
    const arts = await decryptWith(
      `gpg.decrypt signers=${fprOf(alice.publicKey)} -q | out $plain`,
      [await sealed({ to: bob.publicKey, by: mallory.privateKey })],
      bob.privateKey,
      { recipients: [alice.publicKey] }
    );
    const t = tile(arts, "plain");
    expect(t.content).toBe("the letter");
    expect(t.signature.state).toBe("unverified");
    // The sentence names who the message *claims* signed it, because that is
    // what lets a reader go and look the key up.
    expect(t.signature.sentence).toContain(grouped(fprOf(mallory.publicKey)));
    expect(t.signature.sentence).toContain("whom `signers=` does not name");
    // And the structured field a widget colours on stays empty: an
    // unauthenticated packet header is a claim, not a verdict.
    expect(t.signature.signer).toBe("");
  }, 60_000);

  it("records a bad signature as unverified, naming the signer only inside the reason", async () => {
    const { alice, bob } = await cast();
    const arts = await decryptWith(
      `gpg.decrypt signers=${fprOf(alice.publicKey)} -q | out $plain`,
      [
        await tampered({
          to: bob.publicKey,
          by: alice.privateKey,
          signedText: "the letter",
          deliveredText: "not the letter",
        }),
      ],
      bob.privateKey,
      { recipients: [alice.publicKey] }
    );
    const t = tile(arts, "plain");
    expect(t.content).toBe("not the letter");
    expect(t.signature.state).toBe("unverified");
    expect(t.signature.sentence).toMatch(/did not verify/);
    // The structured field a widget would colour on stays empty: the sentence
    // may recount who claimed to sign, the verdict may not assert it.
    expect(t.signature.signer).toBe("");
  }, 60_000);

  it("leaves the tip's type alone — `-q` here is not `gpg.verify -q`", () => {
    // `gpg.verify -q` collapses the tip to a bool. A decrypt's output type is
    // settled by `count=` before the run, so soft mode cannot change the shape
    // — the property `a0c34cf` moved plurality into `count=` to protect.
    const io = (params) => JSON.stringify(getStep("gpg.decrypt").effectiveIo(params));
    expect(io({ count: "1", soft: true })).toBe(io({ count: "1" }));
    expect(io({ count: "all", soft: true })).toBe(io({ count: "all" }));
    expect(io({ count: "1" })).toContain('"text"');
    expect(io({ count: "all" })).toContain('"bundle"');
  });
});

describe("`count=all` — a verdict per part, because a bundle is per part", () => {
  /**
   * The consumer, not the value. A bundle emits no tile of its own; its parts
   * become tiles exactly when something projects them, and `foreach … | out` is
   * that something. Asserting on `value.data.parts[i].meta` would prove the
   * producer works and say nothing about whether a reader ever sees it — the
   * shape of the defect `a0c34cf` found in the registry's declared `output`.
   */
  it("gives each plaintext its own signer on its own tile", async () => {
    const { alice, bob, mallory } = await cast();
    const arts = await decryptWith(
      `gpg.decrypt count=all signers=${fprOf(alice.publicKey)} -q | foreach\n  - out $p`,
      [
        await sealed({ to: bob.publicKey, by: alice.privateKey, text: "from alice" }),
        await sealed({ to: bob.publicKey, by: mallory.privateKey, text: "from mallory" }),
        await sealed({ to: bob.publicKey, text: "from nobody" }),
      ],
      bob.privateKey,
      { recipients: [alice.publicKey] }
    );
    const tiles = arts.filter((a) => a.label === "p");
    expect(tiles).toHaveLength(3);
    expect(tiles.map((t) => t.content)).toEqual(["from alice", "from mallory", "from nobody"]);
    // Three messages, three different states — the whole reason this is not one
    // verdict over the set. A single aggregate could only be the weakest of the
    // three wearing the others' name.
    expect(tiles.map((t) => t.signature.state)).toEqual([
      "verified",
      "unverified",
      "unsigned",
    ]);
    expect(tiles[0].signature.signer).toBe(fprOf(alice.publicKey));
    // No part's verdict may leak onto another's tile: they are separate objects
    // rather than one shared reference the loop walks.
    expect(tiles[1].signature.signer).toBe("");
    expect(tiles[2].signature.signer).toBe("");
    expect(tiles[0].signature).not.toBe(tiles[1].signature);
  }, 60_000);

  it("names which message refused, when one of several does", async () => {
    const { alice, bob, mallory } = await cast();
    await expect(
      decryptWith(
        `gpg.decrypt count=all signers=${fprOf(alice.publicKey)} | foreach\n  - out $p`,
        [
          await sealed({ to: bob.publicKey, by: alice.privateKey }),
          await sealed({ to: bob.publicKey, by: mallory.privateKey }),
        ],
        bob.privateKey,
        { recipients: [alice.publicKey] }
      )
    ).rejects.toThrow(/message 2 of 2/);
  }, 60_000);
});

describe("tier 2 — a live session makes the room the verification set", () => {
  /**
   * A real `NotebookSession`, meshed with a real peer over the pair harness:
   * real OpenPGP keys, real signed and encrypted signalling, real ECDH, real
   * key confirmation. `audienceKeys` is filled by the session's own key fetch,
   * so the set this tier reads is the one the room actually agreed on rather
   * than a fixture standing in for it.
   *
   * `getLiveSession` is the one thing replaced, and only as a *pointer*: it is
   * how the toolkit reaches whichever exchange is open, and pointing it at a
   * session this test has already meshed hands back the same kind of object
   * `execQuorumOpen` would have. Everything the tier does with it — reading the
   * map, normalising the fingerprints, matching the signer, naming the room —
   * runs for real.
   *
   * @param {(ctx: { session: *, run: Function, compile: Function }) => Promise<void>} body
   */
  async function withLiveRoom(body) {
    const pairing = await makeQuorumPair();
    try {
      await pairing.start();
      await pairing.settle();
      const session = pairing.creator.session;
      vi.doMock("../lib/toolkit/quorum-ops.js", async (original) => ({
        ...(await original()),
        getLiveSession: () => session,
      }));
      vi.resetModules();
      const { runRecipe: run } = await import("../lib/toolkit/engine.js");
      const { compileRecipe: compile } = await import("../lib/toolkit/recipe.js");
      await body({ pairing, session, run, compile });
    } finally {
      vi.doUnmock("../lib/toolkit/quorum-ops.js");
      vi.resetModules();
      await pairing.stop();
    }
  }

  it("verifies a real member's signature and says it was the room", async () => {
    await withLiveRoom(async ({ pairing, session, run, compile }) => {
      // Both sides of a two-key room, plus this machine's own key.
      expect(session.audienceKeys.size).toBeGreaterThan(1);
      const signer = pairing.joiner;
      const opener = pairing.creator;
      const armored = await encrypt({
        message: await createMessage({ text: "quorum letter" }),
        encryptionKeys: session.audienceKeys.get(opener.fpr),
        signingKeys: signer.privateKey,
        format: "armored",
      });
      const { ast } = compile("gpg.decrypt | out $plain");
      const arts = await run(ast, {
        inputs: {
          gpg: {
            armoredMessages: [armored],
            privateKeyArmored: opener.privateKey.armor(),
          },
        },
      });
      const t = tile(arts, "plain");
      expect(t.content).toBe("quorum letter");
      expect(t.signature.state).toBe("verified");
      expect(t.signature.against).toBe("room");
      expect(t.signature.signer).toBe(signer.fpr);
      expect(t.signature.sentence).toBe(`signed by ${grouped(signer.fpr)} (in this room)`);
      // Whole fingerprint, in the sentence, ungrouped and unlost.
      expect(t.signature.sentence.replace(/[^0-9A-F]/g, "")).toBe(signer.fpr);
    });
  }, 90_000);

  /**
   * The case that used to throw, and must not.
   *
   * A friend outside the ceremony sends a signed letter and it is pasted in
   * mid-session. The room cannot confirm them — that is worth saying — but
   * nothing about it is a security event, and the room is ambient context
   * rather than a claim anybody wrote into the recipe. So the run completes and
   * the verdict carries the news.
   */
  it("reports a signer the room does not name, and does not refuse", async () => {
    await withLiveRoom(async ({ pairing, session, run, compile }) => {
      const opener = pairing.creator;
      const outsider = await generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        userIDs: [{ email: "outsider@verify.test" }],
        format: "object",
      });
      const outsiderFpr = fprOf(outsider.publicKey);
      const armored = await encrypt({
        message: await createMessage({ text: "from outside" }),
        encryptionKeys: session.audienceKeys.get(opener.fpr),
        signingKeys: outsider.privateKey,
        format: "armored",
      });
      const { ast } = compile("gpg.decrypt | out $plain");
      const arts = await run(ast, {
        inputs: {
          gpg: {
            armoredMessages: [armored],
            privateKeyArmored: opener.privateKey.armor(),
          },
        },
      });
      const t = tile(arts, "plain");
      // The run completed and the letter is readable — the whole point.
      expect(t.content).toBe("from outside");
      expect(t.signature.state).toBe("unverified");
      expect(t.signature.against).toBe("room");
      // Named by whole fingerprint, so the reader can go and look the key up.
      expect(t.signature.sentence).toContain(
        `signed by ${grouped(outsiderFpr)}, who is not in this room — unverified`
      );
      // The room-is-the-list observation survives as narration, not as a gate.
      expect(t.signature.sentence).toContain("the audience is the list");
      // …and it points at the thing that *would* check this signature.
      expect(t.signature.sentence).toContain("Name the key with `signers=`");
      // Unverified never looks verified: the claimed fingerprint is in the
      // sentence and never in the field a widget colours on.
      expect(t.signature.signer).toBe("");
      // Still no bare key id anywhere.
      expect(t.signature.sentence).not.toMatch(/[0-9A-F]{16}/);
    });
  }, 90_000);

  /**
   * A bad signature is a failed cryptographic check, not a set-membership
   * question, so ambient context does not soften it: the room reports an
   * outsider and still refuses bytes that do not say what the signature says.
   */
  it("still refuses a signature that does not hold, session or no session", async () => {
    await withLiveRoom(async ({ pairing, session, run, compile }) => {
      const opener = pairing.creator;
      const signer = pairing.joiner;
      const signed = await (
        await createMessage({ text: "quorum letter" })
      ).sign([signer.privateKey]);
      signed.packets.find((p) => typeof p.setText === "function").setText("swapped");
      const armored = await encrypt({
        message: signed,
        encryptionKeys: session.audienceKeys.get(opener.fpr),
        format: "armored",
      });
      const { ast } = compile("gpg.decrypt | out $plain");
      let raised = "";
      await run(ast, {
        inputs: {
          gpg: {
            armoredMessages: [armored],
            privateKeyArmored: opener.privateKey.armor(),
          },
        },
      }).catch((e) => {
        raised = e.message;
      });
      expect(raised).toMatch(/did not verify/);
      expect(raised).toContain(grouped(signer.fpr));
    });
  }, 90_000);

  it("still lets `signers=` beat the room it is standing in", async () => {
    await withLiveRoom(async ({ pairing, session, run, compile }) => {
      const opener = pairing.creator;
      const signer = pairing.joiner;
      const armored = await encrypt({
        message: await createMessage({ text: "named explicitly" }),
        encryptionKeys: session.audienceKeys.get(opener.fpr),
        signingKeys: signer.privateKey,
        format: "armored",
      });
      const { ast } = compile(`gpg.decrypt signers=${signer.fpr} | out $plain`);
      const arts = await run(ast, {
        inputs: {
          gpg: {
            armoredMessages: [armored],
            privateKeyArmored: opener.privateKey.armor(),
          },
        },
      });
      const t = tile(arts, "plain");
      expect(t.signature.state).toBe("verified");
      // Tier 1 over tier 2: the same key, and the sentence says which decided.
      expect(t.signature.against).toBe("signers");
      expect(t.signature.sentence).toContain("named by signers=");
    });
  }, 90_000);

  /**
   * **The regression this file exists to stop.**
   *
   * One message, one recipe, run twice — once with a session live and once
   * without — and the only thing allowed to differ is what the verdict *says*.
   * Whether the run completes may not depend on ambient state, because the
   * recipe text is identical in both halves and *the text is the agreement*
   * (`docs/LANGUAGE.md`). The first implementation of tier 2 failed exactly
   * this: it threw with a session and succeeded without one, so opening a room
   * broke a decrypt that had worked a minute earlier and nothing a reader could
   * see in their own recipe explained it.
   *
   * The signer is an outsider on purpose — that is the only case where the two
   * halves could ever have diverged.
   */
  it("decrypts the same message identically with and without a live session", async () => {
    /** @type {{ armored: string, openerArmor: string, withRoom: * }} */
    const captured = { armored: "", openerArmor: "", withRoom: null };
    const SRC = "gpg.decrypt | out $plain";

    await withLiveRoom(async ({ pairing, session, run, compile }) => {
      const opener = pairing.creator;
      const outsider = await generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        userIDs: [{ email: "friend@verify.test" }],
        format: "object",
      });
      captured.armored = await encrypt({
        message: await createMessage({ text: "a letter from a friend" }),
        encryptionKeys: session.audienceKeys.get(opener.fpr),
        signingKeys: outsider.privateKey,
        format: "armored",
      });
      // Armor is a string snapshot, so it outlives the session teardown that
      // zeroes the key object it came from.
      captured.openerArmor = opener.privateKey.armor();
      const { ast } = compile(SRC);
      const arts = await run(ast, {
        inputs: {
          gpg: {
            armoredMessages: [captured.armored],
            privateKeyArmored: captured.openerArmor,
          },
        },
      });
      captured.withRoom = tile(arts, "plain");
    });

    // `withLiveRoom` has unmocked and reset by now, so this import gets the
    // real `getLiveSession`, which answers null — tier 3.
    const { runRecipe: run } = await import("../lib/toolkit/engine.js");
    const { compileRecipe: compile } = await import("../lib/toolkit/recipe.js");
    const { ast } = compile(SRC);
    const arts = await run(ast, {
      inputs: {
        gpg: {
          armoredMessages: [captured.armored],
          privateKeyArmored: captured.openerArmor,
        },
      },
    });
    const without = tile(arts, "plain");

    // Both runs completed, and both handed back the same plaintext. This is the
    // assertion that would have failed: the session half used to throw.
    expect(captured.withRoom.content).toBe("a letter from a friend");
    expect(without.content).toBe(captured.withRoom.content);
    // Neither claims a signer it did not check.
    expect(captured.withRoom.signature.state).toBe("unverified");
    expect(without.signature.state).toBe("unverified");
    expect(captured.withRoom.signature.signer).toBe("");
    expect(without.signature.signer).toBe("");
    // What *may* differ is the sentence, and it does: the room could say who
    // the signature claims and that they are not in it; with no session there
    // was no set at all to be outside of.
    expect(captured.withRoom.signature.against).toBe("room");
    expect(without.signature.against).toBe("");
    expect(captured.withRoom.signature.sentence).not.toBe(without.signature.sentence);
    expect(without.signature.sentence).toBe(
      "signature present, no key to verify against — unverified"
    );
    expect(captured.withRoom.signature.sentence).toContain("who is not in this room");
  }, 90_000);
});

/**
 * RFC 9580 §13.12 — the check that had no call site, now that it has one.
 *
 * `intended-recipient.js` decided all three outcomes in advance so that wiring
 * it would not be blocked on them, and the decisions stand unchanged here:
 * **absent** says nothing (most messages carry no subpacket, and warning on the
 * common case teaches people to ignore the rare one), **match** says nothing
 * loud, and **mismatch** changes what the signature verdict *says* without
 * refusing the decrypt — the plaintext is already recovered, and refusing would
 * hide the evidence from the person who needs to see it.
 *
 * Driven against the module rather than through a recipe, and the reason is a
 * property of the library: **openpgp.js does not write subpacket 35.** That is
 * exactly why `intendedRecipientsFromSigPacket` reads it out of
 * `unknownSubpackets` — an implementation that emitted it would have a parser
 * for it. There is no way to make a real signed message carry one from inside
 * this process, so the seam is exercised with a signature shaped like what the
 * reader walks. What is being asserted is the wiring: that a mismatch reaches
 * the sentence, and that the plaintext is not withheld when it does.
 */
describe("§13.12 — a mismatch changes the sentence, never the outcome", () => {
  const SIGNER = "AABBCCDDEEFF00112233445566778899AABBCCDD";
  const OPENED_BY = "00112233445566778899AABBCCDDEEFF00112233";

  /** A signature packet carrying one intended-recipient fingerprint. */
  function irfPacket(fpr) {
    const body = new Uint8Array(21);
    body[0] = 4; // key version
    const hex = fpr.match(/../g);
    for (let i = 0; i < 20; i++) body[i + 1] = parseInt(hex[i], 16);
    return { unknownSubpackets: [{ type: 35, body }] };
  }

  /** One good signature from `SIGNER`, addressed to `addressedTo`. */
  const signatureFrom = (addressedTo) => [
    {
      keyID: { toHex: () => SIGNER.slice(-16).toLowerCase() },
      verified: Promise.resolve(true),
      signature: Promise.resolve({
        packets: addressedTo ? [irfPacket(addressedTo)] : [],
      }),
    },
  ];

  const set = new Map([
    [SIGNER, { getFingerprint: () => SIGNER, getKeyIDs: () => [] }],
  ]);

  /** @param {string} addressedTo */
  async function verdictFor(addressedTo) {
    const { decryptSignatureVerdict } = await import("../lib/pgp/decrypt-verify.js");
    return decryptSignatureVerdict({
      signatures: signatureFrom(addressedTo),
      keyByFpr: set,
      against: "signers",
      decryptFpr: OPENED_BY,
      soft: false,
      what: "gpg.decrypt",
    });
  }

  it("says nothing extra when the subpacket is absent — the common case", async () => {
    const v = await verdictFor("");
    expect(v.state).toBe("verified");
    expect(v.intended).toBe("absent");
    expect(v.sentence).toBe(`signed by ${grouped(SIGNER)} (named by signers=)`);
  });

  it("says nothing loud when it matches the key that opened the message", async () => {
    const v = await verdictFor(OPENED_BY);
    expect(v.state).toBe("verified");
    expect(v.intended).toBe("ok");
    // The expected case does not get badged: the sentence is the plain one.
    expect(v.sentence).toBe(`signed by ${grouped(SIGNER)} (named by signers=)`);
  });

  /**
   * Surreptitious forwarding, from the inside: Mallory took a message Alice
   * signed to Bob and re-encrypted it here. The signature is cryptographically
   * good and the verdict must not read "Alice signed this to you", because she
   * did not.
   */
  /**
   * The half that mutation testing found, and that review had not.
   *
   * A hidden-recipient message names no key id in its PKESK, so the engine
   * cannot say which key opened it and hands over `""`. `checkIntendedRecipient`
   * has no case for that — every comparison against an empty fingerprint fails
   * and it answers `mismatch` — so without the guard, addressing a message
   * privately was enough to have it reported as possible surreptitious
   * forwarding. A confident wrong verdict is the exact failure this verb exists
   * to avoid.
   */
  it("makes no comparison at all when it cannot tell which key opened the message", async () => {
    const { decryptSignatureVerdict } = await import("../lib/pgp/decrypt-verify.js");
    const v = await decryptSignatureVerdict({
      signatures: signatureFrom(OPENED_BY),
      keyByFpr: set,
      against: "signers",
      // What a hidden-recipient message leaves the caller holding.
      decryptFpr: "",
      soft: false,
      what: "gpg.decrypt",
    });
    expect(v.state).toBe("verified");
    expect(v.intended).toBe("absent");
    expect(v.sentence).toBe(`signed by ${grouped(SIGNER)} (named by signers=)`);
    expect(v.sentence).not.toContain("forwarding");
  });

  it("names the mismatch, keeps the verdict verified, and refuses nothing", async () => {
    const v = await verdictFor("FFEEDDCCBBAA99887766554433221100FFEEDDCC");
    expect(v.state).toBe("verified");
    expect(v.intended).toBe("mismatch");
    expect(v.signer).toBe(SIGNER);
    // The signer is still named — the signature really is theirs — and the
    // clause that follows is what a reader acts on differently.
    expect(v.sentence).toContain(`signed by ${grouped(SIGNER)}`);
    expect(v.sentence).toContain("addressed to a different key");
    expect(v.sentence).toContain("RFC 9580 §13.12");
  });
});
