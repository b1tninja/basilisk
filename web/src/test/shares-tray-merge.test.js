/**
 * The single-cell hybrid, restored as a word in the recipe rather than a mood.
 *
 * `a0c34cf` decoupled `gpg.decrypt` from BLIP39 — decrypting a message is not
 * reading a share — and named the one capability that went with it: the hybrid,
 * a single cell merging shares this browser decrypted with shares a custodian
 * opened where no page can go (Kleopatra, gpg, a YubiKey, an OpenPGP card) and
 * typed into the Inputs rows. It had only ever worked because `gpg.decrypt`
 * secretly read that tray.
 *
 * What stood in the way was `shares`' own rule — what the recipe names beats
 * what a tray holds — and the failure it produced was worse than a missing
 * feature. With one share decrypted in-page and the other pasted, the run said:
 *
 *     Need at least 2 shares, got 1. The GPG panel holds 1 OpenPGP message; …
 *     decrypt it in Kleopatra/gpg and paste the mnemonic into the share rows
 *     beside the others.
 *
 * — instructing a custodian to do the thing they had already done, while the
 * mnemonic they had typed sat one field away being ignored. A remedy naming an
 * act already performed is this codebase's signature defect wearing the other
 * face.
 *
 * The loosening is exactly one rule and it is spelled: `tray=merge` folds the
 * rows in beside what the recipe names. The default is untouched, so no shipped
 * recipe changes meaning, and the pairing that used to be silent — named shares
 * *and* a full tray, with neither word written — now refuses rather than
 * picking a side, because a cell whose result depends on whether a panel three
 * inches away happens to be full is the invisible state `f565ab1` killed.
 *
 * The one-assembly-point rule was **not** loosened, and the last case here is
 * its pin: the two-step workaround is still refused, so `tray=merge` remains
 * the only spelling and there is still exactly one place in a pipeline where a
 * set is assembled.
 *
 * The pin's *wording* moved once, deliberately. It used to read "Only one
 * shares step is supported per pipeline", which was one document-wide boolean
 * doing two jobs: this rule, and "one step may read the Inputs → shares tray,
 * because there is one tray". The second job is per *machine* rather than per
 * document — two peers each collecting into their own tray is the ordinary
 * multi-peer notebook and it would not compile — so the two were separated,
 * and each now says what it enforces. This one is still per pipeline, which is
 * what its old sentence claimed and what nothing was actually doing.
 */
import { generateKey } from "openpgp";
import { describe, expect, it } from "vitest";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe, serializeRecipe, unresolvedInputs } from "../lib/toolkit/recipe.js";
import { combineShares } from "../lib/slip39/slip39.js";

/** A message encrypted to a fresh key, with the key to open it. */
async function sealed(text) {
  const { privateKey, publicKey } = await generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ name: "Custodian", email: "custodian@example.com" }],
    format: "object",
  });
  const { encrypt, createMessage } = await import("openpgp");
  const armoredMessage = await encrypt({
    message: await createMessage({ text }),
    encryptionKeys: publicKey,
  });
  return { armoredMessage: String(armoredMessage), privateKeyArmored: privateKey.armor() };
}

/** Three real mnemonics of one 2-of-3 split, plus the secret they rebuild. */
async function deal() {
  const { ast, validation } = compileRecipe(
    "random 32 | sss.split threshold=2 shares=3 | blip39 | foreach\n  - out $share"
  );
  expect(validation.errors.map((e) => e.message)).toEqual([]);
  const arts = await runRecipe(ast);
  const cards = arts.filter((a) => a.shareIndex).map((a) => String(a.content));
  expect(cards).toHaveLength(3);
  return cards;
}

/** What `sss.combine` of two cards should print, computed by the codec itself. */
async function hexOf(cards) {
  const bytes = await combineShares(cards);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Run the hybrid recipe with one share sealed to a key and the rest in the tray. */
async function runHybrid(source, sealedCard, trayCards) {
  const { ast, validation } = compileRecipe(source);
  expect(validation.errors.map((e) => e.message)).toEqual([]);
  return runRecipe(ast, {
    inputs: {
      gpg: {
        armoredMessages: [sealedCard.armoredMessage],
        privateKeyArmored: sealedCard.privateKeyArmored,
        passphrase: "",
      },
      shares: { mnemonics: trayCards },
    },
  });
}

const HYBRID = "gpg.decrypt count=all | shares tray=merge | blip39 -d | sss.combine | encode hex";

describe("the hybrid recovers in one cell", () => {
  it("merges a share this browser opened with one a custodian typed", async () => {
    // The capability itself, on the real spelling rather than a stand-in: the
    // ciphertext road is `gpg.decrypt count=all`, which is what a custodian
    // holding an OpenPGP message actually writes, and the typed road is the
    // share rows. Two shares of a 2-of-3 arrive by two roads and the secret
    // comes back.
    const cards = await deal();
    const arts = await runHybrid(HYBRID, await sealed(cards[0]), [cards[1]]);
    const want = await hexOf([cards[0], cards[1]]);
    expect(arts.map((a) => String(a.content))).toContain(want);
  }, 120_000);

  it("recovers this split's secret and not merely thirty-two bytes", async () => {
    // The control that keeps the case above from being a tautology. Which two
    // of the three arrive is deliberately different here — card 3 down the
    // ciphertext road, card 1 typed — because any 2 of a 2-of-3 rebuild the
    // same secret, and a recovery that only ever worked for one pairing would
    // be reading a position rather than a share index out of the header. The
    // second deal is the negative: an unrelated split's secret is what "some
    // bytes came back" would look like.
    const cards = await deal();
    const unrelated = await deal();
    const arts = await runHybrid(HYBRID, await sealed(cards[2]), [cards[0]]);
    const want = await hexOf([cards[2], cards[0]]);
    expect(want).not.toBe(await hexOf(unrelated.slice(0, 2)));
    expect(want).toBe(await hexOf([cards[0], cards[1]]));
    expect(arts.map((a) => String(a.content))).toContain(want);
  }, 120_000);
});

describe("the merge is in the text, or it does not happen", () => {
  it("survives serializeRecipe unchanged", async () => {
    // A word that the round trip eats is not in the text. The chip flow
    // re-serializes on every edit and Copy link serializes to build the URL,
    // so a `tray=` that vanished there would put the two ends of a share link
    // on different recoveries.
    const { ast, validation } = compileRecipe(HYBRID);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    expect(serializeRecipe(ast)).toContain("shares tray=merge");
    expect(serializeRecipe(compileRecipe(serializeRecipe(ast)).ast)).toBe(serializeRecipe(ast));
  });

  it("leaves the default spelling out of the text entirely", async () => {
    // The other half: `fallback` is what a bare `shares` has always meant, so
    // it must serialize away. Otherwise every recipe in the corpus grows a
    // token, every saved notebook rewrites itself on load, and the shared
    // manifests of two builds stop matching.
    const bare = serializeRecipe(compileRecipe("shares | blip39 -d | sss.combine").ast);
    expect(bare).toBe("shares | blip39.decode | sss.combine");
    expect(bare).not.toContain("tray");
  });

  it("asks for the tray panel even when the pipe is full", async () => {
    // Without this the word would be unusable on the surface it exists for:
    // the shares panel is declared only for a cell that names nothing, so a
    // `gpg.decrypt | shares` cell hides the very rows a merge is meant to read.
    const need = unresolvedInputs(compileRecipe(HYBRID).ast);
    expect(need).toContain("shares");
    expect(need).toContain("gpg");
    // The control: the same pipeline without the word wants only the
    // ciphertext, so the declaration is doing the work and not a blanket.
    const bare = unresolvedInputs(
      compileRecipe("gpg.decrypt count=all | shares | blip39 -d | sss.combine").ast
    );
    expect(bare).toEqual(["gpg"]);
  });
});

describe("an unspelled pairing refuses instead of choosing", () => {
  it("names both counts and two remedies the reader can perform", async () => {
    const cards = await deal();
    let said = "";
    try {
      await runHybrid(
        "gpg.decrypt count=all | shares | blip39 -d | sss.combine | encode hex",
        await sealed(cards[0]),
        [cards[1]]
      );
      said = "no refusal";
    } catch (err) {
      said = String(err?.message || err);
    }
    // The state, both halves of it, as counts rather than as a category.
    expect(said, `the refusal: ${said}`).toContain("the recipe names 1 share");
    expect(said, `the refusal: ${said}`).toContain("the Inputs tray holds 1 more");
    // Both remedies are acts available on the screen the reader is looking at:
    // type a word into this cell, or empty the rows beside it. Neither names
    // another machine, another cell or a file this product cannot accept.
    expect(said, `the refusal: ${said}`).toContain("shares tray=merge");
    expect(said, `the refusal: ${said}`).toContain("clear the share rows");
    // And never the words on a card: a refusal is copied into chats.
    for (const card of cards) {
      expect(said).not.toContain(card.split(/\s+/).slice(0, 4).join(" "));
    }
  }, 120_000);

  it("does not fire when the tray is empty — the recipe still wins alone", async () => {
    // The control for the refusal, and the pin on the rule that was *not*
    // loosened: with nothing typed, a recipe naming its own shares runs exactly
    // as it did before, tray precedence and all.
    const cards = await deal();
    const { ast } = compileRecipe(
      "gpg.decrypt count=all | shares | blip39 -d | sss.combine | encode hex"
    );
    const s = await sealed(`${cards[0]}\n`);
    await expect(
      runRecipe(ast, {
        inputs: {
          gpg: {
            armoredMessages: [s.armoredMessage],
            privateKeyArmored: s.privateKeyArmored,
            passphrase: "",
          },
          shares: { mnemonics: ["", "   "] },
        },
      })
    ).rejects.toThrow(/Need at least 2 shares, got 1/);
  }, 120_000);

  it("still collects from the tray when the recipe names nothing", async () => {
    // The oldest road, unchanged: `CUSTODIAN_RECOVERY` is this line, and it is
    // what a holder of two cards and no ciphertext runs.
    const cards = await deal();
    const { ast } = compileRecipe("shares | blip39 -d | sss.combine | encode hex");
    const arts = await runRecipe(ast, {
      inputs: { shares: { mnemonics: [cards[0], cards[2]] } },
    });
    expect(arts.map((a) => String(a.content))).toContain(await hexOf([cards[0], cards[2]]));
  }, 120_000);
});

describe("a merged set is still one set of distinct shares", () => {
  it("refuses the same card arriving down both roads", async () => {
    // The likelier hybrid mistake by far: a custodian decrypts their card in
    // Kleopatra, pastes it, and leaves the ciphertext in the GPG panel too. Two
    // copies of one point on the polynomial recover nothing, and interpolation
    // would hand back "GF division by zero" three steps downstream. The set id
    // and index in each mnemonic's own header are what makes the two roads
    // comparable without anybody having labelled them.
    const cards = await deal();
    let said = "";
    try {
      await runHybrid(HYBRID, await sealed(cards[0]), [cards[0]]);
      said = "no refusal";
    } catch (err) {
      said = String(err?.message || err);
    }
    expect(said, `the refusal: ${said}`).toContain("are the same share");
    expect(said, `the refusal: ${said}`).toMatch(/number 1 of set [0-9A-F]{4}/);
    // Which roads, not which row numbers: a merge has no numbered list, and a
    // reader told "row 2" of an ordering this step invented cannot find it.
    expect(said, `the refusal: ${said}`).toContain("the Inputs tray");
    expect(said, `the refusal: ${said}`).toContain("piped into");
  }, 120_000);

  it("refuses two roads carrying two different splits, naming both", async () => {
    // The outcome this project counts among its worst: two internally valid
    // mnemonics from two ceremonies do not fail to combine, they combine into
    // thirty-two bytes that are nobody's secret, with no error at all. Before
    // the merge existed, two splits could only meet inside one numbered tray;
    // now they can meet across roads, so the guard is where the meeting is.
    const mine = await deal();
    const stranger = await deal();
    let said = "";
    try {
      await runHybrid(HYBRID, await sealed(mine[0]), [stranger[1]]);
      said = "no refusal";
    } catch (err) {
      said = String(err?.message || err);
    }
    expect(said, `the refusal: ${said}`).toContain("more than one split");
    expect(said, `the refusal: ${said}`).toContain("returns a different secret");
    // Two distinct set ids, each attributed to the road that carried it. One id
    // printed twice would satisfy a laxer pattern and say nothing.
    const named = [...said.matchAll(/set ([0-9A-F]{4}) from ([^;.]+)/g)];
    expect(named.map((m) => m[1]), `the refusal: ${said}`).toHaveLength(2);
    expect(new Set(named.map((m) => m[1])).size, `the refusal: ${said}`).toBe(2);
    expect(named.map((m) => m[2].trim())).toContain("the Inputs tray");
  }, 120_000);

  it("leaves the row-numbered message alone when there is one road", async () => {
    // The pin that the new refusal did not swallow the old one. Two strangers
    // typed into two rows *do* have a numbered list — the person made it — so
    // `decodeShareSet` keeps saying "row 1 is from set …", which is the wording
    // `custodian-recovery` drives through the real UI.
    const mine = await deal();
    const stranger = await deal();
    const { ast } = compileRecipe("shares | blip39 -d | sss.combine | encode hex");
    let said = "";
    try {
      await runRecipe(ast, { inputs: { shares: { mnemonics: [mine[0], stranger[1]] } } });
      said = "no refusal";
    } catch (err) {
      said = String(err?.message || err);
    }
    expect(said, `the refusal: ${said}`).toContain("Share set ID mismatch");
    expect(said, `the refusal: ${said}`).toMatch(/row 1 is from set [0-9A-F]{4}/);
    expect(said, `the refusal: ${said}`).not.toContain("more than one split");
  }, 120_000);
});

describe("the rule that was not loosened", () => {
  it("still refuses a second shares step in one pipeline", () => {
    // The two-step workaround `a0c34cf` named as the other road to the hybrid.
    // It stays closed, so `tray=merge` is the only spelling and a reader still
    // has exactly one step to look at to know what went into a set. Neither
    // `shares` here reads the tray — the set comes down the pipe — so this is
    // pinning the assembly-point rule and nothing else: if it were the panel
    // rule wearing this name, this line would compile.
    const { validation } = compileRecipe(
      "gpg.decrypt count=all | shares | blip39 -d | shares | blip39 -d | sss.combine"
    );
    const said = validation.errors.map((e) => e.message).join("\n");
    expect(said).toContain("assembles its share set in one place");
    // The remedy is the spelling that exists, named where it can be read.
    expect(said).toContain("tray=merge");
  });

  it("does not spend the pipeline's one assembly point on another cell's", () => {
    // The half that moved. Two peers each collecting their own set is two
    // pipelines, not one, and each has its own tray on its own machine.
    const two = compileRecipe(
      ["@ALICE", "shares | blip39 -d | out $a", "", "@BOB", "shares | blip39 -d | out $b"].join(
        "\n"
      )
    );
    expect(two.validation.errors.map((e) => e.message)).toEqual([]);
    expect(two.validation.ok).toBe(true);
  });
});
