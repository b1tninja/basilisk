/**
 * The three refusals a recovery can end at, and what each of them says.
 *
 * A plain Shamir recombination of the wrong set of shares does not error — it
 * interpolates whatever it was given and returns *a different secret*. So the
 * refusals below are not error handling; they are the only thing between a
 * custodian and a wrong answer that looks exactly like a right one, and the
 * assertions that matter are about their wording rather than about the fact
 * that something was thrown.
 *
 * They are tested here, at the layer that composes the sentence, rather than
 * only through `custodian-recovery.e2e.js`. That file drives the same three
 * failures through two real browsers and is where "a person can read this off
 * a screen" is settled; this one is where the *text* is pinned, because a
 * browser assertion that a message contains four hex digits cannot say they
 * are the right four, and a wording regression is cheap to catch and expensive
 * to notice.
 *
 * Each refusal is held to one rule: **name the state that is actually true,
 * and never a remedy that cannot be performed.** For a share that means the
 * row it was pasted into and the set it belongs to — and never the words,
 * which are the share itself and would end up in an error box, a screenshot
 * and a chat thread.
 */
import { describe, expect, it } from "vitest";
import {
  decodeShareSet,
  encodeShareSet,
  formatSetId,
  readShareHeader,
} from "../lib/slip39/blip39.js";
import { combineRawShares, splitRawShares } from "../lib/slip39/slip39.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

/** One 2-of-3, minted the way `sss.split | blip39` mints one. */
async function deal(fill) {
  const secret = new Uint8Array(32).fill(fill);
  return encodeShareSet(await splitRawShares(secret, { threshold: 2, shares: 3 }));
}

/** Swap one word for another legal word, so only the checksum can object. */
function corrupt(mnemonic, donor) {
  const words = mnemonic.split(/\s+/);
  const swapTo = donor.split(/\s+/).find((w) => w !== words[3]) || donor.split(/\s+/)[0];
  return [...words.slice(0, 3), swapTo, ...words.slice(4)].join(" ");
}

/** The first four words of a card — a sequence only that card has. */
const opening = (m) => m.split(/\s+/).slice(0, 4).join(" ");

describe("the set id every surface spells", () => {
  it("is four upper-case hex digits of the low fifteen bits", () => {
    // Pinned against literals rather than against another call, and that is
    // the whole point of this test existing beside the ones below. Those
    // compare a refusal's set id with `formatSetId`'s own answer, which is the
    // property a custodian needs — the message and the check panel agreeing —
    // but it is a comparison both sides of which move together, so a codec
    // that started printing `set 17998` would satisfy every one of them. Four
    // hex digits is the fact a person is holding a card against.
    expect(formatSetId(0x465e)).toBe("465E");
    expect(formatSetId(0x000f)).toBe("000F");
    expect(formatSetId(0)).toBe("0000");
    // The header carries fifteen bits, so the sixteenth is not part of the
    // name — `encodeMnemonic` masks it away and this must mask the same one.
    expect(formatSetId(0xffff)).toBe("7FFF");
  });
});

describe("a share from another split", () => {
  it("is caught, because combining across sets is silent and wrong", async () => {
    const a = await deal(0x11);
    const b = await deal(0x22);
    // Share 2 of one set with share 3 of the other: different indices, so
    // `interpolate` never divides by zero and nothing downstream objects. This
    // is the case the guard exists for, and it is asserted first because
    // without it the refusal is a nicety rather than the whole defence.
    const raw = [a.mnemonics[1], b.mnemonics[2]].map((m) => {
      const d = readShareHeader(m);
      return { index: d.index, data: decodeShareSet([m]).raw[0].data };
    });
    const wrong = await combineRawShares({
      encoding: "raw",
      raw,
      threshold: 2,
      shares: 3,
      flags: 0,
    });
    expect(wrong, "cross-set combination stopped producing bytes").toHaveLength(32);
    expect([...wrong].every((x) => x === 0x11)).toBe(false);
    expect([...wrong].every((x) => x === 0x22)).toBe(false);
  });

  it("names every row with the set it came from, and never the words", async () => {
    const a = await deal(0x33);
    const b = await deal(0x44);
    let said = "";
    try {
      decodeShareSet([a.mnemonics[1], b.mnemonics[2]]);
      expect.unreachable("two sets recombined without objecting");
    } catch (err) {
      said = err.message;
    }
    expect(said).toContain("Share set ID mismatch");
    // The row, and the set it is from — the two facts a person acts on. The set
    // ids are compared against `formatSetId`'s own answer rather than a regex,
    // because "four hex digits" and "the right four hex digits" are different
    // claims and only the second is worth anything to a custodian holding a
    // card whose id they have read off the check panel.
    expect(said).toContain(`row 1 is from set ${formatSetId(a.id)}`);
    expect(said).toContain(`row 2 is from set ${formatSetId(b.id)}`);
    // Why it is caught here: the sentence that stops a reader assuming a
    // stricter tool would simply have worked.
    expect(said).toContain("returns a different secret");
    // And not the share.
    expect(said).not.toContain(opening(a.mnemonics[1]));
    expect(said).not.toContain(opening(b.mnemonics[2]));
  });

  it("groups rows by set rather than listing one clause per card", async () => {
    const a = await deal(0x55);
    const b = await deal(0x66);
    let said = "";
    try {
      decodeShareSet([a.mnemonics[0], a.mnemonics[1], b.mnemonics[2]]);
      expect.unreachable("three shares across two sets recombined without objecting");
    } catch (err) {
      said = err.message;
    }
    // With more than two cards the minority is what a reader is looking for,
    // and a per-row list buries it. Grouped, the odd one out is the short side.
    expect(said).toContain(`rows 1 and 2 are from set ${formatSetId(a.id)}`);
    expect(said).toContain(`row 3 is from set ${formatSetId(b.id)}`);
  });
});

describe("a card with one word wrong", () => {
  it("names the row it was pasted into, and says the others read", async () => {
    const a = await deal(0x77);
    const bad = corrupt(a.mnemonics[2], a.mnemonics[1]);
    let said = "";
    try {
      decodeShareSet([a.mnemonics[1], bad]);
      expect.unreachable("a corrupted mnemonic decoded");
    } catch (err) {
      said = err.message;
    }
    expect(said).toContain("Invalid share checksum");
    expect(said).toContain("Row 2 of the 2 pasted shares is not readable");
    // The clause that stops a custodian re-typing both cards, and the reason it
    // is knowable at all: every row is decoded before anything is thrown.
    expect(said).toContain("The other row decoded cleanly");
    expect(said).not.toContain(opening(bad));
    expect(said).not.toContain(opening(a.mnemonics[1]));
  });

  it("reports every unreadable row, not the first one it met", async () => {
    const a = await deal(0x88);
    const bad2 = corrupt(a.mnemonics[1], a.mnemonics[0]);
    const bad3 = corrupt(a.mnemonics[2], a.mnemonics[0]);
    let said = "";
    try {
      decodeShareSet([a.mnemonics[0], bad2, bad3]);
      expect.unreachable("two corrupted mnemonics decoded");
    } catch (err) {
      said = err.message;
    }
    // `.map` gave up on the first failure, so row 3 was never read and could
    // not have been named. This is the assertion that the change of shape —
    // decode everything, then throw — is the thing doing the work.
    expect(said).toContain("2 of the 3 pasted shares are not readable");
    expect(said).toContain("row 2:");
    expect(said).toContain("row 3:");
    expect(said).toContain("The other row decoded cleanly");
  });
});

describe("a recovery that is short of shares", () => {
  /** Two cards of a 2-of-3, minted through the language. */
  async function cards() {
    const { ast, validation } = compileRecipe(
      "random 32 | sss.split threshold=2 shares=3 | blip39 | out $set"
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    const arts = await runRecipe(ast);
    return arts.filter((a) => a.shareIndex).map((a) => String(a.content));
  }

  const RECOVER = "shares | blip39 -d | sss.combine | encode hex | out $back";

  it("tells a custodian with a card to add a card, and does not mention GPG", async () => {
    const [, second] = await cards();
    const { ast } = compileRecipe(RECOVER);
    let said = "";
    try {
      await runRecipe(ast, { inputs: { shares: { mnemonics: [second] } } });
      expect.unreachable("one share of a 2-of-3 recombined into something");
    } catch (err) {
      said = err.message;
    }
    expect(said).toContain("Need at least 2 shares, got 1");
    expect(said).toContain("Paste one more card's mnemonic into the share rows");
    // Why any card will do. Without it "get another one" sends a person to ask
    // the dealer which, and the dealer is the party this ceremony is designed
    // to be able to do without.
    expect(said).toContain("Any 2 shares of this split rebuild it");
    // The whole of finding 3a: this reader has no ciphertext, so nothing may
    // send them to a panel holding none.
    expect(said).not.toMatch(/Kleopatra|GPG panel|OpenPGP/i);
  });

  it("names the GPG panel only when the GPG panel is holding something", async () => {
    const [, second] = await cards();
    const { ast } = compileRecipe(RECOVER);
    let said = "";
    try {
      await runRecipe(ast, {
        inputs: {
          shares: { mnemonics: [second] },
          // One armored block that is not a share this browser can open — the
          // hybrid state the old appendix was written for, and the only state
          // in which naming it is a remedy rather than a distraction.
          gpg: { armoredMessages: ["-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----"] },
        },
      });
      expect.unreachable("one share of a 2-of-3 recombined into something");
    } catch (err) {
      said = err.message;
    }
    expect(said).toContain("Need at least 2 shares, got 1");
    expect(said).toContain("The GPG panel holds 1 OpenPGP message");
    expect(said).toContain("Kleopatra");
    // And still the act that works for everybody: paste the card.
    expect(said).toContain("one more card's mnemonic");
  });

  it("does not send a recipe-fed recovery to a tray it never used", async () => {
    const [first] = await cards();
    // The shares arrive down the pipe and out of a slot, which is the room
    // ceremony's shape — so "paste it in the share rows" would name a panel
    // this run has not been near.
    const { ast, validation } = compileRecipe(
      [`"${first}" | out $mine`, "$mine | shares | blip39 -d | sss.combine | out $secret"].join(
        "\n\n"
      )
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    let said = "";
    try {
      await runRecipe(ast, {});
      expect.unreachable("one share of a 2-of-3 recombined into something");
    } catch (err) {
      said = err.message;
    }
    expect(said).toContain("Need at least 2 shares, got 1");
    expect(said).toContain("reached this step from the recipe rather than from the Inputs tray");
    expect(said).not.toContain("Paste one more card's mnemonic into the share rows");
  });
});
