/**
 * The custodian check — the verdicts, against shares a real ceremony produces.
 *
 * These assert *wording*, not just status codes, and deliberately so. The whole
 * value of this surface is that it never says more than it checked, and the
 * only way that claim can be pinned is to pin the sentences. A status enum
 * would let "well-formed" quietly start rendering as reassurance.
 */
import { describe, expect, it } from "vitest";
import {
  checkShare,
  readCommitments,
  readShareMnemonic,
  shareCheckRecipe,
  splitIdFor,
} from "../lib/toolkit/share-check.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { CUSTODIAN_RECOVERY } from "../lib/toolkit/room-recovery.js";

/**
 * Run a real verifiable ceremony split and hand back the printed artifacts a
 * custodian would actually be holding.
 */
async function realSplit({ threshold = 2, shares = 3 } = {}) {
  const { ast } = compileRecipe(
    `random 32 | vss.split threshold=${threshold} shares=${shares} | tee
  - vss.commitments | out $commitments
| blip39 | foreach
  - out $share`
  );
  const arts = await runRecipe(ast);
  const mnemonics = arts
    .filter((a) => a.role === "share")
    .sort((a, b) => (a.shareIndex || 0) - (b.shareIndex || 0))
    .map((a) => String(a.content || "").trim());
  const commitments = arts
    .map((a) => String(a.content || "").trim())
    .find((t) => t.startsWith("{") && t.includes("commitments"));
  return { mnemonics, commitments };
}

describe("readShareMnemonic", () => {
  it("reports nothing at all for empty input", () => {
    const r = readShareMnemonic("   ");
    expect(r.empty).toBe(true);
    expect(r.facts).toBeNull();
  });

  it("reads index, total and threshold off a real card", async () => {
    const { mnemonics } = await realSplit({ threshold: 2, shares: 3 });
    const r = readShareMnemonic(mnemonics[1]);
    expect(r.ok).toBe(true);
    expect(r.facts.index).toBe(2);
    expect(r.facts.total).toBe(3);
    expect(r.facts.threshold).toBe(2);
    expect(r.facts.setId).toMatch(/^[0-9A-F]{4}$/);
  }, 30_000);

  it("refuses a mnemonic with a word swapped", async () => {
    const { mnemonics } = await realSplit();
    const words = mnemonics[0].split(/\s+/);
    words[3] = words[3] === "acid" ? "acne" : "acid";
    const r = readShareMnemonic(words.join(" "));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/checksum/i);
  }, 30_000);
});

describe("readCommitments", () => {
  it("accepts the JSON that vss.commitments writes", async () => {
    const { commitments } = await realSplit();
    const r = readCommitments(commitments);
    expect(r.ok).toBe(true);
    expect(r.facts.commitments.length).toBeGreaterThan(1);
    // Degree = threshold - 1; a 2-of-3 split commits to a line.
    expect(r.facts.degree).toBe(1);
    expect(r.facts.splitId).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
  }, 30_000);

  it("accepts a bare array and a whitespace-separated hex list", async () => {
    const { commitments } = await realSplit();
    const list = JSON.parse(commitments).commitments;
    expect(readCommitments(JSON.stringify(list)).ok).toBe(true);
    expect(readCommitments(list.join("\n")).ok).toBe(true);
  }, 30_000);

  it("names the problem rather than throwing on junk", () => {
    expect(readCommitments("hello").error).toMatch(/commitments document/i);
    expect(readCommitments('{"commitments":["02ff"]}').error).toMatch(/P-256/);
  });
});

describe("splitIdFor", () => {
  it("drops the parity prefix and groups the rest for reading aloud", () => {
    expect(splitIdFor(`02${"a".repeat(64)}`)).toBe("AAAA-AAAA-AAAA");
  });

  it("returns nothing for nothing, rather than a plausible-looking id", () => {
    expect(splitIdFor("")).toBe("");
  });
});

describe("checkShare", () => {
  it("says nothing has been checked when only the share is present", async () => {
    const { mnemonics } = await realSplit();
    const v = checkShare({ shareText: mnemonics[0] });
    expect(v.status).toBe("share-only");
    // Not `ok`. A decode success must never reach the verified appearance.
    expect(v.tone).toBe("warn");
    expect(v.headline).toMatch(/unverified/i);
    expect(v.detail).toMatch(/Nothing has been checked/);
  }, 30_000);

  it("verifies a genuine share against the published commitments", async () => {
    const { mnemonics, commitments } = await realSplit({ threshold: 2, shares: 3 });
    for (const m of mnemonics) {
      const v = checkShare({ shareText: m, commitmentsText: commitments });
      expect(v.status).toBe("verified");
      expect(v.tone).toBe("ok");
      expect(v.headline).toMatch(/is genuine/);
      expect(v.split.splitId).toBeTruthy();
    }
  }, 30_000);

  it("rejects a share from a different split, and does not blame the holder", async () => {
    const a = await realSplit();
    const b = await realSplit();
    const v = checkShare({ shareText: a.mnemonics[0], commitmentsText: b.commitments });
    expect(v.status).toBe("mismatch");
    expect(v.tone).toBe("error");
    // The three indistinguishable causes are all named — the checksum has
    // already ruled out the one a user would assume.
    expect(v.detail).toMatch(/not a typing mistake/);
    expect(v.detail).toMatch(/another ceremony/);
    expect(v.detail).toMatch(/sss\.split/);
  }, 30_000);

  it("rejects an sss share without pretending it could ever have passed", async () => {
    const { ast } = compileRecipe(
      `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`
    );
    const arts = await runRecipe(ast);
    const mnemonic = String(arts.find((a) => a.role === "share")?.content || "").trim();
    const { commitments } = await realSplit();
    const v = checkShare({ shareText: mnemonic, commitmentsText: commitments });
    expect(v.status).toBe("mismatch");
  }, 30_000);

  it("distinguishes an unreadable share from unreadable commitments", async () => {
    const { commitments } = await realSplit();
    expect(checkShare({ shareText: "not a mnemonic", commitmentsText: commitments }).status).toBe(
      "bad-share"
    );
    const { mnemonics } = await realSplit();
    expect(checkShare({ shareText: mnemonics[0], commitmentsText: "junk" }).status).toBe(
      "bad-commitments"
    );
  }, 30_000);

  it("offers a recipe that uses only registered ops", () => {
    const recipe = shareCheckRecipe();
    expect(recipe).toContain("blip39.decode");
    expect(recipe).toContain("vss.verify commitments=$commitments");
    const { ast } = compileRecipe(recipe);
    expect(ast?.chains?.length).toBe(1);
  });
});

/**
 * The plain-Shamir road — `custodian-recovery.e2e.js` finding 2b.
 *
 * The whole risk on this branch is a panel that, having lost the one real
 * check it had, reaches for reassurance instead. So these assert the negative
 * space as hard as the positive: what the header proves, and — in the same
 * verdict — that it does not prove reconstruction, does not identify the
 * split, and has no commitments coming.
 */
describe("checkShare on the sss road", () => {
  /** One card off a real `sss.split`, which is what the room ceremony deals. */
  async function realSssCard({ threshold = 2, shares = 3 } = {}) {
    const { ast } = compileRecipe(
      `random 32 | sss.split threshold=${threshold} shares=${shares} | blip39 | foreach
  - out $share`
    );
    const arts = await runRecipe(ast);
    return arts
      .filter((a) => a.role === "share")
      .sort((x, y) => (x.shareIndex || 0) - (y.shareIndex || 0))
      .map((a) => String(a.content || "").trim());
  }

  it("reads the header and says in the same breath that it proves no such thing", async () => {
    const cards = await realSssCard();
    const v = checkShare({ shareText: cards[1], scheme: "sss" });
    expect(v.status).toBe("header-only");
    // Never `ok`. This is the one line that would undo the whole branch: a
    // reader who sees a green verdict has been told their card is good, and
    // nothing here checked anything.
    expect(v.tone).toBe("warn");
    expect(v.headline).toMatch(/^Share 2 of 3 — a well-formed card from set [0-9A-F]{4}\.$/);
    // What it does prove — the checksum, and the header's own four facts.
    expect(v.detail).toMatch(/checksum passed/);
    expect(v.detail).toMatch(/share 2 of 3 in set [0-9A-F]{4} with any 2 recombining/);
    // What it does not, said as denials rather than left to inference.
    expect(v.detail).toMatch(/not a check that this card came from the split you think it did/);
    expect(v.detail).toMatch(/does not show that it will reconstruct/);
    expect(v.detail).toMatch(/another ceremony decodes exactly this cleanly/);
    // And the reason the other road is not offered: the document does not
    // exist, rather than being missing.
    expect(v.detail).toMatch(/sss\.split does not produce any/);
    // The road that does exist, named as a later comparison and not as a
    // verdict this panel reached.
    expect(v.detail).toMatch(/\$expected/);
    expect(v.detail).toMatch(/proves the recombination — not this card/);
  }, 30_000);

  it("never reports a split on this road, whatever is in the commitments box", async () => {
    const cards = await realSssCard();
    const { commitments } = await realSplit();
    // The surface stops drawing the field, but the model is what must not
    // wobble: a stale value left behind by a scheme switch must not put a
    // split id back beside a card that has no relationship to it.
    const v = checkShare({ shareText: cards[0], commitmentsText: commitments, scheme: "sss" });
    expect(v.status).toBe("header-only");
    expect(v.split).toBeNull();
    expect(v.commitmentsError).toBe("");
  }, 30_000);

  it("still catches a mistyped card, with the same sentence as the other road", async () => {
    const v = checkShare({ shareText: "acid academic not a mnemonic", scheme: "sss" });
    expect(v.status).toBe("bad-share");
    expect(v.tone).toBe("error");
    expect(v.detail).toMatch(/carries a checksum/);
  });

  it("asks for the card and nothing else when the panel is empty", () => {
    const v = checkShare({ scheme: "sss" });
    expect(v.status).toBe("empty");
    // The vss road's empty state asks for "the commitments the ceremony
    // published" too. On this road that sentence names a document nobody can
    // fetch, which is finding 2b one state earlier than where it was found.
    expect(v.detail).not.toMatch(/commitments/i);
    expect(v.detail).toMatch(/Paste the mnemonic from your card/);
  });

  it("prints the recovery rather than a check that cannot succeed for this card", () => {
    const recipe = shareCheckRecipe("sss");
    // It is `room-recovery.js`'s own text, so the panel and the picker cannot
    // hold two spellings of what recovery is.
    expect(recipe).toBe(CUSTODIAN_RECOVERY);
    expect(recipe).toContain("sss.combine");
    expect(recipe).toContain("digest sha-256");
    // And emphatically not the op that can never pass here — the exact thing
    // the custodian was previously handed to copy.
    expect(recipe).not.toContain("vss.verify");
    const { ast } = compileRecipe(recipe);
    expect(ast?.chains?.length).toBe(1);
  });

  it("leaves the verifiable road exactly where it was", async () => {
    const { mnemonics, commitments } = await realSplit();
    const v = checkShare({ shareText: mnemonics[0], commitmentsText: commitments, scheme: "vss" });
    expect(v.status).toBe("verified");
    expect(shareCheckRecipe("vss")).toContain("vss.verify commitments=$commitments");
    // The default is still the verifiable road, so every existing caller that
    // names no scheme is unmoved. The *surface* opens on sss when nobody hands
    // it commitments; that choice belongs to the widget, not here.
    expect(shareCheckRecipe()).toBe(shareCheckRecipe("vss"));
  }, 30_000);

  it("tells the share-only reader that the other road exists", async () => {
    const { mnemonics } = await realSplit();
    const v = checkShare({ shareText: mnemonics[0] });
    expect(v.status).toBe("share-only");
    // The old copy's only exit was "paste the published commitments", and a
    // custodian holding an sss card could not perform it. Both exits now.
    expect(v.detail).toMatch(/Paste the published commitments/);
    expect(v.detail).toMatch(/publishes no commitments and never will/);
  }, 30_000);
});
