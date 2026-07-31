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

/**
 * Run a real verifiable ceremony split and hand back the printed artifacts a
 * custodian would actually be holding.
 */
async function realSplit({ threshold = 2, shares = 3 } = {}) {
  const { ast } = compileRecipe(
    `random 32 | vss.split threshold=${threshold} shares=${shares} | tee
  - vss.commitments | out @commitments
| blip39 | foreach
  - out @share`
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
  - out @share`
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
    expect(recipe).toContain("vss.verify commitments=@commitments");
    const { ast } = compileRecipe(recipe);
    expect(ast?.chains?.length).toBe(1);
  });
});
