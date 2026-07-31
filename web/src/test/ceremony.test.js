/**
 * The guided key ceremony's stage machine and its recipes.
 *
 * The property that matters most is negative and easy to regress: the master
 * secret must never reach a revealable `out` tile, and verification must
 * conclude "these match" from digests alone. Both are asserted against a real
 * run through the kernel, not against the recipe text.
 */
import { describe, expect, it } from "vitest";
import {
  CEREMONY_STAGES,
  ceremonyCells,
  ceremonyIssues,
  ceremonyTitle,
  nextStage,
  prevStage,
  receiptRecipe,
  splitRecipe,
  stageIndex,
  tileForSlot,
  verificationResult,
  verifyRecipe,
} from "../lib/toolkit/ceremony.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { createKernel } from "../lib/toolkit/kernel.js";
import { collectShareCards } from "../lib/toolkit/share-cards.js";
import { parseReceipt } from "../lib/toolkit/receipt.js";

describe("stage machine", () => {
  it("runs setup → split → verify → cards → receipt", () => {
    expect(CEREMONY_STAGES.map((s) => s.id)).toEqual([
      "setup",
      "split",
      "verify",
      "cards",
      "receipt",
    ]);
  });

  it("walks forwards and backwards, and stops at the ends", () => {
    expect(nextStage("setup")).toBe("split");
    expect(nextStage("receipt")).toBeNull();
    expect(prevStage("split")).toBe("setup");
    expect(prevStage("setup")).toBeNull();
    expect(stageIndex("cards")).toBe(3);
  });

  it("puts the verification step before the printing step", () => {
    // Proving the shares work after the room has dispersed is not a ceremony.
    expect(stageIndex("verify")).toBeLessThan(stageIndex("cards"));
  });
});

describe("quorum validation", () => {
  it("accepts an ordinary quorum", () => {
    expect(ceremonyIssues({ threshold: 3, shares: 5 })).toEqual([]);
  });

  it("catches a threshold above the share count", () => {
    const issues = ceremonyIssues({ threshold: 5, shares: 3 });
    expect(issues.some((i) => /cannot be required/.test(i))).toBe(true);
  });

  it("calls a threshold of 1 what it is", () => {
    expect(ceremonyIssues({ threshold: 1, shares: 3 }).join(" ")).toMatch(
      /copy, not a quorum/
    );
  });

  it("rejects out-of-range and non-integer counts", () => {
    expect(ceremonyIssues({ threshold: 2, shares: 1 })).not.toEqual([]);
    expect(ceremonyIssues({ threshold: 2, shares: 99 })).not.toEqual([]);
    expect(ceremonyIssues({ threshold: 2.5, shares: 3 })).not.toEqual([]);
  });
});

describe("recipes", () => {
  const params = { threshold: 2, shares: 3, label: "Board key", qr: true };

  it("compiles every cell the ceremony will add", () => {
    // Compiled together, because that is what they are: the Sheet appends
    // them to one notebook, and the verify cell reads `@commitments` from the
    // split cell. Compiling each in isolation would report a missing slot
    // that never happens in the flow.
    const notebook = ceremonyCells(params)
      .map((c) => c.recipe)
      .join("\n\n");
    const { validation } = compileRecipe(notebook);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
  });

  it("never writes the master to an out tile", () => {
    // The tee branch digests it in place; `out @master` would put the secret
    // one click from the screen for the rest of the session.
    expect(splitRecipe(params)).not.toMatch(/out @master/);
    expect(splitRecipe(params)).toContain("digest | encode hex | out @expected");
  });

  it("carries the chosen threshold and share count into the split", () => {
    expect(splitRecipe({ threshold: 3, shares: 5 })).toContain(
      "vss.split threshold=3 shares=5"
    );
  });

  it("splits verifiably, and publishes the commitments that make it so", () => {
    // The difference a ceremony actually feels: a custodian can check the
    // share they were handed, at the table. Without the commitments leaving
    // the cell there is nothing to check it against.
    const recipe = splitRecipe(params);
    expect(recipe).toContain("vss.split");
    expect(recipe).toContain("vss.commitments | out @commitments");
    expect(recipe).not.toContain("sss.split");
  });

  it("drops the qr step when the ceremony asked for no QR", () => {
    expect(splitRecipe({ ...params, qr: false })).toContain("- out @share");
    expect(splitRecipe({ ...params, qr: false })).not.toContain("| qr");
  });

  it("verifies by digest, never by revealing the recovered secret", () => {
    const r = verifyRecipe();
    expect(r).toContain("vss.combine | digest");
    expect(r).not.toMatch(/out @secret|utf8 \| out/);
  });

  it("checks the shares against the commitments before recombining them", () => {
    // Order matters: recombining first and comparing digests afterwards can
    // only say "something is wrong". Verifying first says which share.
    const r = verifyRecipe();
    expect(r.indexOf("vss.verify")).toBeGreaterThan(-1);
    expect(r.indexOf("vss.verify")).toBeLessThan(r.indexOf("vss.combine"));
    expect(r).toContain("commitments=@commitments");
  });

  it("signs the receipt when a key was chosen, and still makes one when not", () => {
    expect(receiptRecipe({ label: "Board key", signWith: "me" })).toBe(
      'run.receipt "Board key" | gpg.sign key=@me | out @receipt'
    );
    expect(receiptRecipe({ label: "Board key" })).toBe(
      'run.receipt "Board key" | out @receipt'
    );
    expect(receiptRecipe({})).toBe("run.receipt | out @receipt");
  });

  it("titles the notebook with the quorum", () => {
    expect(ceremonyTitle(params)).toBe("Board key — 2-of-3");
    expect(ceremonyTitle({})).toBe("Key ceremony — 2-of-3");
  });
});

describe("verification comparison", () => {
  const hex = (c) => c.repeat(64);

  it("is pending until the split has run", () => {
    expect(verificationResult("", "").status).toBe("pending");
  });

  it("is incomplete with only one side", () => {
    expect(verificationResult(hex("a"), "").status).toBe("incomplete");
  });

  it("matches identical digests and says nothing was shown", () => {
    const r = verificationResult(hex("a"), hex("a"));
    expect(r.status).toBe("match");
    expect(r.message).toMatch(/neither value was shown/i);
  });

  it("refuses to call a mismatch a pass, and says not to distribute", () => {
    const r = verificationResult(hex("a"), hex("b"));
    expect(r.status).toBe("mismatch");
    expect(r.message).toMatch(/do not distribute/i);
  });

  it("is case- and whitespace-insensitive about hex", () => {
    expect(verificationResult(` ${hex("A")} `, hex("a")).status).toBe("match");
  });

  it("rejects something that is not a SHA-256 digest", () => {
    expect(verificationResult("abc", "abc").status).toBe("incomplete");
  });
});

describe("tileForSlot", () => {
  it("finds a tile by slot label or filename", () => {
    const outputs = [
      { label: "expected", filename: "expected.txt", content: "aa" },
      { label: "@recovered", filename: "recovered.txt", content: "bb" },
    ];
    expect(tileForSlot(outputs, "expected")).toBe("aa");
    expect(tileForSlot(outputs, "@recovered")).toBe("bb");
    expect(tileForSlot(outputs, "nothing")).toBe("");
  });
});

describe("the whole ceremony, through the kernel", () => {
  it("splits, proves the shares recombine, cards them, and receipts it", async () => {
    const kernel = createKernel();
    const params = { threshold: 2, shares: 3, label: "Board key", qr: true };
    const cells = ceremonyCells(params);
    const chains = cells.map((c) => compileRecipe(c.recipe).ast.chains[0]);

    // ── split ──
    const splitArts = await kernel.runCell(0, chains[0], {});
    const expected = tileForSlot(splitArts, "expected");
    expect(expected).toMatch(/^[0-9a-f]{64}$/);

    // The master itself is nowhere revealable.
    expect(splitArts.some((a) => a.revealable && a.sensitive && a.role === "secret")).toBe(
      false
    );

    // ── verify: recombines from the slots the split registered, no paste ──
    const verifyArts = await kernel.runCell(1, chains[1], {});
    const recovered = tileForSlot(verifyArts, "recovered");
    const result = verificationResult(expected, recovered);
    expect(result.status).toBe("match");

    // ── cards ──
    const cards = collectShareCards(splitArts, { label: params.label });
    expect(cards.length).toBe(3);
    expect(cards.every((c) => c.threshold === 2 && c.qrSvg)).toBe(true);

    // ── receipt: covers all three cells, contains no share ──
    const receiptArts = await kernel.runCell(2, chains[2], {});
    const receipt = parseReceipt(
      receiptArts.find((a) => a.role === "receipt").content
    );
    expect(receipt.label).toBe("Board key");
    expect(receipt.cells.length).toBe(3);
    const body = JSON.stringify(receipt);
    for (const c of cards) expect(body).not.toContain(c.mnemonic);
    // It records that three shares existed, by digest, and that the receipt
    // cell itself contributed no output (a receipt cannot contain its own).
    const shareRows = receipt.cells.flatMap((c) =>
      (c.outputs || []).filter((o) => o.role === "share")
    );
    expect(shareRows.length).toBe(3);
    expect(receipt.cells[2].outputs).toEqual([]);

    kernel.destroy();
  }, 60_000);

  it("reports a mismatch rather than a pass when the wrong shares are pasted", async () => {
    const kernel = createKernel();
    const params = { threshold: 2, shares: 3, qr: false };
    const chains = ceremonyCells(params).map(
      (c) => compileRecipe(c.recipe).ast.chains[0]
    );
    const splitA = await kernel.runCell(0, chains[0], {});
    const expected = tileForSlot(splitA, "expected");

    // A second, unrelated split's shares — the classic "wrong envelope" error.
    const other = createKernel();
    const splitB = await other.runCell(0, chains[0], {});
    const otherMnemonics = splitB
      .filter((a) => a.role === "share")
      .map((a) => String(a.content).trim())
      .slice(0, 2);

    // With verifiable sharing this now fails *earlier and louder* than the
    // digest comparison it used to reach: the shares are checked against the
    // published commitments first, so the run stops naming the offending
    // shares instead of reporting that two hashes differ. For a ceremony that
    // is the difference between "something is wrong" and "these are from a
    // different split".
    await expect(
      kernel.runCell(1, chains[1], { inputs: { shares: { mnemonics: otherMnemonics } } })
    ).rejects.toThrow(/do not match the commitments|different split/i);

    // And the comparison helper still reports a mismatch rather than a pass
    // if it is ever handed a recovered digest that disagrees.
    expect(verificationResult(expected, "00".repeat(32)).status).toBe("mismatch");
    kernel.destroy();
    other.destroy();
    other.destroy();
  }, 60_000);
});
