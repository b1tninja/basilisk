/**
 * Share cards — the join from a split cell's flat artifact list to one card
 * per share.
 *
 * The pairing rule and the threshold inference are the parts that can be wrong
 * in a way nobody notices until a card has been printed and the secret
 * destroyed, so they are tested against artifacts a real split actually emits
 * rather than against hand-written fixtures alone.
 */
import { describe, expect, it } from "vitest";
import {
  checkLine,
  collectShareCards,
  findCommitments,
  inferThreshold,
  quorumLine,
  recoveryLine,
  revealWarning,
} from "../lib/toolkit/share-cards.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

const shareTile = (index, content, threshold = 2) => ({
  label: `Share ${index}`,
  filename: `share-${index}.txt`,
  content,
  role: "share",
  sensitive: true,
  shareIndex: index,
  traits: { shareOf: index, threshold },
});

const qrTile = (index) => ({
  label: `Share ${index} QR`,
  filename: `share-${index}.svg`,
  content: `<svg data-share="${index}"></svg>`,
  role: "qr",
  mime: "image/svg+xml",
  shareIndex: index,
});

describe("collectShareCards", () => {
  it("returns nothing when the cell produced no shares", () => {
    expect(collectShareCards([])).toEqual([]);
    expect(collectShareCards([{ label: "text", content: "hi", role: "text" }])).toEqual([]);
  });

  it("builds one card per share, in index order regardless of tile order", () => {
    const cards = collectShareCards([shareTile(3, "c c"), shareTile(1, "a a"), shareTile(2, "b b")]);
    expect(cards.map((c) => c.index)).toEqual([1, 2, 3]);
    expect(cards.every((c) => c.total === 3)).toBe(true);
    expect(cards[0].mnemonic).toBe("a a");
  });

  it("pairs each QR with the share of the same index, not by position", () => {
    const cards = collectShareCards([
      qrTile(2),
      shareTile(1, "a a"),
      qrTile(1),
      shareTile(2, "b b"),
    ]);
    expect(cards[0].qrSvg).toContain('data-share="1"');
    expect(cards[1].qrSvg).toContain('data-share="2"');
  });

  it("leaves qrSvg empty rather than borrowing another share's QR", () => {
    const cards = collectShareCards([shareTile(1, "a a"), shareTile(2, "b b"), qrTile(1)]);
    expect(cards[0].qrSvg).toBeTruthy();
    expect(cards[1].qrSvg).toBe("");
  });

  it("does not mistake a QR tile for a share body", () => {
    // Both carry a shareIndex; only one has a mnemonic on it.
    const cards = collectShareCards([shareTile(1, "a a"), qrTile(1)]);
    expect(cards.length).toBe(1);
    expect(cards[0].mnemonic).toBe("a a");
  });

  it("stamps the ceremony label and date on every card", () => {
    const cards = collectShareCards([shareTile(1, "a"), shareTile(2, "b")], {
      label: "Board key ceremony",
      date: new Date("2026-07-30T09:00:00Z"),
    });
    expect(cards.map((c) => c.label)).toEqual([
      "Board key ceremony",
      "Board key ceremony",
    ]);
    expect(cards[0].date).toBe("2026-07-30");
  });

  it("takes the threshold from traits, and an explicit option wins", () => {
    expect(inferThreshold([shareTile(1, "a", 3)])).toBe(3);
    const cards = collectShareCards([shareTile(1, "a", 3)], { threshold: 5 });
    expect(cards[0].threshold).toBe(5);
  });

  it("reports 0 rather than guessing when no tile recorded a threshold", () => {
    // A card claiming 2-of-3 for a 3-of-5 split is worse than one that admits
    // it does not know.
    const cards = collectShareCards([
      { role: "share", shareIndex: 1, content: "a" },
      { role: "share", shareIndex: 2, content: "b" },
    ]);
    expect(cards[0].threshold).toBe(0);
    expect(quorumLine(cards[0])).toMatch(/did not record/);
  });
});

describe("card copy", () => {
  it("states the quorum in words a card holder can act on", () => {
    const [card] = collectShareCards([shareTile(1, "a"), shareTile(2, "b"), shareTile(3, "c")]);
    expect(quorumLine(card)).toBe(
      "Share 1 of 3 — any 2 of these 3 reconstruct the secret."
    );
  });

  it("warns about what printing actually does, not just that it reveals", () => {
    const text = revealWarning(3);
    expect(text).toContain("3 shares");
    expect(text).toMatch(/cleartext/);
    expect(text).toMatch(/spool|print server/);
    expect(revealWarning(1)).toContain("1 share");
  });
});

describe("verifiable splits on paper", () => {
  it("prints vss.combine for a verifiable set and sss.combine otherwise", async () => {
    const { ast } = compileRecipe(
      `random 32 | vss.split threshold=2 shares=3 | tee
  - vss.commitments | out @commitments
| blip39 | foreach
  - out @share`
    );
    const arts = await runRecipe(ast);
    const [card] = collectShareCards(arts);
    expect(card.verifiable).toBe(true);
    expect(card.splitId).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
    // The old hard-coded line told a vss custodian to run an op that would
    // reject their shares. It is derived now, so it cannot drift again.
    expect(recoveryLine(card)).toContain("vss.combine");
    expect(recoveryLine(card)).toContain("vss.verify");
    expect(checkLine(card)).toContain(card.splitId);
  }, 30_000);

  it("says an sss card cannot be checked, rather than offering a check that fails", () => {
    const [card] = collectShareCards([
      { role: "share", shareIndex: 1, content: "a a", traits: { threshold: 2 } },
    ]);
    expect(card.verifiable).toBe(false);
    expect(card.splitId).toBe("");
    expect(recoveryLine(card)).toContain("sss.combine");
    expect(checkLine(card)).toMatch(/cannot be checked/);
  });

  it("stamps no split id when the commitments document is unreadable", () => {
    // An id derived from a document that could not be parsed would be a label
    // with nothing behind it — and the label's only job is to be compared.
    const cards = collectShareCards(
      [{ role: "share", shareIndex: 1, content: "a a" }],
      { commitments: '{"commitments":["not-a-point"]}' }
    );
    expect(cards[0].verifiable).toBe(false);
  });

  it("finds the commitments tile by shape, not only by slot name", () => {
    expect(findCommitments([{ content: "hello" }])).toBeNull();
    expect(
      findCommitments([{ label: "renamed", content: '{"v":1,"commitments":["02aa"]}' }])
    ).toEqual(["02aa"]);
  });
});

describe("against a real split", () => {
  it("cards a 2-of-3 blip39 split with QR codes attached", async () => {
    const { ast } = compileRecipe(
      `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share | qr`
    );
    const arts = await runRecipe(ast);
    const cards = collectShareCards(arts, { label: "Ceremony" });
    expect(cards.length).toBe(3);
    expect(cards.map((c) => c.index)).toEqual([1, 2, 3]);
    for (const c of cards) {
      expect(c.threshold).toBe(2);
      expect(c.mnemonic.split(/\s+/).length).toBeGreaterThan(8);
      expect(c.qrSvg).toMatch(/<svg/);
    }
    // Every mnemonic distinct — a card set where two cards carry the same
    // share is a broken ceremony, not a cosmetic bug.
    expect(new Set(cards.map((c) => c.mnemonic)).size).toBe(3);
  }, 30_000);

  it("cards a split with no qr step, leaving the QR slot empty", async () => {
    const { ast } = compileRecipe(
      `random 32 | sss.split threshold=3 shares=5 | blip39 | foreach
  - out @share`
    );
    const arts = await runRecipe(ast);
    const cards = collectShareCards(arts);
    expect(cards.length).toBe(5);
    expect(cards.every((c) => c.qrSvg === "")).toBe(true);
    expect(cards[0].threshold).toBe(3);
  }, 30_000);
});
