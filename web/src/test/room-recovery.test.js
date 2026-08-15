/**
 * The recovery a quorum writes for itself, at recovery time.
 *
 * `room-ceremony.test.js` proves the deal notebook is the deal and nothing
 * else; this file proves the other agreement exists and holds the properties
 * the old single-notebook shape could not:
 *
 * - **Dealer-absent is the default shape.** The contributors are whoever is
 *   listed, the dealer is nobody special, and no cell anywhere returns the
 *   dealer's share unless the dealer was listed as a contributor — in which
 *   case it is an ordinary send cell like everyone else's.
 * - **Everything but "who" is read off the share's own header.** Threshold,
 *   count and set id come from `ShareHeaderFacts` — the same facts the
 *   "Check a share…" panel reads off one mnemonic, offline — so the recovery
 *   can be written with the deal notebook gone and the dealer dead.
 * - **The gather takes exactly the listed contributors.** `count=` is the
 *   agreement's own number, never `threshold - 1` of whatever arrives first —
 *   the three-party e2e's finding 6a was a spare custodian's press that did
 *   nothing anything reported, and a gather that consumes every listed press
 *   cannot have one.
 * - **The words never enter the text.** The generator takes header facts, not
 *   the mnemonic: recipe text travels (previews, share links, manifests), and
 *   key material in it would be the leak.
 */
import { describe, expect, it } from "vitest";
import {
  CUSTODIAN_RECOVERY,
  RECOVERY_WAIT_MS,
  custodianRecovery,
  dealHoldings,
  roomRecovery,
  roomRecoveryIssues,
} from "../lib/toolkit/room-recovery.js";
import { roomCeremony } from "../lib/toolkit/room-ceremony.js";
import { canonicalizeRecipe, compileRecipe, recipeChains, serializeRecipe } from "../lib/toolkit/recipe.js";
import { planRun } from "../lib/toolkit/plan.js";
import { BLIP39_VERSION, encodeMnemonic, readShareHeader } from "../lib/slip39/blip39.js";

/** Distinct whole fingerprints — same scheme as room-ceremony.test.js. */
const fpr = (n) => n.toString(16).toUpperCase().padStart(4, "0").repeat(10).slice(0, 40);
const room = (n) => Array.from({ length: n }, (_, i) => fpr(i + 1));

/** A real share header, through the real codec, so the facts are the codec's. */
const facts = (over = {}) =>
  readShareHeader(
    encodeMnemonic({
      version: BLIP39_VERSION,
      id: 0x2abc,
      index: 2,
      threshold: 2,
      shareCount: 3,
      flags: 0,
      data: new Uint8Array(32),
      ...over,
    })
  );

/** The three-person deal's holdings, read off the generated deal itself. */
const holdingsFor = (n, self = fpr(1)) => {
  const deal = roomCeremony({ audience: room(n), self });
  const compiled = compileRecipe(deal.text);
  expect(compiled.validation.errors).toEqual([]);
  return dealHoldings(recipeChains(compiled.ast));
};

describe("who holds what, read off the deal's own text", () => {
  it("maps every member to the slot the deal binds on them", () => {
    // fpr(1) < fpr(2) < fpr(3), so canonical positions are list positions.
    const holdings = holdingsFor(3);
    expect(holdings).toEqual([
      // The dealer's own share is the unnumbered `$share` the scatter body
      // binds — the one share that was never received.
      { fingerprint: fpr(1), slot: "share" },
      { fingerprint: fpr(2), slot: "share-2" },
      { fingerprint: fpr(3), slot: "share-3" },
    ]);
  });

  it("reads structurally, so a peer with no share cell simply has no holding", () => {
    expect(dealHoldings([{ peer: fpr(1), steps: [{ name: "random" }] }])).toEqual([]);
    expect(dealHoldings([])).toEqual([]);
  });
});

describe("the generated recovery", () => {
  const recover = (contributors, self = fpr(2)) =>
    roomRecovery({
      self,
      header: facts(),
      holdings: holdingsFor(3),
      contributors,
    });

  it("writes one send per contributor and one gather, dealer nowhere special", () => {
    const r = recover([fpr(3)]);
    expect(r.issues).toEqual([]);
    expect(r.cells).toHaveLength(2);
    const [send, gather] = r.cells;
    // The contributor's cell reads the slot the *deal* bound on their machine
    // and addresses the recoverer by whole fingerprint.
    expect(send.peer).toBe(fpr(3));
    expect(send.recipe).toBe(`$share-3 | quorum.send to=${fpr(2)}`);
    // The gather is on the recoverer, folds their own share in through
    // `with=`, and decodes/combines — the canonical recovery pipeline.
    expect(gather.peer).toBe(fpr(2));
    expect(gather.recipe).toContain(`quorum.recv from=${fpr(3)} wait=${RECOVERY_WAIT_MS}`);
    expect(gather.recipe).toContain("shares with=$share-2");
    expect(gather.recipe).toContain("blip39 -d | sss.combine");
    expect(gather.recipe).toContain("out $recovered");
    expect(gather.recipe).toContain("out $secret");
    // No cell anywhere touches the dealer or the dealer's share: the dealer
    // was not listed, so the dealer does not exist in this agreement.
    expect(r.text).not.toContain(fpr(1));
  });

  it("compiles as placed text, with the deal's slots deferred to the run", () => {
    // `$share-3` and `$share-2` are slots this document never writes — the
    // deal wrote them, on the machines the cells are placed on. The compiler
    // defers a placed cell's unknown slot instead of refusing a value another
    // notebook bound, which is what makes a second notebook *writable* at all.
    const r = recover([fpr(3)]);
    const compiled = compileRecipe(r.text);
    expect(compiled.validation.errors.map((e) => e.message)).toEqual([]);
    // And it plans clean from every participant's point of view.
    const roster = Object.fromEntries(room(3).map((m) => [m, m]));
    for (const me of [fpr(2), fpr(3)]) {
      const plan = planRun(compiled, { roster, me });
      expect(plan.refusals, `${me} refused the recovery`).toEqual([]);
      expect(plan.ok).toBe(true);
    }
  });

  it("gathers exactly the listed contributors, never threshold-minus-one of whoever", () => {
    // Two contributors listed for a 2-of-3: legal (a surplus press is a press
    // the gather consumes), and `count=` is their number. The one-contributor
    // case names the sender in `from=` instead — the filter takes one
    // fingerprint, so it is written exactly when it is enforceable.
    const two = recover([fpr(1), fpr(3)]);
    expect(two.issues).toEqual([]);
    const gather = two.cells.at(-1);
    expect(gather.recipe).toContain(`count=2 wait=${RECOVERY_WAIT_MS}`);
    expect(gather.recipe).not.toContain("from=");
    // The dealer, listed, is an ordinary contributor: their send cell reads
    // the unnumbered `$share` their scatter body bound.
    const dealerSend = two.cells.find((c) => c.peer === fpr(1));
    expect(dealerSend.recipe).toBe(`$share | quorum.send to=${fpr(2)}`);
  });

  it("is a fixed point of the serializer, whole fingerprints and all", () => {
    const r = recover([fpr(3)]);
    expect(canonicalizeRecipe(r.text).text).toBe(r.text);
    expect(r.text).not.toContain("…");
    for (const run of r.text.match(/[0-9A-F]{16,}/g) || []) {
      expect(run, `a shortened key id is in the recipe: ${run}`).toHaveLength(40);
    }
    const chains = recipeChains(compileRecipe(r.text).ast);
    expect(serializeRecipe(chains)).toBe(r.text);
    expect(chains.map((c) => c.peer)).toEqual(r.cells.map((c) => c.peer));
  });

  it("keeps the gather's wait the length of the act, and says it before the press", () => {
    expect(RECOVERY_WAIT_MS).toBeGreaterThan(10 * 60_000);
    const r = recover([fpr(3)]);
    const gather = r.cells.at(-1);
    expect(gather.recipe).toContain(`wait=${RECOVERY_WAIT_MS}`);
    expect(gather.why).toContain(String(RECOVERY_WAIT_MS / 60000));
  });

  it("never carries key material — the header's facts are all it was given", () => {
    // The generator's input is four numbers and a set id; assert the output
    // could not contain words even if it wanted to, by checking the only
    // free-text fields against the share alphabet's shape.
    const r = recover([fpr(3)]);
    expect(r.setId).toMatch(/^[0-9A-F]{4}$/);
    expect(r.threshold).toBe(2);
    expect(r.total).toBe(3);
    expect(r.text).not.toMatch(/\b([a-z]+ ){8,}/);
  });
});

describe("the refusals name the number that is actually true", () => {
  const holdings = () => holdingsFor(3);

  it("counts shares against the header's own threshold", () => {
    const short = roomRecoveryIssues({
      self: fpr(2),
      header: facts({ threshold: 3, shareCount: 4 }),
      holdings: holdings(),
      contributors: [],
    });
    expect(short.join(" ")).toContain("3-of-4");
    expect(short.join(" ")).toContain("no contributor is");
    expect(short.join(" ")).toContain("Name 2 more");
    const nearly = roomRecoveryIssues({
      self: fpr(2),
      header: facts({ threshold: 3, shareCount: 4 }),
      holdings: holdings(),
      contributors: [fpr(3)],
    });
    expect(nearly.join(" ")).toContain("2 of the 3 needed");
    expect(nearly.join(" ")).toContain("Name 1 more contributor");
  });

  it("refuses a recoverer the deal never dealt to, and points at the paste path", () => {
    const cold = roomRecoveryIssues({
      self: fpr(9),
      header: facts(),
      holdings: holdings(),
      contributors: [fpr(3)],
    });
    expect(cold.join(" ")).toContain("places no share on this key");
    expect(cold.join(" ")).toContain("paste recovery");
  });

  it("refuses a contributor who is the recoverer, or whom the deal never dealt to", () => {
    const selfish = roomRecoveryIssues({
      self: fpr(2),
      header: facts(),
      holdings: holdings(),
      contributors: [fpr(2), fpr(3)],
    });
    expect(selfish.join(" ")).toContain("already counted");
    const stranger = roomRecoveryIssues({
      self: fpr(2),
      header: facts(),
      holdings: holdings(),
      contributors: [fpr(9)],
    });
    expect(stranger.join(" ")).toContain(`${fpr(9)} holds no share this deal records`);
  });

  it("says when the slot's value is not a share, rather than typing it as one", () => {
    const unread = roomRecoveryIssues({
      self: fpr(2),
      header: null,
      holdings: holdings(),
      contributors: [fpr(3)],
    });
    expect(unread.join(" ")).toContain("does not read as a BLIP39 share mnemonic");
    // And nothing is generated on top of an unreadable share.
    const r = roomRecovery({
      self: fpr(2),
      header: null,
      holdings: holdings(),
      contributors: [fpr(3)],
    });
    expect(r.cells).toEqual([]);
    expect(r.text).toBe("");
  });
});

describe("the custodian's paste path", () => {
  it("is one unheaded cell that compiles cold — no session, no vault, no slots", () => {
    const r = custodianRecovery();
    expect(r.cells).toHaveLength(1);
    expect(r.cells[0].peer).toBe("");
    expect(r.cells[0].recipe).toBe(CUSTODIAN_RECOVERY);
    const compiled = compileRecipe(r.text);
    expect(compiled.validation.errors).toEqual([]);
    // `shares` with nothing named collects from the Inputs tray, which is the
    // only road in for a person holding cards — asserted here as the absence
    // of any slot or peer the cold machine would not have.
    expect(r.text).not.toContain("with=");
    expect(r.text).not.toContain("@");
    expect(canonicalizeRecipe(r.text).text).toBe(r.text);
  });

  it("digests what it recombines, because wrong shares recombine silently", () => {
    expect(CUSTODIAN_RECOVERY).toContain("sss.combine");
    expect(CUSTODIAN_RECOVERY).toContain("digest sha-256");
    expect(CUSTODIAN_RECOVERY).toContain("out $recovered");
    expect(CUSTODIAN_RECOVERY).toContain("out $secret");
  });
});
