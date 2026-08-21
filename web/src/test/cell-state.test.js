/**
 * What a peer's cell announcement says — face up, face down, and out loud.
 *
 * The wire half is `notebook-travels.test.js`; this is the copy, which is the
 * part that can be wrong in a way no transport test would notice. Three rules
 * are pinned here because each of them is a decision rather than a rendering:
 *
 * 1. A **refusal carries the state and never the sentence.** The running peer's
 *    reason can name their slots, their keys or their files.
 * 2. A **cell starting is silent** to a screen reader. `7ac9f50` made the local
 *    per-cell ticker silent so twelve announcements could not drown the one
 *    that mattered; a peer's ticker is no more announceable, and three peers
 *    make it three times worse.
 * 3. **Possession is asked of this machine**, never taken from the
 *    announcement. A row goes face up because a value arrived, not because
 *    somebody said they wrote one.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { describeCellState, facesFor } from "../lib/toolkit/cell-state.js";

const FPR = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678";

/** A registry that holds exactly these labels. */
const holding = (...labels) => (label) => labels.includes(label);

/** @param {Partial<import("../lib/toolkit/cell-state.js").PeerCellState>} [over] */
const row = (over = {}) => ({
  from: FPR,
  cell: 2,
  state: "done",
  slots: [],
  ts: 1_700_000_000_000,
  ...over,
});

describe("which of a peer's slots are face up here", () => {
  it("turns a slot face up only when this machine actually holds it", () => {
    const faces = facesFor(row({ slots: ["share-2", "expected"] }), holding("share-2"));
    expect(faces).toEqual([
      { slot: "share-2", here: true },
      { slot: "expected", here: false },
    ]);
  });

  it("turns nothing over for a cell that has not finished", () => {
    // A running cell has written nothing yet, and a refused one is not making a
    // claim about slots at all. Either drawn with faces would be this screen
    // asserting an outcome the announcement did not carry.
    expect(facesFor(row({ state: "running", slots: ["share-2"] }), holding("share-2"))).toEqual(
      []
    );
    expect(facesFor(row({ state: "refused", slots: ["share-2"] }), holding("share-2"))).toEqual(
      []
    );
  });
});

describe("what a screen reader is told", () => {
  it("says nothing at all when a peer's cell starts", () => {
    // The rule `7ac9f50` established, applied rather than restated: twelve
    // cells across three peers is roughly thirty-six interruptions, and every
    // `running` among them is a fact the listener cannot act on arriving
    // between the ones they came for.
    expect(describeCellState(row({ state: "running" }), holding())).toBe("");
  });

  it("names a finished cell and the slots that reached this machine", () => {
    const said = describeCellState(row({ slots: ["share-2"] }), holding("share-2"));
    expect(said).toBe(`${FPR} finished cell 2. $share-2 is here.`);
  });

  it("names a face-down slot as theirs, and offers no way to get it", () => {
    const said = describeCellState(row({ cell: 0, slots: ["expected", "share"] }), holding());
    expect(said).toBe(
      `${FPR} finished cell 0. $expected, $share exist on their machine and did not come here.`
    );
    // Never a remedy that cannot be performed: nothing on this wire requests a
    // value, so a sentence that hinted at one would tell a reader there is
    // something to do when there is not.
    expect(said).not.toMatch(/ask|request|fetch|send it|share it/i);
  });

  it("says a cell refused, and says the reason is not on this screen", () => {
    const said = describeCellState(row({ state: "refused" }), holding());
    expect(said).toBe(`${FPR} refused cell 2. The reason stayed on their machine.`);
  });

  it("prints the peer's whole fingerprint, because that is their whole name", () => {
    // The roster is identity-mapped — a peer *is* their key — so this is the
    // only name a peer has, and the line saying who just did something is the
    // last place to print part of it.
    for (const state of ["done", "refused"]) {
      expect(describeCellState(row({ state }), holding())).toContain(FPR);
    }
  });

  it("says a cell finished even when it wrote nothing anybody can name", () => {
    expect(describeCellState(row({ slots: [] }), holding())).toBe(
      `${FPR} finished cell 2.`
    );
  });
});

describe("the model this draws", () => {
  const DOC = readFileSync(
    new URL("../lib/toolkit/cell-state.js", import.meta.url),
    "utf8"
  );

  it("states that an absent row is silence and not an outcome", () => {
    // The one reading a person could take from this table that would be wrong:
    // a stretch with no rows means *nobody told me*, never *nothing ran*. There
    // is no replay on this wire and nothing to ask, so a late joiner's empty
    // table is the honest one.
    expect(DOC).toMatch(/absence means \*nothing has been said\*/);
    expect(DOC).toMatch(/not the same claim as \*this has not happened\*/);
  });

  it("keeps possession a question for the local registry", () => {
    expect(DOC).toMatch(/a label is not possession/);
    expect(DOC).toMatch(
      /goes face up when a value arrived, never when a peer said it wrote one/
    );
  });
});
