/**
 * The DKG session projection — design-ahead of the op layer.
 *
 * There is no transport to test against, which is the point: these are the
 * rules the transport will have to satisfy, written down first. The refusal
 * wording is asserted rather than the status alone, for the same reason it is
 * in `share-check.test.js` — the sentence a person is shown when key generation
 * fails is the deliverable, and the sentence that must not go missing is the
 * one saying they might be wrong about whose fault it is.
 */
import { describe, expect, it } from "vitest";
import {
  DKG_EXPERIMENTAL_NOTE,
  badDealers,
  canFinalize,
  dkgPhase,
  refusalReport,
  roundProgress,
  stageFor,
} from "../lib/quorum/dkg-session.js";

const p = (id, round, extra = {}) => ({ id, round, state: "connected", ...extra });
const me = { id: "me", round: "verified", self: true, state: "connected" };

describe("roundProgress", () => {
  it("counts only the other participants", () => {
    // "3 of 5" that quietly includes yourself is off by one in the direction
    // of looking healthier than it is.
    const r = roundProgress([me, p("a", "commitments"), p("b", "waiting")], "commitments");
    expect(r.have).toBe(1);
    expect(r.need).toBe(2);
    expect(r.label).toBe("1 of 2 commitments");
    expect(r.complete).toBe(false);
  });

  it("treats later rounds as satisfying earlier milestones", () => {
    const list = [me, p("a", "verified"), p("b", "share")];
    expect(roundProgress(list, "commitments").have).toBe(2);
    expect(roundProgress(list, "verified").have).toBe(1);
  });

  it("never counts a bad dealer as progress at any milestone", () => {
    const r = roundProgress([me, p("a", "bad"), p("b", "verified")], "commitments");
    expect(r.have).toBe(1);
  });

  it("says so plainly when there is nobody else yet", () => {
    expect(roundProgress([me], "commitments").label).toMatch(/no other participants/);
  });
});

describe("canFinalize", () => {
  it("requires every other contribution, not a threshold of them", () => {
    // Joint-Feldman sums all contributions: a missing one is a different key,
    // not a smaller quorum.
    expect(canFinalize([me, p("a", "verified"), p("b", "verified")])).toBe(true);
    expect(canFinalize([me, p("a", "verified"), p("b", "share")])).toBe(false);
    expect(canFinalize([me, p("a", "verified"), p("b", "bad")])).toBe(false);
    expect(canFinalize([me])).toBe(false);
  });
});

describe("dkgPhase", () => {
  it("derives the phase from what arrived, not from a stored flag", () => {
    const roster = [me, p("a", "waiting"), p("b", "waiting")];
    expect(dkgPhase({ participants: roster, started: false })).toBe("assembling");
    expect(dkgPhase({ participants: roster, started: true })).toBe("dealing");
    expect(
      dkgPhase({ participants: [me, p("a", "commitments"), p("b", "share")], started: true })
    ).toBe("collecting");
    expect(
      dkgPhase({ participants: [me, p("a", "verified"), p("b", "verified")], started: true })
    ).toBe("finalizing");
  });

  it("lets a bad dealer override every other signal", () => {
    // Not "collecting, with one problem". A refusal is total.
    expect(
      dkgPhase({ participants: [me, p("a", "verified"), p("b", "bad")], started: true })
    ).toBe("refused");
  });

  it("reports complete only once a joint key exists", () => {
    expect(
      dkgPhase({
        participants: [me, p("a", "verified")],
        started: true,
        jointPublicKey: "02ab",
      })
    ).toBe("complete");
  });
});

describe("refusalReport", () => {
  const r = refusalReport({
    dealer: p("4f2a", "bad"),
    participants: [me, p("4f2a", "bad"), p("b", "verified")],
  });

  it("names the dealer without turning the name into a verdict", () => {
    expect(r.headline).toContain("4f2a");
    expect(r.what).toMatch(/cannot tell the two apart/);
  });

  it("states that nothing is salvageable", () => {
    expect(r.cost).toMatch(/no partial result|There is no partial result/);
    expect(r.cost).toMatch(/different key/);
  });

  it("keeps the caution about acting alone — the part a stack trace drops", () => {
    expect(r.caution).toMatch(/Only you saw this/);
    expect(r.caution).toMatch(/no complaint round/);
    expect(r.caution).toMatch(/out of band/);
  });

  it("survives a refusal with no dealer identified", () => {
    const anon = refusalReport({ dealer: null, participants: [me] });
    expect(anon.headline).toContain("a participant");
  });
});

describe("standing copy", () => {
  it("says shared key, not threshold signing", () => {
    expect(DKG_EXPERIMENTAL_NOTE).toMatch(/does not produce threshold/i);
    expect(DKG_EXPERIMENTAL_NOTE).toMatch(/not been independently reviewed/);
  });

  it("has a stage for every phase, including the two terminal ones", () => {
    for (const id of ["assembling", "dealing", "collecting", "finalizing", "complete", "refused"]) {
      expect(stageFor(id).id).toBe(id);
    }
  });

  it("badDealers reports every one, not just the first", () => {
    expect(badDealers([me, p("a", "bad"), p("b", "bad"), p("c", "verified")])).toHaveLength(2);
  });
});
