/**
 * A refusal names a participant and stops short of sentencing them.
 *
 * `finalize` used to end its message "restart excluding that participant". That
 * is a remedy stated as a conclusion, and it is the one conclusion the reader is
 * not entitled to draw on their own: commitments are broadcast but shares are
 * pairwise, so the recipient is the *only* participant who can see a bad deal,
 * and from every other seat the observation and an accusation are the same
 * thing.
 *
 * The two modules were saying different things about it. `dkg-session.js` does
 * prescribe starting again without that dealer — but only after the room has
 * compared notes out of band, which is the caution that makes the remedy safe.
 * `finalize` named the remedy and dropped the caution, so a person reading it
 * went looking for an "exclude" control that must not exist, and `DkgPanel`'s
 * deliberately absent button read as missing rather than as a decision.
 *
 * Split by layer rather than reworded: the arithmetic says what it knows, the
 * session says what to do. This pins both halves, because the failure was that
 * they drifted.
 */
import { describe, expect, it } from "vitest";
import { finalize } from "../lib/quorum/dkg.js";
import { refusalReport } from "../lib/quorum/dkg-session.js";
import { deal, scalarToHex } from "../lib/quorum/vss.js";

const ids = ["aa", "bb"].map((_, i) => scalarToHex(BigInt(i + 1)));

/** A contribution set in which `bb` deals a share of something else. */
function withBadDealer() {
  const [me, them] = ids;
  const good = deal({ ids, threshold: 2 });
  const other = deal({ ids, threshold: 2 });
  return [
    { from: me, share: good.shares[me], commitments: good.commitments },
    // Their commitments, somebody else's share: exactly the mismatch
    // `verify` exists to catch.
    { from: them, share: other.shares[me], commitments: good.commitments },
  ];
}

describe("what the arithmetic layer says", () => {
  const message = () => {
    try {
      finalize({ myId: ids[0], contributions: withBadDealer() });
      return "";
    } catch (err) {
      return String(err.message);
    }
  };

  it("names the dealer and what the run produced", () => {
    const m = message();
    expect(m).toMatch(/does not match their commitments/);
    // Not "a share short" — the joint key is a sum, so one bad contribution is
    // a different key. A reader who thinks they lost one share will look for a
    // way to proceed with the rest, and there isn't one.
    expect(m).toMatch(/Nothing usable came out of this run/);
    expect(m).toMatch(/different key rather than a share short/);
  });

  it("says only the recipient can see it", () => {
    // The fact that makes every remedy a social one. Without it the message
    // reads as a verdict the whole room could check.
    const m = message();
    expect(m).toMatch(/[Oo]nly the recipient can see this/);
    expect(m).toMatch(/indistinguishable\s+from a claim about them/);
  });

  it("prescribes nothing, and names no control", () => {
    // The regression this file exists for. This layer may not send anyone
    // looking for an affordance the product deliberately does not offer.
    const m = message();
    expect(m).not.toMatch(/exclud/i);
    expect(m).not.toMatch(/restart/i);
  });

  it("names the dealer by the whole id, not its last eight characters", () => {
    /*
     * The id in this sentence is the handle on a conversation that has to
     * happen out of band — `dkg-session.js` is explicit that the remedy is
     * social — and it used to be `shortId(c.from)…`, the last eight hex
     * characters. For a real room those are the last eight of somebody's
     * *fingerprint*: `idFromFingerprint` reduces mod the curve order, a v4
     * fingerprint is 160 bits and the order is 256, so the reduction is the
     * identity and the scalar is the fingerprint with zeros in front. A
     * refusal naming a peer by their 32-bit short key id, in the one message
     * a person carries into a room and reads aloud.
     *
     * Asserted as "the only id-shaped token is a whole id" rather than
     * `toContain(ids[1])` alone, because `toContain` passes on a message that
     * carries the whole id *and* a truncation of it beside — which is how a
     * second spelling of one fact gets in.
     */
    const runs = message().match(/\b[0-9a-f]{8,}\b/g) || [];
    expect(runs).toEqual([ids[1]]);
  });

  it("names the whole id in the duplicate-contribution refusal too", () => {
    // The other throw in `finalize`, and it carried the same truncation.
    const dup = withBadDealer();
    let m = "";
    try {
      finalize({ myId: ids[0], contributions: [dup[0], dup[0]] });
    } catch (err) {
      m = String(err.message);
    }
    expect(m).toMatch(/duplicate contribution/);
    expect(m.match(/\b[0-9a-f]{8,}\b/g)).toEqual([ids[0]]);
  });

  it("still carries the dealer's id for a surface to use", () => {
    // Structurally, not parsed back out of the sentence — `dkg-ops.js` maps it
    // to a fingerprint so `DkgPanel` can mark the right row.
    try {
      finalize({ myId: ids[0], contributions: withBadDealer() });
      expect.unreachable("finalize must refuse a mismatched share");
    } catch (err) {
      expect(err.dealer).toBe(ids[1]);
    }
  });
});

describe("what the session layer says", () => {
  const report = () =>
    refusalReport({
      dealer: { id: "@lin", fingerprint: "LIN", round: "bad" },
      participants: [
        { id: "you", fingerprint: "ME", self: true, round: "verified" },
        { id: "@lin", fingerprint: "LIN", round: "bad" },
      ],
    });

  it("is the layer that prescribes, and it does prescribe", () => {
    // The remedy is not forbidden — it is conditional. Restarting without a
    // dealer is what the room may well decide; the point is that the room
    // decides it, not the arithmetic.
    expect(report().remedy).toMatch(/Start again without @lin/);
  });

  it("attaches the caution that makes the remedy safe", () => {
    const caution = report().caution;
    expect(caution).toMatch(/Only you saw this/);
    expect(caution).toMatch(/out of band before anyone is excluded/);
  });
});
