/**
 * Perfect negotiation — the collision rule that lets a mesh renegotiate
 * without a coordinator.
 *
 * In a mesh, glare (both sides offering at once) is the normal case, not the
 * edge case: members join in arbitrary order and either end of a pair can
 * trigger an ICE restart. The rule under test is the whole resolution
 * mechanism: politeness comes from comparing stable identifiers, the impolite
 * peer ignores the colliding offer, the polite peer accepts and lets its own
 * roll back.
 */
import { describe, expect, it } from "vitest";
import { offerCollisionAction } from "../lib/webrtc/negotiation.js";

describe("offerCollisionAction", () => {
  it("accepts freely when there is no collision", () => {
    for (const polite of [true, false]) {
      expect(
        offerCollisionAction({ polite, makingOffer: false, signalingState: "stable" })
      ).toBe("accept");
    }
  });

  it("on glare, the impolite peer ignores and the polite peer accepts", () => {
    const glare = { makingOffer: true, signalingState: "have-local-offer" };
    expect(offerCollisionAction({ polite: false, ...glare })).toBe("ignore");
    expect(offerCollisionAction({ polite: true, ...glare })).toBe("accept");
  });

  it("treats either signal alone as a collision", () => {
    // makingOffer covers the async gap before setLocalDescription resolves,
    // when signalingState still reads "stable" — dropping either check
    // reopens exactly the race the pattern exists to close.
    expect(
      offerCollisionAction({ polite: false, makingOffer: true, signalingState: "stable" })
    ).toBe("ignore");
    expect(
      offerCollisionAction({
        polite: false,
        makingOffer: false,
        signalingState: "have-local-offer",
      })
    ).toBe("ignore");
  });

  it("the polite peer never ignores, whatever the state", () => {
    for (const makingOffer of [true, false]) {
      for (const signalingState of ["stable", "have-local-offer", "have-remote-offer"]) {
        expect(
          offerCollisionAction({ polite: true, makingOffer, signalingState })
        ).toBe("accept");
      }
    }
  });
});
