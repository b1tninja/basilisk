/**
 * Roster projection — the one translation point between the transport's
 * vocabulary (QuorumPeerState) and the Connections panel's (ConnectionPeer).
 *
 * The property that matters most: connectivity and authentication are
 * independent axes. A peer can be fully connected and completely unverified,
 * and `authenticated` must demand both the PGP-signed envelope and the
 * transcript-bound key confirmation — either alone is not identity.
 */
import { describe, expect, it } from "vitest";
import { projectRosterPeers, shortFpr } from "../lib/quorum/roster.js";
import { selectedCandidateType } from "../lib/webrtc/candidates.js";

const FPR_A = "AAAA111122223333444455556666777788889999";
const FPR_B = "BBBB111122223333444455556666777788889999";

/** @param {Partial<{status: string, pgpVerified: boolean, kcVerified: boolean}>} over */
function peer(over = {}) {
  return { status: "unknown", pgpVerified: false, kcVerified: false, ...over };
}

describe("projectRosterPeers", () => {
  it("maps every transport status onto a panel state", () => {
    const map = new Map([
      ["A", peer({ status: "unknown" })],
      ["B", peer({ status: "verified" })],
      ["C", peer({ status: "connecting" })],
      ["D", peer({ status: "connected" })],
      ["E", peer({ status: "failed" })],
    ]);
    expect(projectRosterPeers(map).map((r) => r.state)).toEqual([
      "new",
      "new", // signalling seen but no transport — still new to the mesh
      "connecting",
      "connected",
      "failed",
    ]);
  });

  it("keeps connectivity and authentication independent", () => {
    const rows = projectRosterPeers(
      new Map([
        // connected but only envelope-verified — a working pipe is not identity
        [FPR_A, peer({ status: "connected", pgpVerified: true })],
        // both proofs — this is the only combination that earns the badge
        [FPR_B, peer({ status: "connected", pgpVerified: true, kcVerified: true })],
      ])
    );
    expect(rows.map((r) => r.authenticated)).toEqual([false, true]);
    expect(rows.every((r) => r.state === "connected")).toBe(true);
  });

  it("never grants authenticated on key confirmation alone", () => {
    // kcVerified without pgpVerified cannot happen in a healthy session, but
    // the projection must not be the layer that decides it is impossible.
    const rows = projectRosterPeers(
      new Map([[FPR_A, peer({ kcVerified: true })]])
    );
    expect(rows[0].authenticated).toBe(false);
  });

  it("carries the full fingerprint beside the short label", () => {
    const [row] = projectRosterPeers(new Map([[FPR_A, peer()]]));
    expect(row.fingerprint).toBe(FPR_A);
    expect(row.id).toBe("AAAA1111…9999");
  });

  it("attaches via only for peers whose ICE lookup has resolved", () => {
    const rows = projectRosterPeers(
      new Map([
        [FPR_A, peer({ status: "connected" })],
        [FPR_B, peer({ status: "connected" })],
      ]),
      new Map([[FPR_A, "srflx"]])
    );
    expect(rows[0].via).toBe("srflx");
    expect("via" in rows[1]).toBe(false);
  });
});

describe("shortFpr", () => {
  it("shortens long fingerprints and leaves short labels alone", () => {
    expect(shortFpr(FPR_A)).toBe("AAAA1111…9999");
    expect(shortFpr("abcd1234")).toBe("ABCD1234");
    expect(shortFpr("")).toBe("");
  });
});

describe("selectedCandidateType", () => {
  /** @param {object[]} stats */
  function fakePc(stats) {
    const report = {
      forEach: (fn) => stats.forEach(fn),
    };
    return { getStats: async () => report };
  }

  it("follows the transport's selected pair to the local candidate type", async () => {
    const via = await selectedCandidateType(
      fakePc([
        { id: "T", type: "transport", selectedCandidatePairId: "P" },
        { id: "P", type: "candidate-pair", localCandidateId: "L" },
        { id: "L", type: "local-candidate", candidateType: "srflx" },
      ])
    );
    expect(via).toBe("srflx");
  });

  it("falls back to selected/nominated pairs when there is no transport stat", async () => {
    const via = await selectedCandidateType(
      fakePc([
        { id: "P1", type: "candidate-pair", state: "failed", localCandidateId: "L1" },
        {
          id: "P2",
          type: "candidate-pair",
          nominated: true,
          state: "succeeded",
          localCandidateId: "L2",
        },
        { id: "L2", type: "local-candidate", candidateType: "relay" },
      ])
    );
    expect(via).toBe("relay");
  });

  it("returns empty rather than throwing on absent or hostile stats", async () => {
    expect(await selectedCandidateType(null)).toBe("");
    expect(await selectedCandidateType({})).toBe("");
    expect(
      await selectedCandidateType({
        getStats: async () => {
          throw new Error("not connected");
        },
      })
    ).toBe("");
    expect(await selectedCandidateType(fakePc([]))).toBe("");
  });
});
