/**
 * Roster projection — the one translation point between the transport's
 * vocabulary (NotebookPeerState) and the Connections panel's (ConnectionPeer).
 *
 * The property that matters most: connectivity and authentication are
 * independent axes. A peer can be fully connected and completely unverified,
 * and `authenticated` must demand both the PGP-signed envelope and the
 * transcript-bound key confirmation — either alone is not identity.
 */
import { describe, expect, it } from "vitest";
import * as roster from "../lib/notebook/roster.js";
import { projectRosterPeers } from "../lib/notebook/roster.js";
import { selectedCandidateType } from "../lib/webrtc/candidates.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { normalizeRoster, planRun } from "../lib/toolkit/plan.js";

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

  it("carries the whole fingerprint beside the label, and nothing in between", () => {
    const [row] = projectRosterPeers(new Map([[FPR_A, peer()]]));
    expect(row.fingerprint).toBe(FPR_A);
    // `id` was `AAAA1111…9999`, the output of a `shortFpr` this module used to
    // export. Changed because `id` is the name a cell header addresses and the
    // key of `planRun`'s roster, and an elided fingerprint is not a legal peer
    // label — it stopped notebooks compiling and made `normalizeRoster` throw.
    expect(row.id).toBe("peer1");
    // The abbreviation then moved to `display`, and `display` is now gone too.
    // It was twelve of forty characters — 48 bits, against the 32 the search
    // page already warns are collision-prone — printed where a reader compares
    // it, with no way to tell whether the 112 bits behind the ellipsis matched.
    // A row has two honest options and this projection supplies both: the label
    // it can print, and the whole fingerprint a `<Fingerprint>` can copy.
    expect("display" in row).toBe(false);
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

describe("the projection prints no fingerprint at all", () => {
  it("exports nothing that shortens one", () => {
    // `shortFpr` lived here and had five private copies in widgets. It is not
    // centralised, it is gone: a shared `shortFpr` is the same defect with one
    // import, because the defect was never the duplication. See
    // `components/ui/fingerprint.tsx` for what replaced it and why there is no
    // safer number of characters to have chosen instead.
    // `roomRoster` joined the list when the shell stopped answering "which peer
    // am I" by searching the peer rows — which are the audience minus self, so
    // the search never matched. It is here rather than in the shell because the
    // map that names the peers has to be the map that names you; see
    // `handoff-who.test.js`. It shortens no fingerprint either: it hands back
    // labels and whole keys, the same two honest things a row carries.
    expect(Object.keys(roster).sort()).toEqual([
      "peerLabels",
      "projectRosterPeers",
      "roomRoster",
    ]);
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

/**
 * A roster row's `id` is an identity, not a caption.
 *
 * Two surfaces read it as one. `ToolkitShell` offers it in `CellAssign`, which
 * writes `@<id>` into the notebook source; and it builds `planRun`'s roster —
 * `{ label: fingerprint }` — by keying on the same value. Both go through the
 * peer-label grammar, so an `id` that is not a legal label is not a cosmetic
 * problem: the notebook stops compiling and `normalizeRoster` throws, which
 * `ToolkitShell` catches into a null plan. The feature fails silently.
 *
 * The abbreviation this module used to produce cannot be that value. It carries
 * U+2026, which no label grammar admits, and the elided form could not be an
 * identity even if it parsed — it is a truncation, and
 * `peerLooksLikeFingerprint` refuses fingerprint-shaped labels on the security
 * ground that a fingerprint in shared recipe text gives away the audience the
 * room is derived from.
 *
 * That abbreviation is now gone from the product altogether rather than merely
 * demoted, because being an illegal name was the smaller of its two problems.
 */
describe("peer labels are legal, stable identities", () => {
  const FPR_C = "CCCC111122223333444455556666777788889999";
  const AUDIENCE = [FPR_B, FPR_A, FPR_C]; // deliberately unsorted

  const connected = () =>
    new Map([
      [FPR_A, peer({ status: "connected", pgpVerified: true, kcVerified: true })],
      [FPR_B, peer({ status: "connected" })],
    ]);

  it("names peers with something a notebook can compile", () => {
    const rows = projectRosterPeers(connected(), undefined, AUDIENCE);
    for (const row of rows) {
      // Exactly what `peerChoices` hands `CellAssign`, and what it writes.
      const { validation } = compileRecipe(`@${row.id}\nrandom 32 | out $x`);
      expect(validation.ok, `@${row.id} did not compile`).toBe(true);
    }
  });

  it("names peers with something planRun can bind", () => {
    const rows = projectRosterPeers(connected(), undefined, AUDIENCE);
    // The roster ToolkitShell assembles, in the shape `planRun` takes.
    const roster = Object.fromEntries(rows.map((r) => [r.id, r.fingerprint]));
    expect(() => normalizeRoster(roster)).not.toThrow();
    expect(planRun(compileRecipe("@" + rows[0].id + "\nrandom 32 | out $x"), { roster }).bound).toBe(
      true
    );
  });

  it("gives every audience member the same label on every machine", () => {
    // The room is a digest of the audience, so the audience is fixed for the
    // session and identical everywhere. Ordering the labels by it — rather than
    // by who happened to arrive first — is what makes `@peer2` mean one person
    // in a notebook that round-trips through text between two browsers.
    const asCreator = projectRosterPeers(connected(), undefined, AUDIENCE);
    const asJoiner = projectRosterPeers(
      new Map([...connected()].reverse()),
      undefined,
      [FPR_C, FPR_A, FPR_B]
    );
    const labelOf = (rows) =>
      Object.fromEntries(rows.map((r) => [r.fingerprint, r.id]));
    expect(labelOf(asJoiner)).toEqual(labelOf(asCreator));

    // And a peer arriving later must not renumber the peers already placed.
    const late = projectRosterPeers(
      new Map([...connected(), [FPR_C, peer({ status: "connected" })]]),
      undefined,
      AUDIENCE
    );
    expect(labelOf(late)).toMatchObject(labelOf(asCreator));
  });

  it("hands a panel a name and a whole key, and no third thing", () => {
    // This used to assert that the abbreviation survived on `display` — "still
    // what the panels put in front of a reader; the defect was using its output
    // where an identity was wanted". That reading of the defect was too narrow.
    // `AAAA1111…9999` was also unsafe to *read*: a reader who compares it has
    // checked 48 of 160 bits and has no way to know it. So the row carries the
    // label, which is a name and admits it, and the fingerprint, which is
    // whole — and a panel renders one or the other, never a blend of the two.
    const rows = projectRosterPeers(connected(), undefined, AUDIENCE);
    expect(rows.every((r) => !r.id.includes("…"))).toBe(true);
    expect(rows.map((r) => r.id)).toEqual(["peer1", "peer2"]);
    expect(rows.map((r) => r.fingerprint)).toEqual([FPR_A, FPR_B]);
    expect(rows.some((r) => JSON.stringify(r).includes("…"))).toBe(false);
  });
});
