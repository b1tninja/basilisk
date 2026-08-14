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

  it("carries the whole fingerprint, and nothing in between", () => {
    const [row] = projectRosterPeers(new Map([[FPR_A, peer()]]));
    expect(row.fingerprint).toBe(FPR_A);
    // `id` was `AAAA1111…9999`, the output of a `shortFpr` this module used to
    // export; then `peer1`, a position in the sorted audience; and it is the key
    // itself now. Each step removed a layer between the row and what a `@peer`
    // header actually says, and this is the last one — the row's name for a
    // person and the notebook's name for them are one value.
    expect(row.id).toBe(FPR_A);
    // The abbreviation then moved to `display`, and `display` is now gone too.
    // It was twelve of forty characters — 48 bits, against the 32 the search
    // page already warns are collision-prone — printed where a reader compares
    // it, with no way to tell whether the 112 bits behind the ellipsis matched.
    // A row has two honest options and this projection supplies both: the label
    // it can print, and the whole fingerprint a `<Fingerprint>` can copy.
    expect("display" in row).toBe(false);
  });

  it("carries the attestations a peer signed, as documents", () => {
    // The projection used to drop these on the floor, which made `_onDocument`'s
    // own comment — "who has attested travels with everything else the roster
    // says about a peer" — true of the emitter and false of the product: every
    // path out of the session runs through here, so a fact discarded here can
    // never reach a screen.
    const a = { v: 1, kind: "basilisk.manifest-attestation", manifest: "a".repeat(64), claimedAt: "x" };
    const b = { v: 1, kind: "basilisk.manifest-attestation", manifest: "b".repeat(64), claimedAt: "y" };
    const rows = projectRosterPeers(
      new Map([
        [FPR_A, { ...peer({ status: "connected" }), attested: new Map([[a.manifest, a], [b.manifest, b]]) }],
        [FPR_B, peer({ status: "connected" })],
      ])
    );
    // Insertion order, which is the order they arrived in.
    expect(rows[0].attested).toEqual([a, b]);
    // Whole documents, not digests: `manifestAttestedBy` reads `kind` and `v`
    // off the bytes the peer signed, and a digest alone would make the reader
    // synthesise the fields it then checks.
    expect(rows[0].attested[0].kind).toBe("basilisk.manifest-attestation");
    // Always an array. A peer with no `attested` at all and a peer who has
    // signed nothing are the same state on screen and must be one shape here.
    expect(rows[1].attested).toEqual([]);
  });

  it("builds a fresh list each time, so no row is a live view of the session", () => {
    // A row is something a component holds across renders. If two projections
    // handed back the same array — a cache on the peer record, say — a widget
    // that sorted or spliced its copy would be editing what the *next* coverage
    // count reads, and the count would move for a reason nothing signed.
    const a = { v: 1, kind: "basilisk.manifest-attestation", manifest: "a".repeat(64), claimedAt: "x" };
    const peers = new Map([
      [FPR_A, { ...peer({ status: "connected" }), attested: new Map([[a.manifest, a]]) }],
    ]);
    const first = projectRosterPeers(peers)[0].attested;
    const second = projectRosterPeers(peers)[0].attested;
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
    // The documents themselves are the session's, and are not copied — a
    // signature is not something this projection is entitled to rewrite.
    expect(first[0]).toBe(a);
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
    // `peerLabels` left this list rather than joining it. It handed out
    // positional labels — `peer1`, `peer2`, numbered over the canonical
    // audience — and a position is not a name a reader can use, and it moved
    // whenever the room changed size. What is left is the *order*, which
    // several callers still want, and a roster that maps each key to itself.
    expect(Object.keys(roster).sort()).toEqual([
      "projectRosterPeers",
      "roomMembers",
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
 * writes `@<id>` into the notebook source; and it builds `planRun`'s roster by
 * keying on the same value. Both go through the peer grammar, so an `id` that is
 * not a legal peer is not a cosmetic problem: the notebook stops compiling and
 * `normalizeRoster` throws, which `ToolkitShell` catches into a null plan. The
 * feature fails silently.
 *
 * The abbreviation this module used to produce cannot be that value — it carries
 * U+2026, which no grammar admits — and neither can any other truncation, for a
 * reason that has outlived the label layer entirely: a suffix of a fingerprint
 * names more than one key, so it identifies nobody, and `peerLooksLikeKeyId`
 * refuses one wherever it is written.
 *
 * The positional label that replaced the abbreviation has now gone the same way.
 * It was legal and it was stable and it was not an *identity*: `peer2` names a
 * place in a sorted list, the list is sorted over key material, and it therefore
 * moved whenever the room changed size. A row's `id` is the whole key.
 */
describe("a peer is a legal, stable identity", () => {
  const FPR_C = "CCCC111122223333444455556666777788889999";
  const AUDIENCE = [FPR_B, FPR_A, FPR_C]; // deliberately unsorted

  const connected = () =>
    new Map([
      [FPR_A, peer({ status: "connected", pgpVerified: true, kcVerified: true })],
      [FPR_B, peer({ status: "connected" })],
    ]);

  it("names peers with something a notebook can compile", () => {
    const rows = projectRosterPeers(connected());
    for (const row of rows) {
      // Exactly what `peerChoices` hands `CellAssign`, and what it writes.
      const { validation } = compileRecipe(`@${row.id}\nrandom 32 | out $x`);
      expect(validation.ok, `@${row.id} did not compile`).toBe(true);
    }
  });

  it("names peers with something planRun can bind", () => {
    const rows = projectRosterPeers(connected());
    // The roster ToolkitShell assembles, in the shape `planRun` takes.
    const roster = Object.fromEntries(rows.map((r) => [r.id, r.fingerprint]));
    expect(() => normalizeRoster(roster)).not.toThrow();
    expect(planRun(compileRecipe("@" + rows[0].id + "\nrandom 32 | out $x"), { roster }).bound).toBe(
      true
    );
  });

  it("names every member the same way on every machine, with nothing carried", () => {
    // This used to be a property bought with an ordering rule: a label was a
    // position in the canonical audience, so both browsers had to sort the same
    // list the same way to agree about who `@peer2` was. It is a property of the
    // *value* now — a key names itself — so arrival order, audience order and
    // the audience contents are all irrelevant to it, which is why the
    // assertions below no longer pass an audience in at all.
    const asCreator = projectRosterPeers(connected());
    const asJoiner = projectRosterPeers(new Map([...connected()].reverse()));
    const nameOf = (rows) =>
      Object.fromEntries(rows.map((r) => [r.fingerprint, r.id]));
    expect(nameOf(asJoiner)).toEqual(nameOf(asCreator));

    // And a peer arriving later must not rename the peers already placed —
    // which was the hazard, and is now not expressible.
    const late = projectRosterPeers(
      new Map([...connected(), [FPR_C, peer({ status: "connected" })]])
    );
    expect(nameOf(late)).toMatchObject(nameOf(asCreator));
  });

  it("hands a panel a whole key and no piece of one", () => {
    // The abbreviation used to survive on `display` — "still what the panels put
    // in front of a reader; the defect was using its output where an identity
    // was wanted". That reading was too narrow: `AAAA1111…9999` was also unsafe
    // to *read*, because a reader who compares it has checked 48 of 160 bits and
    // has no way to know it. Nothing partial is on the row in any field, and
    // that is asserted over the serialized object rather than over the two
    // fields this test happens to name.
    const rows = projectRosterPeers(connected());
    expect(rows.map((r) => r.id)).toEqual([FPR_A, FPR_B]);
    expect(rows.map((r) => r.fingerprint)).toEqual([FPR_A, FPR_B]);
    expect(rows.some((r) => JSON.stringify(r).includes("…"))).toBe(false);
  });
});
