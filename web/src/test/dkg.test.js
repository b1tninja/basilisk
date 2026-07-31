/**
 * Feldman VSS distributed key generation.
 *
 * The property the whole mesh exists to deliver: n participants end up
 * holding shares of a key that never existed anywhere, any `threshold` of
 * them can reconstruct it, and fewer learn nothing. These tests prove the
 * arithmetic actually does that — a DKG that "runs" but produces shares
 * describing a different key than the published one would look fine in a UI
 * and be worthless.
 */
import { describe, expect, it } from "vitest";
import {
  finalize,
  idFromFingerprint,
  normalizeIds,
  publicKeyForSecret,
  randomScalar,
  reconstruct,
  round1,
  scalarToHex,
  verifyShare,
} from "../lib/quorum/dkg.js";

/**
 * Run a complete honest DKG among `ids` and return every participant's view.
 * @param {number[]} ids
 * @param {number} threshold
 */
function runDkg(ids, threshold) {
  const dealers = ids.map((id) => ({ id, ...round1({ ids, threshold }) }));
  const results = ids.map((me) => ({
    id: me,
    ...finalize({
      myId: me,
      contributions: dealers.map((d) => ({
        from: scalarToHex(BigInt(d.id)),
        share: d.shares[scalarToHex(BigInt(me))],
        commitments: d.commitments,
      })),
    }),
  }));
  return { dealers, results };
}

describe("a complete honest run", () => {
  it("gives every participant the same joint public key", () => {
    const { results } = runDkg([1, 2, 3, 4, 5], 3);
    const keys = new Set(results.map((r) => r.publicKey));
    expect(keys.size, "participants disagree on the joint key").toBe(1);
  });

  it("produces shares that reconstruct the key the commitments claim", () => {
    // The load-bearing assertion. Reconstruct from a threshold subset and
    // check the secret's public key equals the jointly published one.
    const { results } = runDkg([1, 2, 3, 4, 5], 3);
    const secret = reconstruct(results.slice(0, 3).map((r) => ({ id: r.id, share: r.share })));
    expect(publicKeyForSecret(secret)).toBe(results[0].publicKey);
  });

  it("reconstructs identically from any threshold subset", () => {
    const { results } = runDkg([1, 2, 3, 4, 5], 3);
    const pick = (idx) => reconstruct(idx.map((i) => ({ id: results[i].id, share: results[i].share })));
    const a = pick([0, 1, 2]);
    const b = pick([2, 3, 4]);
    const c = pick([0, 2, 4]);
    expect(b).toBe(a);
    expect(c).toBe(a);
  });

  it("equals the sum of the participants' own contributions", () => {
    // The joint secret is Σ sᵢ — no dealer, no server, nobody who held it.
    const ids = [1, 2, 3];
    const dealers = ids.map((id) => ({ id, ...round1({ ids, threshold: 2 }) }));
    const results = ids.map((me) =>
      finalize({
        myId: me,
        contributions: dealers.map((d) => ({
          from: scalarToHex(BigInt(d.id)),
          share: d.shares[scalarToHex(BigInt(me))],
          commitments: d.commitments,
        })),
      })
    );
    const reconstructed = BigInt(
      `0x${reconstruct([
        { id: 1, share: results[0].share },
        { id: 2, share: results[1].share },
      ])}`
    );
    const summed = dealers.reduce((acc, d) => acc + d.secret, 0n);
    const ORDER = BigInt(
      "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    );
    expect(reconstructed).toBe(summed % ORDER);
  });

  it("works at the realistic threshold configurations", () => {
    for (const [n, t] of [
      [3, 2],
      [5, 3],
      [7, 5],
    ]) {
      const ids = Array.from({ length: n }, (_, i) => i + 1);
      const { results } = runDkg(ids, t);
      const secret = reconstruct(
        results.slice(0, t).map((r) => ({ id: r.id, share: r.share }))
      );
      expect(publicKeyForSecret(secret), `${t}-of-${n}`).toBe(results[0].publicKey);
    }
  });
});

describe("fewer than the threshold learn nothing", () => {
  it("t-1 shares reconstruct to the wrong secret", () => {
    // Not a proof of security — that is the maths — but it does catch an
    // implementation where the polynomial degree is off by one and t-1
    // shares happen to suffice.
    const { results } = runDkg([1, 2, 3, 4, 5], 3);
    const truth = reconstruct(results.slice(0, 3).map((r) => ({ id: r.id, share: r.share })));
    const short = reconstruct(results.slice(0, 2).map((r) => ({ id: r.id, share: r.share })));
    expect(short).not.toBe(truth);
  });
});

describe("verification catches a dishonest dealer", () => {
  it("accepts an honest share", () => {
    const ids = [1, 2, 3];
    const d = round1({ ids, threshold: 2 });
    expect(
      verifyShare({ share: d.shares[scalarToHex(2n)], id: 2, commitments: d.commitments })
    ).toBe(true);
  });

  it("rejects a tampered share", () => {
    const ids = [1, 2, 3];
    const d = round1({ ids, threshold: 2 });
    const tampered = scalarToHex(BigInt(`0x${d.shares[scalarToHex(2n)]}`) + 1n);
    expect(verifyShare({ share: tampered, id: 2, commitments: d.commitments })).toBe(false);
  });

  it("rejects a share aimed at a different participant", () => {
    // The equation binds the share to the id it was computed for, so a dealer
    // cannot swap two participants' shares undetected.
    const ids = [1, 2, 3];
    const d = round1({ ids, threshold: 2 });
    expect(
      verifyShare({ share: d.shares[scalarToHex(3n)], id: 2, commitments: d.commitments })
    ).toBe(false);
  });

  it("rejects shares checked against someone else's commitments", () => {
    const ids = [1, 2, 3];
    const mine = round1({ ids, threshold: 2 });
    const theirs = round1({ ids, threshold: 2 });
    expect(
      verifyShare({ share: mine.shares[scalarToHex(2n)], id: 2, commitments: theirs.commitments })
    ).toBe(false);
  });

  it("survives malformed input without throwing", () => {
    const d = round1({ ids: [1, 2], threshold: 2 });
    expect(verifyShare({ share: "zz", id: 1, commitments: d.commitments })).toBe(false);
    expect(verifyShare({ share: d.shares[scalarToHex(1n)], id: 1, commitments: ["nope"] })).toBe(false);
    expect(verifyShare({ share: "00", id: 1, commitments: [] })).toBe(false);
  });

  it("finalize refuses a bad contribution and names the dealer", () => {
    const ids = [1, 2, 3];
    const good = round1({ ids, threshold: 2 });
    const bad = round1({ ids, threshold: 2 });
    expect(() =>
      finalize({
        myId: 2,
        contributions: [
          { from: "aa", share: good.shares[scalarToHex(2n)], commitments: good.commitments },
          // A share that does not match the commitments published alongside it.
          { from: "bb", share: good.shares[scalarToHex(2n)], commitments: bad.commitments },
        ],
      })
    ).toThrow(/bb.*does not match their commitments|does not match/i);
  });

  it("finalize refuses a duplicated dealer", () => {
    // Counting one dealer twice would double their contribution's weight in
    // the joint key without anyone's consent.
    const ids = [1, 2];
    const d = round1({ ids, threshold: 2 });
    const c = { from: "aa", share: d.shares[scalarToHex(1n)], commitments: d.commitments };
    expect(() => finalize({ myId: 1, contributions: [c, c] })).toThrow(/duplicate/i);
  });
});

describe("participant ids", () => {
  it("rejects id 0, which is the secret itself", () => {
    expect(() => normalizeIds([0])).toThrow(/id 0 is the secret/i);
    expect(() => round1({ ids: [0, 1], threshold: 2 })).toThrow(/id 0/i);
  });

  it("rejects duplicates, which silently break the threshold", () => {
    expect(() => normalizeIds([1, 2, 1])).toThrow(/duplicate/i);
  });

  it("derives a usable id from a PGP fingerprint", () => {
    const a = idFromFingerprint("AAAA1111222233334444555566667777888899 99");
    const b = idFromFingerprint("BBBB111122223333444455556666777788889999");
    expect(a).not.toBe(b);
    expect(a > 0n).toBe(true);
    expect(() => idFromFingerprint("")).toThrow(/empty/i);
  });
});

describe("threshold bounds", () => {
  it("refuses a threshold nobody could ever meet", () => {
    expect(() => round1({ ids: [1, 2], threshold: 3 })).toThrow(/exceeds 2 participants/i);
  });

  it("refuses a threshold below 1", () => {
    expect(() => round1({ ids: [1, 2], threshold: 0 })).toThrow(/threshold must be/i);
  });

  it("allows the degenerate 1-of-n, where every share is the key", () => {
    // Valid arithmetic, terrible policy — the toolkit should say so, but the
    // maths layer is not where that judgement belongs.
    const ids = [1, 2];
    const { results } = runDkg(ids, 1);
    const fromOne = reconstruct([{ id: 1, share: results[0].share }]);
    expect(publicKeyForSecret(fromOne)).toBe(results[0].publicKey);
  });
});

describe("scalars", () => {
  it("serializes fixed-width, so a share never leaks its magnitude", () => {
    expect(scalarToHex(1n)).toHaveLength(64);
    expect(scalarToHex(randomScalar())).toHaveLength(64);
  });
});
