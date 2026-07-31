/**
 * Feldman VSS as a standalone capability — no mesh, no DKG.
 *
 * The use case this unlocks: one person splits their own key and hands the
 * shares to custodians who can **check** them on the spot. With the GF(256)
 * sharing in lib/slip39, a corrupted share is indistinguishable from a good
 * one until reconstruction fails — by which time everyone has gone home and
 * nobody knows whose share was wrong.
 *
 * `dkg.test.js` exercises the same primitives through the joint-Feldman
 * layer; between them they pin both halves of the split.
 */
import { describe, expect, it } from "vitest";
import {
  ORDER,
  combine,
  deal,
  publicKeyForSecret,
  publicKeyOf,
  scalarToHex,
  verify,
} from "../lib/quorum/vss.js";
import { splitSecret, combineSecret } from "../lib/slip39/gf256.js";

describe("split, verify, reconstruct", () => {
  it("hands every custodian a share they can verify immediately", () => {
    const ids = [1, 2, 3, 4, 5];
    const d = deal({ ids, threshold: 3 });
    for (const id of ids) {
      expect(
        verify({ share: d.shares[scalarToHex(BigInt(id))], id, commitments: d.commitments }),
        `share ${id}`
      ).toBe(true);
    }
  });

  it("reconstructs the dealt secret from a threshold subset", () => {
    const secret = 0x2a2a2a2a2a2a2a2an;
    const d = deal({ ids: [1, 2, 3], threshold: 2, secret });
    const back = combine([
      { id: 1, share: d.shares[scalarToHex(1n)] },
      { id: 3, share: d.shares[scalarToHex(3n)] },
    ]);
    expect(BigInt(`0x${back}`)).toBe(secret);
  });

  it("the commitment publishes the secret's public key, and nothing else", () => {
    const d = deal({ ids: [1, 2, 3], threshold: 2 });
    // C₀ = secret·G — usable as the public key of the shared private key,
    // which is what makes the shares checkable without revealing anything.
    expect(publicKeyOf(d.commitments)).toBe(publicKeyForSecret(scalarToHex(d.secret)));
  });

  it("a corrupted share is caught at hand-over, not at reconstruction", () => {
    // The entire point of the V in VSS.
    const d = deal({ ids: [1, 2, 3], threshold: 2 });
    const good = d.shares[scalarToHex(2n)];
    const bad = scalarToHex(BigInt(`0x${good}`) ^ 1n);
    expect(verify({ share: good, id: 2, commitments: d.commitments })).toBe(true);
    expect(verify({ share: bad, id: 2, commitments: d.commitments })).toBe(false);
  });

  it("refuses a threshold that could never be met", () => {
    expect(() => deal({ ids: [1, 2], threshold: 3 })).toThrow(/exceeds 2 shares/i);
  });

  it("refuses id 0, which would hand over the secret itself", () => {
    expect(() => deal({ ids: [0, 1], threshold: 2 })).toThrow(/id 0 is the secret/i);
  });
});

describe("the two sharing schemes stay separate on purpose", () => {
  it("GF(256) sharing still works untouched, on arbitrary-length data", () => {
    // The prime-field scheme cannot replace this: a scalar holds ~32 bytes,
    // while SLIP-39 style sharing handles a secret of any length byte-wise.
    const secret = new Uint8Array(48).fill(7);
    const shares = splitSecret(secret, 2, 3);
    const back = combineSecret([shares[0], shares[2]]);
    expect([...back]).toEqual([...secret]);
  });

  it("a VSS secret must fit in one scalar", () => {
    // Stated as a test because it is the real constraint on when to reach for
    // which scheme, not a footnote.
    const tooBig = ORDER + 1n;
    const d = deal({ ids: [1, 2], threshold: 2, secret: tooBig });
    // Reduced mod the order rather than silently truncated — but the caller
    // does not get back what they put in, which is why arbitrary-length data
    // belongs in the GF(256) path.
    expect(d.secret).toBe(1n);
  });
});
