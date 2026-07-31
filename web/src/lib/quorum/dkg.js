/**
 * Distributed key generation — joint-Feldman, built on `lib/quorum/vss.js`.
 *
 * The layering is the protocol's own: **joint-Feldman DKG is n parallel VSS
 * instances, summed.** Every participant deals a secret they chose, verifies
 * what they receive, and adds the verified shares together. Nobody deals the
 * final key because nobody knows it — it is the sum of everyone's
 * contributions, and it never exists anywhere.
 *
 * So the only thing this module adds to VSS is the aggregation, plus the
 * refusals that make aggregation safe. Everything else — polynomials,
 * commitments, the verification equation, Lagrange reconstruction — belongs
 * to VSS and is used unchanged, which also means the standalone
 * "verifiably split my own key" case shares an implementation with this one
 * rather than duplicating it.
 *
 * ## What this does not do
 *
 * There is no complaint/resolution round. If a dealer's share fails
 * verification, `finalize` refuses and names them; the participants must
 * restart excluding that dealer. Real complaint handling (the accused
 * publishes the disputed share, everyone adjudicates) is a third round and is
 * deliberately absent rather than half-implemented.
 *
 * A rudimentary DKG is **not** a substitute for an audited threshold-signature
 * implementation. It gives you a shared key; it does not give you threshold
 * signing.
 * @module lib/quorum/dkg
 */

import {
  addCommitments,
  combine,
  deal,
  mod,
  publicKeyOf,
  scalarFromHex,
  scalarToHex,
  verify,
} from "./vss.js";

// Re-exported so the DKG layer reads as a complete protocol without callers
// reaching past it for primitives it is built from.
export {
  idFromFingerprint,
  normalizeIds,
  publicKeyForSecret,
  randomScalar,
  scalarFromHex,
  scalarToHex,
} from "./vss.js";

/**
 * @typedef {import("./vss.js").VssDeal} DkgRound1
 */

/**
 * Round 1 — deal a contribution.
 *
 * Exactly a VSS deal; the name is kept because in DKG this is one round of a
 * protocol rather than a standalone act, and every participant performs it
 * simultaneously.
 *
 * @param {{
 *   ids: Array<number|string|bigint>,
 *   threshold: number,
 *   secret?: bigint,
 * }} opts
 * @returns {DkgRound1}
 */
export function round1(opts) {
  return deal(opts);
}

/**
 * Verify a received contribution against its dealer's commitments.
 * @param {{ share: string, id: number|string|bigint, commitments: string[] }} x
 * @returns {boolean}
 */
export function verifyShare(x) {
  return verify(x);
}

/**
 * @typedef {object} DkgResult
 * @property {string} share      this participant's share of the joint secret
 * @property {string} publicKey  compressed joint public key
 * @property {string[]} dealers  dealer ids whose contributions were included
 */

/**
 * Sum verified contributions into a final share and the joint public key.
 *
 * This is the step that is DKG rather than VSS: the participant's share of
 * the joint secret is the sum of the shares they were dealt, and the joint
 * public key is the sum of everyone's constant-term commitments — which is
 * `(Σ secrets) · G` without anyone computing `Σ secrets`.
 *
 * Every share is verified here as well as on arrival. Finalizing is the last
 * point at which a bad contribution can be refused, and accepting one
 * silently corrupts the joint key for everyone.
 *
 * @param {{
 *   myId: number|string|bigint,
 *   contributions: Array<{ from: string, share: string, commitments: string[] }>,
 * }} x
 * @returns {DkgResult}
 */
export function finalize({ myId, contributions }) {
  if (!Array.isArray(contributions) || !contributions.length) {
    throw new Error("dkg: no contributions to finalize");
  }
  const seen = new Set();
  for (const c of contributions) {
    if (seen.has(c.from)) {
      throw new Error(`dkg: duplicate contribution from ${String(c.from).slice(0, 8)}…`);
    }
    seen.add(c.from);
    if (!verify({ share: c.share, id: myId, commitments: c.commitments })) {
      // Named, because the remedy is to restart without this dealer — there
      // is no complaint round to adjudicate it.
      throw new Error(
        `dkg: share from ${String(c.from).slice(0, 8)}… does not match their commitments — restart excluding that participant`
      );
    }
  }

  let share = 0n;
  /** @type {string|null} */
  let pub = null;
  for (const c of contributions) {
    share = mod(share + scalarFromHex(c.share));
    const theirs = publicKeyOf(c.commitments);
    // Point addition goes through VSS's commitment adder so curve handling
    // lives in one module rather than being re-derived here.
    pub = pub === null ? theirs : addCommitments([pub], [theirs])[0];
  }
  return {
    share: scalarToHex(share),
    publicKey: /** @type {string} */ (pub),
    dealers: contributions.map((c) => c.from),
  };
}

/**
 * Lagrange-interpolate the joint secret from `threshold` final shares.
 *
 * Never called by the protocol: assembling the secret is precisely what a DKG
 * exists to avoid. It is here for deliberate recovery, and to let the tests
 * prove the shares really do describe the key the commitments claim.
 *
 * @param {Array<{ id: number|string|bigint, share: string }>} shares
 * @returns {string} the secret scalar, hex
 */
export function reconstruct(shares) {
  return combine(shares);
}
