/**
 * Pooled entropy — the value every participant helped choose, and the half of
 * `entropy: { mode: "pool" }` that did not exist.
 *
 * `manifest.js` has declared the slot for a while and says so in its own words:
 * *"What is still not wired is the other half: no op reads a pool."* It also
 * ships the refusal that makes a pool safe — `mirroredRunRefusals` reads each
 * op's declared `entropy` and refuses a `pool` run containing anything that
 * draws `keying` randomness, because entropy the whole room can recompute is a
 * private key the whole room can recompute. That refusal has been guarding a
 * value nothing produced. This module produces it.
 *
 * Public-safe randomness only: salts, nonces, IVs, challenges. The refusal in
 * `manifest.js` is what keeps it there, and it is upstream of everything here.
 *
 * ## Commit, then reveal
 *
 * Sampling one value between mutually suspicious parties has one obvious
 * failure and one obvious fix. If everyone simply announces a nonce, whoever
 * speaks last picks the answer: they wait, see the others, and choose theirs so
 * the sum lands where they want. So each participant first publishes a
 * *commitment* — a digest of their nonce — and only reveals the nonce once the
 * commitments are in. Now the last mover is bound to a choice made blind.
 *
 * A commitment binds the nonce **to its participant**. Without the id in the
 * preimage a commitment is a bare digest of a nonce, and anyone who has seen it
 * can publish it as their own and reveal the same value later — two
 * participants contributing one choice, which is the many-hands illusion this
 * exists to prevent.
 *
 * ## Sorted, so arrival order is not an input
 *
 * The pool is a digest over the reveals sorted by participant id. Two
 * participants whose messages crossed on the wire must compute the same pool or
 * the whole point is lost, and hashing in arrival order would make the value
 * depend on the network. Same reason `audienceDigest` sorts.
 *
 * ## Domain separation
 *
 * Both digests carry a domain prefix in the `basilisk.run-manifest/…/v1` family
 * `PEERS_DOMAIN` and `AUDIENCE_DOMAIN` established. A pool digest must never be
 * some other digest of the same bytes — a commitment must not be mistakable for
 * a pool over one reveal, and a pool must not be mistakable for a peer binding
 * that happens to serialize identically. The prefix is what makes "this digest
 * is a pool" a property of the digest rather than of where it was found.
 *
 * ## A refusal, not a smaller pool
 *
 * Every failure here throws and names who. A pool that quietly proceeded
 * without a contributor would be a pool *the remaining parties chose* — which
 * is precisely the outcome commit-and-reveal exists to prevent, arrived at by
 * accident instead of by cheating. Dropping a participant who cannot open their
 * commitment hands the choice to whoever is left; dropping one whose reveal
 * never arrived hands it to whoever decided to stop waiting.
 *
 * @module lib/toolkit/entropy-pool
 */

import { canonicalJson, digestText } from "./receipt.js";

/** Binds one participant to one nonce, before anybody has revealed. */
export const ENTROPY_COMMIT_DOMAIN = "basilisk.run-manifest/entropy-commit/v1\n";

/** The pooled value itself, over every reveal. */
export const ENTROPY_POOL_DOMAIN = "basilisk.run-manifest/entropy-pool/v1\n";

/**
 * @typedef {object} EntropyReveal
 * @property {string} id     participant, in whatever spelling the room uses
 * @property {string} nonce  the value they committed to, lowercase hex
 */

/** Nonces are hex so a pool preimage is unambiguous bytes, not a text encoding. */
const HEX = /^[0-9a-f]+$/;

/**
 * @param {unknown} raw
 * @param {string} what
 * @returns {string}
 */
function requireId(raw, what) {
  const id = String(raw ?? "").trim();
  if (!id) throw new Error(`entropy pool: ${what} with no participant id`);
  return id;
}

/**
 * @param {unknown} raw
 * @param {string} who
 * @returns {string}
 */
function requireNonce(raw, who) {
  const nonce = String(raw ?? "").trim().toLowerCase();
  if (!nonce) throw new Error(`entropy pool: ${who} revealed no nonce`);
  if (!HEX.test(nonce)) {
    throw new Error(
      `entropy pool: ${who}'s nonce is not hex — a pool is a digest over bytes, and ` +
        "two spellings of the same value would be two different pools"
    );
  }
  // Odd length is half a byte. Refused rather than padded, because padding
  // silently makes two different reveals equal.
  if (nonce.length % 2) {
    throw new Error(`entropy pool: ${who}'s nonce has an odd number of hex digits`);
  }
  return nonce;
}

/**
 * A nonce to contribute.
 *
 * Here rather than in the driver because this module defines what a nonce *is*
 * — hex, even-length, lowercase — and a minter that disagreed with the reader
 * beside it would be two answers to one question. 32 bytes because the pool is
 * a SHA-256 digest and a contribution smaller than the output it feeds is a
 * contribution somebody could search.
 *
 * @param {number} [byteLength]
 * @returns {string} lowercase hex
 */
export function randomNonce(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/**
 * A participant's commitment to a nonce they have not published yet.
 *
 * @param {{ id: string, nonce: string }} reveal
 * @returns {Promise<string>} lowercase hex digest
 */
export async function entropyCommitment({ id, nonce }) {
  const who = requireId(id, "commitment");
  return digestText(
    ENTROPY_COMMIT_DOMAIN + canonicalJson({ id: who, nonce: requireNonce(nonce, who) })
  );
}

/**
 * Reveals in canonical order — sorted by id, and refusing a room that cannot
 * be put in one.
 *
 * @param {EntropyReveal[]} reveals
 * @returns {{ id: string, nonce: string }[]}
 */
function canonicalReveals(reveals) {
  const list = Array.isArray(reveals) ? reveals : [];
  if (!list.length) {
    throw new Error("entropy pool: no reveals — a pool nobody contributed to is not one");
  }
  /** @type {Map<string, string>} */
  const byId = new Map();
  for (const r of list) {
    const id = requireId(r?.id, "reveal");
    if (byId.has(id)) {
      // Not deduped: two reveals under one id means the room disagrees about
      // who contributed what, and picking either one picks a pool.
      throw new Error(`entropy pool: ${id} revealed twice`);
    }
    byId.set(id, requireNonce(r?.nonce, id));
  }
  return [...byId.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([id, nonce]) => ({ id, nonce }));
}

/**
 * The pooled value, over reveals in any order.
 *
 * Does **not** check commitments — `openEntropyPool` does, and is what a room
 * should call. This is the digest on its own so that it can be recomputed by
 * anyone holding the reveals, including someone auditing a manifest long after
 * the commitments are gone.
 *
 * @param {EntropyReveal[]} reveals
 * @returns {Promise<string>} lowercase hex digest
 */
export async function entropyPoolDigest(reveals) {
  return digestText(ENTROPY_POOL_DOMAIN + canonicalJson(canonicalReveals(reveals)));
}

/**
 * @typedef {object} EntropyPool
 * @property {string} digest        the pooled value, for `entropy.digest`
 * @property {string[]} contributors  ids, sorted — who the value is made of
 */

/**
 * Open a round: check every reveal against the commitment it claims to open,
 * then pool.
 *
 * The check is the whole ceremony. A reveal that does not match its commitment
 * is a participant choosing their contribution *after* seeing everyone else's,
 * which is the attack commit-and-reveal exists to stop — and it is refused by
 * name rather than skipped, because a pool computed without them is a pool the
 * rest of the room chose.
 *
 * A commitment with no reveal is refused for the same reason and is *not* the
 * same event: it may be someone who went offline rather than someone who
 * cheated, and the room needs to be able to tell those apart. A reveal with no
 * commitment is refused too — a contribution nobody was bound to is a
 * contribution made in the open, whatever order it happened to arrive in.
 *
 * @param {{ commitments: Record<string, string>, reveals: EntropyReveal[] }} round
 * @returns {Promise<EntropyPool>}
 */
export async function openEntropyPool({ commitments, reveals }) {
  const promised = new Map(
    Object.entries(commitments || {}).map(([id, digest]) => [
      requireId(id, "commitment"),
      String(digest ?? "").trim().toLowerCase(),
    ])
  );
  if (!promised.size) {
    throw new Error("entropy pool: no commitments — there is nothing for a reveal to open");
  }

  const opened = canonicalReveals(reveals);

  const silent = [...promised.keys()].filter((id) => !opened.some((r) => r.id === id)).sort();
  if (silent.length) {
    const err = new Error(
      `entropy pool: ${silent.join(", ")} committed and did not reveal. The round is not ` +
        "complete, and pooling without them would let whoever is left choose the value."
    );
    // The ids as well as the sentence, so a surface can mark the right rows
    // without parsing them back out of a message — the same reason `finalize`
    // carries `dealer`. `silent` and `broken` stay separate because they are
    // different events: somebody offline is not somebody who cheated, and a
    // panel that merged them would accuse the first of being the second.
    Object.assign(err, { silent });
    throw err;
  }

  /** @type {string[]} */
  const broken = [];
  for (const r of opened) {
    if (!promised.has(r.id)) {
      throw new Error(
        `entropy pool: ${r.id} revealed without committing — a contribution nobody was ` +
          "bound to is one chosen in the open"
      );
    }
    if ((await entropyCommitment(r)) !== promised.get(r.id)) broken.push(r.id);
  }
  if (broken.length) {
    const err = new Error(
      `entropy pool: ${broken.join(", ")} revealed a nonce that does not open their ` +
        "commitment. That is a contribution chosen after seeing the others, which is the " +
        "one thing committing first was for — so the round is refused rather than pooled " +
        "without them."
    );
    Object.assign(err, { broken });
    throw err;
  }

  return {
    digest: await digestText(ENTROPY_POOL_DOMAIN + canonicalJson(opened)),
    contributors: opened.map((r) => r.id),
  };
}
