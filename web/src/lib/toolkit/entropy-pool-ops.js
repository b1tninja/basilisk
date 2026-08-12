/**
 * `entropy.pool` — commit-and-reveal over the live exchange.
 *
 * One op rather than a step per round, for the reason `dkg-ops.js` states about
 * itself: each round blocks on every other participant, so a recipe of two
 * chained steps would be two places to stall with no way to say which. The
 * rounds are not something a person hand-cranks.
 *
 * ## What it produces, and what it may be used for
 *
 * A value every participant helped choose and every participant can recompute.
 * That is exactly what makes a distributed run agree and exactly what must
 * never reach key generation: a private key everyone can derive is not one.
 * The guard is the compiler's pooled-value rule in `recipe.js`: a value
 * carrying `pooled` may not reach a step that produces key material, and a
 * param takes one only where it says `acceptsPooled` — which is true of a salt,
 * an HKDF `info` and an AEAD's `aad`, all public by definition. It is upstream
 * of this op rather than inside it, because a refusal before the run is worth
 * more than one after the value exists.
 *
 * So: salts, nonces, IVs, challenges, set ids. The op declares `public` for the
 * same reason.
 *
 * ## The digest is recorded, not claimed
 *
 * `manifest.js` has carried `entropy: { mode: "pool", digest }` as a slot with
 * nothing to put in it. `lastPooledEntropy()` is what fills it: the manifest
 * records the pool this run actually drew, or stays at its fail-closed `local`
 * default when no pool was drawn. A manifest that declared `pool` because the
 * notebook *mentions* one would be a claim; this is a record.
 *
 * @module lib/toolkit/entropy-pool-ops
 */

import { runEntropyPool } from "../quorum/pool-run.js";
import { createExchangeTransport, getQuorumState } from "./quorum-ops.js";

/**
 * The pool this run drew, if it drew one.
 *
 * Module state rather than a return value threaded through the engine, because
 * the manifest is built by a different op at a different time and the two share
 * no call stack. Same one-way shape the exchange state uses.
 *
 * @type {{ digest: string, contributors: string[], room: string }|null}
 */
let lastPool = null;

/** What `entropy.pool` last produced in this session, or null. */
export function lastPooledEntropy() {
  return lastPool ? { ...lastPool, contributors: [...lastPool.contributors] } : null;
}

/**
 * Forget it. Called when a session ends: a pool describes a room, and a digest
 * that outlived its room would be recorded against the wrong one.
 */
export function clearPooledEntropy() {
  lastPool = null;
}

/**
 * @param {Record<string, unknown>} params
 * @returns {Promise<{ type: string, data: unknown, meta: Record<string, unknown> }>}
 */
export async function execEntropyPool(params) {
  const { transport, myId, ids, fingerprintOf, release } =
    createExchangeTransport("entropy.pool");
  const wait = Math.max(1000, Number(params?.wait) || 120000);

  const announce = (detail) => {
    if (typeof window === "undefined") return;
    window.dispatchEvent(
      new CustomEvent("basilisk:entropy-pool", {
        detail: { participants: ids.length, ...detail },
      })
    );
  };

  try {
    const result = await runEntropyPool({
      transport,
      myId,
      ids,
      timeoutMs: wait,
      // Fingerprints on the way out, as `dkg-ops.js` does: the driver reports
      // the ids it was given, and the shell's roster is keyed by fingerprint.
      onProgress: (p) =>
        announce({
          phase: "running",
          round: p.round,
          commitments: p.commitments.map(fingerprintOf),
          reveals: p.reveals.map(fingerprintOf),
          expected: p.expected.map(fingerprintOf),
        }),
    });

    const room = getQuorumState().room;
    const contributors = result.contributors.map(fingerprintOf);
    lastPool = { digest: result.digest, contributors, room };
    announce({ phase: "complete", digest: result.digest, contributors });

    return {
      type: "bytes",
      data: hexToBytes(result.digest),
      meta: {
        // Public by construction and by policy: every participant can
        // recompute it, so marking it sensitive would be false and would hide
        // the one number the room needs to compare.
        kind: "opaque",
        entropyPool: true,
        digest: result.digest,
        room,
        contributors,
        participants: ids.length,
        filename: "pool.bin",
      },
    };
  } catch (err) {
    // A round that refused is not the same event as one that broke, and the
    // panel has to tell them apart: `broken` is a participant who revealed
    // something that does not open their commitment — a contribution chosen
    // after seeing the others — and `silent` is one who committed and went
    // away. Everything else (a timeout, a cancelled run, a peer that dropped)
    // is reported as itself.
    const broken = /** @type {any} */ (err)?.broken;
    const silent = /** @type {any} */ (err)?.silent;
    announce(
      broken?.length || silent?.length
        ? {
            phase: "refused",
            broken: (broken || []).map(fingerprintOf),
            silent: (silent || []).map(fingerprintOf),
            message: err instanceof Error ? err.message : String(err),
          }
        : { phase: "failed", message: err instanceof Error ? err.message : String(err) }
    );
    // Rethrown unchanged: the cell still fails, and a pool that refused must
    // not leave a digest behind for the manifest to record.
    throw err;
  } finally {
    release();
  }
}

/**
 * @param {string} hex
 * @returns {Uint8Array}
 */
function hexToBytes(hex) {
  const s = String(hex || "");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
