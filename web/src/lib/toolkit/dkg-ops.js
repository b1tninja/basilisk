/**
 * `dkg.run` — distributed key generation over the live exchange.
 *
 * One op rather than a step per round, because the rounds are not something a
 * person hand-cranks: each one blocks on every other participant, so a recipe
 * of three chained steps would be three places to stall with no way to say
 * which. The same reasoning `quorum.offer` already follows — it runs a whole
 * handshake and pauses the cell until the mesh forms.
 *
 * The result is deliberately asymmetric: the **share is secret** and the
 * **public key is not**, and they come out of one op because a share without
 * the key it belongs to is unusable and a key without the share is not yours.
 * The value is marked sensitive as a whole; `vss.commitments` is the
 * precedent for publishing the public half deliberately rather than by
 * default.
 *
 * Experimental, and the UI should say so: this produces a shared key, not
 * threshold signing, and it is not a substitute for an audited threshold
 * implementation.
 * @module lib/toolkit/dkg-ops
 */

import { runDkg } from "../quorum/dkg-run.js";
import { createExchangeTransport, getQuorumState } from "./quorum-ops.js";

/**
 * @param {Record<string, unknown>} params
 * @returns {Promise<{ type: string, data: unknown, meta: Record<string, unknown> }>}
 */
export async function execDkgRun(params) {
  const { transport, myId, ids, fingerprintOf, release } =
    createExchangeTransport("dkg.run");

  const threshold = Math.trunc(Number(params?.threshold) || 2);
  if (threshold < 1) throw new Error("dkg.run: threshold must be at least 1");
  if (threshold > ids.length) {
    throw new Error(
      `dkg.run: threshold ${threshold} exceeds the ${ids.length} participants in this room — the key could never be reconstructed`
    );
  }
  const wait = Math.max(1000, Number(params?.wait) || 120000);

  /**
   * One event, four phases, so the shell never has to guess where a run got to.
   *
   * `dkg.run` blocks its cell for up to two minutes and the person watching has
   * two questions: is it still going, and who is it waiting on. Progress answers
   * both. The terminal phases answer the third — how it ended — and they matter
   * more than they look: a refusal is the whole reason `dkg-session.js` exists,
   * and without an event the shell would see only a failed cell and could never
   * show what a bad share actually means for the group.
   *
   * @param {Record<string, unknown>} detail
   */
  const announce = (detail) => {
    if (typeof window === "undefined") return;
    // The same one-way channel the exchange state uses, so this module can talk
    // to the shell without importing React.
    window.dispatchEvent(
      new CustomEvent("basilisk:dkg-progress", {
        detail: { threshold, participants: ids.length, ...detail },
      })
    );
  };

  try {
    const result = await runDkg({
      transport,
      myId,
      ids,
      threshold,
      timeoutMs: wait,
      // Translated to fingerprints on the way out. `runDkg` reports the ids it
      // was given, which are the scalars the polynomial is indexed by; the
      // shell has a roster keyed by fingerprint and nothing that could join the
      // two. Doing it here keeps that knowledge in the one module that already
      // holds both spellings.
      onProgress: (p) =>
        announce({
          phase: "running",
          commitments: p.commitments.map(fingerprintOf),
          shares: p.shares.map(fingerprintOf),
          expected: p.expected.map(fingerprintOf),
        }),
    });
    announce({ phase: "complete", publicKey: result.publicKey });
    const room = getQuorumState().room;
    return {
      type: "text",
      data: JSON.stringify(
        {
          v: 1,
          room,
          threshold,
          participants: ids.length,
          publicKey: result.publicKey,
          share: result.share,
        },
        null,
        2
      ),
      meta: {
        // Sensitive as a whole: the object carries this participant's share.
        sensitive: true,
        dkg: true,
        publicKey: result.publicKey,
        threshold,
        participants: ids.length,
        filename: "dkg-share.json",
      },
    };
  } catch (err) {
    // A bad share is not a failure like the others and must not be flattened
    // into one. `finalize` names the dealer on the error; everything else — a
    // timeout, a cancelled run, a peer that dropped — is reported as itself.
    const dealer = /** @type {any} */ (err)?.dealer;
    announce(
      dealer
        ? { phase: "refused", dealer: fingerprintOf(String(dealer)) }
        : { phase: "failed", message: err instanceof Error ? err.message : String(err) }
    );
    // Rethrown unchanged: the cell still fails, and the panel is a second
    // account of why rather than a replacement for the first.
    throw err;
  } finally {
    release();
  }
}
