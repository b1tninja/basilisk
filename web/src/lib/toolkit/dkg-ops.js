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
  const { transport, myId, ids, release } = createExchangeTransport("dkg.run");

  const threshold = Math.trunc(Number(params?.threshold) || 2);
  if (threshold < 1) throw new Error("dkg.run: threshold must be at least 1");
  if (threshold > ids.length) {
    throw new Error(
      `dkg.run: threshold ${threshold} exceeds the ${ids.length} participants in this room — the key could never be reconstructed`
    );
  }
  const wait = Math.max(1000, Number(params?.wait) || 120000);

  try {
    const result = await runDkg({
      transport,
      myId,
      ids,
      threshold,
      timeoutMs: wait,
      onProgress: (p) => {
        if (typeof window === "undefined") return;
        // Same one-way channel the exchange state uses, so the shell can show
        // round progress without this module importing React.
        window.dispatchEvent(
          new CustomEvent("basilisk:dkg-progress", { detail: { ...p, threshold } })
        );
      },
    });
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
  } finally {
    release();
  }
}
