/**
 * The entropy-pool rounds, driven over a transport somebody else supplies.
 *
 * Same shape as `dkg-run.js` and for the same reason: the transport is a
 * parameter, so the whole ceremony can be run with N participants in one
 * process and proven before it ever meets a browser or a mesh. That is what
 * made the DKG testable without two browsers, and a pool is a strictly simpler
 * protocol — two broadcasts and a digest.
 *
 * `lib/toolkit/entropy-pool.js` owns what a commitment and a pool *are*. This
 * owns *when*: the one ordering rule that makes commit-and-reveal worth doing.
 *
 * ## Nobody reveals until every commitment is in
 *
 * That sentence is the protocol. If a participant reveals while a commitment is
 * still outstanding, whoever has not committed can choose theirs after seeing a
 * contribution — which is precisely the last-mover advantage committing was
 * for. So round 2 does not begin until round 1 is complete, and a participant
 * who withholds their commitment stalls the round rather than subverting it.
 * Stalling is the correct failure: it times out, names who was missing, and
 * produces nothing.
 *
 * ## What this cannot do
 *
 * There is no agreement layer under the broadcast. A participant who sends
 * different commitments to different peers splits the room's view, and each
 * half computes a pool the other does not have — detectable only by comparing
 * the resulting digests, which is a thing the participants can do and this
 * driver cannot do for them. Fixing it properly needs a broadcast channel with
 * agreement, which is a different protocol; saying so is better than a check
 * that half-catches it.
 *
 * @module lib/quorum/pool-run
 */

import {
  entropyCommitment,
  openEntropyPool,
  randomNonce,
} from "../toolkit/entropy-pool.js";
import { shortId } from "./vss.js";

/** Round 1: `{ t, v, from, commit }`. */
export const POOL_COMMIT = "pool-commit";
/** Round 2: `{ t, v, from, nonce }`. */
export const POOL_REVEAL = "pool-reveal";

/**
 * @typedef {object} PoolProgress
 * @property {"committing"|"revealing"} round  which half is outstanding
 * @property {string[]} commitments  who has committed, in the caller's ids
 * @property {string[]} reveals      who has revealed
 * @property {string[]} expected     every peer this run waits on (never us)
 *
 * Identity rather than counts, for the reason `DkgProgress` learned: a surface
 * that has to say *which* participant is still silent cannot derive it from a
 * total, and inventing it is the one thing a progress display must not do.
 */

/**
 * Run one entropy pool to completion.
 *
 * @param {{
 *   transport: import("./dkg-run.js").DkgTransport,
 *   myId: string,
 *   ids: string[],
 *   nonce?: string,
 *   timeoutMs?: number,
 *   onProgress?: (p: PoolProgress) => void,
 *   signal?: { aborted: boolean },
 * }} opts
 * @returns {Promise<{ digest: string, contributors: string[], nonce: string }>}
 */
export async function runEntropyPool({
  transport,
  myId,
  ids,
  nonce = randomNonce(),
  timeoutMs = 120000,
  onProgress,
  signal,
}) {
  const parties = [...new Set((ids || []).map((x) => String(x)))];
  const me = String(myId);
  if (!parties.includes(me)) {
    throw new Error("entropy pool: my own id is not in the participant list");
  }
  const peers = parties.filter((p) => p !== me);
  if (!peers.length) {
    throw new Error("entropy pool: a pool needs at least two participants");
  }

  const mine = await entropyCommitment({ id: me, nonce });
  /** @type {Map<string, string>} id → their commitment */
  const commitments = new Map([[me, mine]]);
  /** @type {Map<string, string>} id → the nonce they revealed */
  const reveals = new Map([[me, nonce]]);

  /** Ordered by the participant list, so every seat reports the same roster. */
  const arrived = (held) => peers.filter((p) => held.has(p));
  /** @type {"committing"|"revealing"} */
  let round = "committing";
  const report = () =>
    onProgress?.({
      round,
      // First-writing-wins below, and these read the maps rather than counting
      // messages, so a peer who broadcasts twice appears once.
      commitments: arrived(commitments),
      reveals: arrived(reveals),
      expected: [...peers],
    });

  /** @type {(() => void)|null} */
  let wake = null;
  const settled = () => wake?.();
  const nextChange = () => new Promise((resolve) => (wake = () => resolve(undefined)));

  const unsubscribe = transport.subscribe((msg) => {
    if (!msg || typeof msg !== "object") return;
    const from = String(msg.from || "");
    // Anything from outside the agreed set, and our own echo, is not a
    // contribution — a broadcast that loops back must not count as one.
    if (!parties.includes(from) || from === me) return;

    if (msg.t === POOL_COMMIT && typeof msg.commit === "string") {
      // First writing wins. A participant who broadcasts a second, different
      // commitment is trying to split the room's view of what they promised;
      // taking the first means everyone who heard it agrees, and their reveal
      // will simply fail to open it for whoever kept the other.
      if (!commitments.has(from)) {
        commitments.set(from, msg.commit);
        report();
        settled();
      }
      return;
    }
    if (msg.t === POOL_REVEAL && typeof msg.nonce === "string") {
      if (!reveals.has(from)) {
        reveals.set(from, msg.nonce);
        report();
        settled();
      }
    }
  });

  /**
   * Wait until `held` has every peer, or fail saying who is missing.
   * @param {Map<string, string>} held
   * @param {string} what
   */
  async function waitForAll(held, what) {
    const deadline = Date.now() + timeoutMs;
    while (peers.some((p) => !held.has(p))) {
      if (signal?.aborted) throw new Error("entropy pool: cancelled");
      const left = deadline - Date.now();
      if (left <= 0) {
        const missing = peers.filter((p) => !held.has(p));
        throw new Error(
          `entropy pool: timed out after ${Math.round(timeoutMs / 1000)}s waiting for ` +
            `${what} from ${missing.length} of ${peers.length} participants ` +
            `(${missing.map(shortId).join(", ")}). Nothing was pooled: a value drawn ` +
            "without them would be one the rest of us chose."
        );
      }
      /** @type {any} */
      let timer = null;
      await Promise.race([
        nextChange(),
        new Promise((resolve) => {
          timer = setTimeout(resolve, Math.min(left, 100));
        }),
      ]);
      if (timer) clearTimeout(timer);
    }
  }

  try {
    await transport.broadcast({ t: POOL_COMMIT, v: 1, from: me, commit: mine });
    report();
    // **The ordering rule.** Not one line earlier: revealing while a commitment
    // is outstanding hands the last mover exactly the choice committing was
    // meant to take away from them.
    await waitForAll(commitments, "commitments");

    round = "revealing";
    report();
    await transport.broadcast({ t: POOL_REVEAL, v: 1, from: me, nonce });
    await waitForAll(reveals, "reveals");
  } finally {
    unsubscribe();
  }

  // Checked, not assembled: `openEntropyPool` refuses a round in which any
  // reveal fails to open its commitment, and refuses it by name rather than
  // pooling without them.
  const { digest, contributors } = await openEntropyPool({
    commitments: Object.fromEntries(commitments),
    reveals: [...reveals.entries()].map(([id, n]) => ({ id, nonce: n })),
  });
  return { digest, contributors, nonce };
}

/**
 * An in-memory transport wiring participants to each other.
 *
 * The same escape hatch `dkg-run.js` exports and for the same reason: it is the
 * honest way to exercise this driver, and a caller rehearsing a ceremony
 * without a network deserves it too. Delivery is asynchronous and buffered
 * before a subscriber exists, because participants do not start together.
 *
 * @param {string[]} ids
 * @returns {Map<string, import("./dkg-run.js").DkgTransport>}
 */
export function createLoopbackTransports(ids) {
  /** @type {Map<string, ((msg: object) => void)[]>} */
  const handlers = new Map(ids.map((id) => [id, []]));
  /** @type {Map<string, object[]>} */
  const pending = new Map(ids.map((id) => [id, []]));

  const deliver = (to, msg) => {
    const copy = JSON.parse(JSON.stringify(msg));
    const list = handlers.get(to) || [];
    if (!list.length) {
      pending.get(to)?.push(copy);
      return;
    }
    for (const h of list) setTimeout(() => h(copy), 0);
  };

  return new Map(
    ids.map((me) => [
      me,
      {
        broadcast(msg) {
          for (const other of ids) if (other !== me) deliver(other, msg);
        },
        sendTo(id, msg) {
          deliver(id, msg);
        },
        subscribe(handler) {
          handlers.get(me)?.push(handler);
          const queued = pending.get(me) || [];
          while (queued.length) {
            const msg = /** @type {object} */ (queued.shift());
            setTimeout(() => handler(msg), 0);
          }
          return () => {
            const list = handlers.get(me) || [];
            const i = list.indexOf(handler);
            if (i >= 0) list.splice(i, 1);
          };
        },
      },
    ])
  );
}
