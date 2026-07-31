/**
 * The DKG round driver — what actually runs the protocol.
 *
 * `dkg.js` has the arithmetic and `dkg-session.js` has the state model the UI
 * projects; this is the piece between them that sends and waits. It is written
 * against an **injected transport** rather than the mesh, for one reason worth
 * stating: a distributed protocol whose only test is "two browsers, by hand"
 * is a protocol that is never tested. With the transport as a parameter, N
 * participants can be run headlessly in-process, concurrently, against the
 * real arithmetic — and the same driver then takes the live exchange.
 *
 * ## The rounds
 *
 * 1. Deal locally, **broadcast** commitments, **send each peer their own
 *    share** pairwise. Commitments are public; shares are not, and the mesh
 *    gives per-peer channels for free, which is why a mesh and not an SFU.
 * 2. Collect. A contribution is complete only when *both* halves have arrived
 *    from a participant — their commitments and the share addressed to us.
 * 3. Finalize, which verifies every share against its dealer's commitments
 *    before summing. `dkg.js` refuses and names the dealer on a mismatch.
 *
 * ## What this deliberately does not do
 *
 * There is no complaint round, so there is no message type for accusing a
 * dealer and no path that excludes one. A refusal ends the run and names who
 * caused it; the group restarts out of band. Adding an "exclude" message
 * without the adjudication that validates it would build the eviction
 * primitive and skip the part that makes it safe — see `dkg-session.js` for
 * why that is a design decision rather than an omission.
 * @module lib/quorum/dkg-run
 */

import { finalize, round1, scalarToHex } from "./dkg.js";
import { normalizeIds, shortId } from "./vss.js";

/** Wire types. Kept tiny and versioned — these ride a data channel. */
export const DKG_COMMIT = "dkg-commit";
export const DKG_SHARE = "dkg-share";


/**
 * @typedef {object} DkgTransport
 * @property {(msg: object) => void | Promise<void>} broadcast  to every participant
 * @property {(id: string, msg: object) => void | Promise<void>} sendTo  to one
 * @property {(handler: (msg: object) => void) => (() => void)} subscribe
 *   returns an unsubscribe function
 */

/**
 * @typedef {object} DkgProgress
 * @property {number} commitments  participants whose commitments have arrived
 * @property {number} shares       participants whose share to us has arrived
 * @property {number} expected     peers we are waiting on (excludes us)
 */

/**
 * Run one distributed key generation to completion.
 *
 * @param {{
 *   transport: DkgTransport,
 *   myId: string,
 *   ids: string[],
 *   threshold: number,
 *   timeoutMs?: number,
 *   onProgress?: (p: DkgProgress) => void,
 *   signal?: { aborted: boolean },
 * }} opts
 * @returns {Promise<{ share: string, publicKey: string, dealers: string[] }>}
 */
export async function runDkg({
  transport,
  myId,
  ids,
  threshold,
  timeoutMs = 120000,
  onProgress,
  signal,
}) {
  // Canonicalize once, here, so every participant indexes the polynomial the
  // same way regardless of how their caller spelled the ids. A disagreement
  // about ids is indistinguishable from a bad dealer at verification time,
  // which would be a miserable thing to debug.
  const parties = normalizeIds(ids).map((s) => scalarToHex(s));
  const me = scalarToHex(normalizeIds([myId])[0]);
  if (!parties.includes(me)) {
    throw new Error("dkg: my own id is not in the participant list");
  }
  const peers = parties.filter((p) => p !== me);
  if (!peers.length) throw new Error("dkg: a distributed key generation needs at least two participants");

  const dealt = round1({ ids: parties, threshold });

  /** @type {Map<string, string[]>} dealer id → their commitments */
  const commitments = new Map([[me, dealt.commitments]]);
  /** @type {Map<string, string>} dealer id → the share they dealt us */
  const shares = new Map([[me, dealt.shares[me]]]);

  const report = () =>
    onProgress?.({
      commitments: commitments.size - 1,
      shares: shares.size - 1,
      expected: peers.length,
    });

  /** @type {(() => void) | null} */
  let resolveDone = null;
  const done = new Promise((resolve) => {
    resolveDone = /** @type {() => void} */ (resolve);
  });

  const complete = () =>
    peers.every((p) => commitments.has(p) && shares.has(p));

  const unsubscribe = transport.subscribe((msg) => {
    if (!msg || typeof msg !== "object") return;
    const from = String(msg.from || "");
    // Ignore anything from outside the agreed participant set, and our own
    // echo — a broadcast that loops back must not count as a contribution.
    if (!parties.includes(from) || from === me) return;

    if (msg.t === DKG_COMMIT && Array.isArray(msg.commitments)) {
      // First writing wins. A dealer who broadcasts twice with different
      // commitments is trying to split the group's view of their polynomial;
      // taking the first means everyone who heard it agrees, and the second
      // set simply fails verification for whoever it was aimed at.
      if (!commitments.has(from)) {
        commitments.set(from, msg.commitments.map(String));
        report();
      }
    } else if (msg.t === DKG_SHARE && typeof msg.share === "string") {
      if (String(msg.to || "") !== me) return; // not ours to hold
      if (!shares.has(from)) {
        shares.set(from, msg.share);
        report();
      }
    }
    if (complete()) resolveDone?.();
  });

  /** @type {any} */
  let timer = null;
  try {
    await transport.broadcast({
      t: DKG_COMMIT,
      v: 1,
      from: me,
      commitments: dealt.commitments,
    });
    for (const peer of peers) {
      await transport.sendTo(peer, {
        t: DKG_SHARE,
        v: 1,
        from: me,
        to: peer,
        share: dealt.shares[peer],
      });
    }
    report();

    if (!complete()) {
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          const missing = peers.filter(
            (p) => !commitments.has(p) || !shares.has(p)
          );
          reject(
            new Error(
              `dkg: timed out after ${Math.round(timeoutMs / 1000)}s waiting on ${missing.length} of ${peers.length} participants (${missing
                .map(shortId)
                .join(", ")})`
            )
          );
        }, timeoutMs);
      });
      const aborted = signal
        ? new Promise((_, reject) => {
            const poll = setInterval(() => {
              if (signal.aborted) {
                clearInterval(poll);
                reject(new Error("dkg: cancelled"));
              }
            }, 150);
            void done.finally(() => clearInterval(poll));
          })
        : null;
      await (aborted ? Promise.race([done, timeout, aborted]) : Promise.race([done, timeout]));
    }
  } finally {
    if (timer) clearTimeout(timer);
    unsubscribe();
  }

  // Ordered by the canonical participant list rather than arrival, so every
  // participant sums in the same order and any future transcript of the run is
  // comparable between them.
  const contributions = parties.map((id) => ({
    from: id,
    share: /** @type {string} */ (shares.get(id)),
    commitments: /** @type {string[]} */ (commitments.get(id)),
  }));
  return finalize({ myId: me, contributions });
}

/**
 * An in-memory transport wiring participants to each other.
 *
 * Exported rather than kept in the test file because it is the honest way to
 * exercise this driver — and because a caller wanting to rehearse a ceremony
 * without a network deserves the same thing.
 *
 * @param {string[]} ids
 * @returns {Map<string, DkgTransport>}
 */
export function createLoopbackTransports(ids) {
  /** @type {Map<string, ((msg: object) => void)[]>} */
  const handlers = new Map(ids.map((id) => [id, []]));
  /**
   * Messages that arrived before their recipient started listening.
   *
   * Not a convenience for the test: participants do not start simultaneously,
   * so the first dealer broadcasts while others are still generating their
   * polynomial. Dropping those would make the protocol depend on start order.
   * The live transport has the same property — `quorum-ops` queues received
   * messages in an inbox until a reader takes them — so buffering here models
   * the real channel rather than papering over it.
   * @type {Map<string, object[]>}
   */
  const pending = new Map(ids.map((id) => [id, []]));

  /** Deliver asynchronously: same-tick delivery would hide ordering bugs that
   * a real channel exposes immediately. */
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
          // Drain in arrival order, so first-writing-wins stays meaningful.
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
