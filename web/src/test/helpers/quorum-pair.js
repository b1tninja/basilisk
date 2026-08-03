/**
 * Two live `QuorumSession`s meshing with each other, in node.
 *
 * Nothing about the session is stubbed: real OpenPGP keys, real signed and
 * encrypted signalling envelopes, real ECDH, real key confirmation. Only the
 * two things that are genuinely outside the process are replaced — the
 * keyserver and mailbox HTTP endpoints (`globalThis.fetch`) and the transport
 * (`globalThis.RTCPeerConnection`, see `fake-peer-connection.js`).
 *
 * The mailbox delivers by opening each envelope and **re-sealing it with the
 * original signer's own key**, which is what makes `tamper` meaningful: a
 * tampered payload is indistinguishable from an honest one to every check the
 * protocol makes — right signer, right room, right audience, valid signature.
 * The DTLS binding in the key transcript is the *only* thing that can catch it.
 * That is the oracle: weaken the binding and the tamper goes through unnoticed.
 *
 * Envelopes are re-sealed on the honest path too, so both runs go through
 * identical machinery and a difference in outcome can only come from the
 * payload.
 */

import { generateKey } from "openpgp";
import {
  openSignalingEnvelope,
  sealSignalingEnvelope,
} from "../../lib/quorum/crypto.js";
import { deriveRoomId } from "../../lib/quorum/room.js";
import { QuorumSession } from "../../lib/quorum/rtc.js";
import { FakePeerConnection } from "./fake-peer-connection.js";

/**
 * @typedef {object} PairSide
 * @property {string} fpr
 * @property {import("openpgp").PrivateKey} privateKey
 * @property {QuorumSession} session
 * @property {Error[]} errors
 * @property {{ from: string, text: string, ts: number }[]} chats
 * @property {string[]} statuses
 */

/**
 * @param {object} [opts]
 * @param {(payload: any, fromFpr: string) => any} [opts.tamper]
 *   Called on every signalling payload after it is opened and before it is
 *   re-sealed. Return the payload (mutated or not) to deliver it.
 * @returns {Promise<{
 *   roomId: string,
 *   audience: string[],
 *   creator: PairSide,
 *   joiner: PairSide,
 *   settle: () => Promise<void>,
 *   start: () => Promise<void>,
 *   stop: () => void,
 * }>}
 */
export async function makeQuorumPair({ tamper } = {}) {
  const [a, b] = await Promise.all([
    generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "a@quorum.test" }],
      format: "object",
    }),
    generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "b@quorum.test" }],
      format: "object",
    }),
  ]);

  const aFpr = a.publicKey.getFingerprint().toUpperCase();
  const bFpr = b.publicKey.getFingerprint().toUpperCase();
  const audience = [aFpr, bFpr].sort();
  const roomId = await deriveRoomId(audience);

  const armoredByFpr = new Map([
    [aFpr, a.publicKey.armor()],
    [bFpr, b.publicKey.armor()],
  ]);
  /** @type {Map<string, import("openpgp").Key>} */
  const keyByFpr = new Map([
    [aFpr, a.publicKey],
    [bFpr, b.publicKey],
  ]);
  /** @type {Map<string, import("openpgp").PrivateKey>} */
  const privateByFpr = new Map([
    [aFpr, a.privateKey],
    [bFpr, b.privateKey],
  ]);

  /** @type {PairSide[]} */
  const sides = [];
  let seq = 0;
  let queue = Promise.resolve();
  let stopped = false;

  /**
   * One posted envelope, opened, optionally tampered, re-sealed by its own
   * signer, and handed to everyone except the signer. Serialised through a
   * promise chain so ordering on the wire is the ordering on the mailbox.
   * @param {string} armored
   */
  function enqueue(armored) {
    queue = queue.then(async () => {
      if (stopped) return;
      /** @type {{ payload: any, signerFpr: string }} */
      let opened;
      try {
        opened = await openSignalingEnvelope({
          armored,
          decryptionKey: a.privateKey,
          audienceKeyByFpr: keyByFpr,
          audienceFprs: audience,
          expectedRoomId: roomId,
        });
      } catch (_) {
        return; // an envelope the mailbox itself cannot read never happens here
      }
      const signer = opened.signerFpr;
      const signingKey = privateByFpr.get(signer);
      if (!signingKey) return;
      const payload = tamper ? tamper(opened.payload, signer) : opened.payload;
      const wire = await sealSignalingEnvelope({
        payload,
        signingKey,
        audienceKeys: [...keyByFpr.values()],
      });
      for (const side of sides) {
        if (side.fpr === signer || stopped) continue;
        seq += 1;
        // The poll loop's own seam. Driving it directly rather than waiting on
        // the 1500 ms interval keeps a full handshake inside a test timeout;
        // `_seenSeqs` dedupes, so the real poll running alongside is harmless.
        await Promise.resolve(
          side.session._onMailbox({ seq, payload: wire })
        ).catch((err) => {
          side.errors.push(err instanceof Error ? err : new Error(String(err)));
        });
      }
    });
    return queue;
  }

  const realFetch = globalThis.fetch;
  const realRtc = globalThis.RTCPeerConnection;

  globalThis.fetch = /** @type {any} */ (
    async (url, init) => {
      const href = String(url);
      if (href.startsWith("/pks/lookup")) {
        const fpr = (/search=0x([0-9A-Fa-f]+)/.exec(href)?.[1] || "").toUpperCase();
        const armored = armoredByFpr.get(fpr);
        if (!armored) return new Response("not found", { status: 404 });
        return new Response(armored, {
          status: 200,
          headers: { "content-type": "application/pgp-keys" },
        });
      }
      if (/\/api\/v1\/quorum\/room\//.test(href)) {
        if (String(init?.method || "GET").toUpperCase() === "POST") {
          const body = JSON.parse(String(init?.body || "{}"));
          enqueue(String(body.payload || ""));
          seq += 1;
          return Response.json({ seq, room_id: roomId });
        }
        // The poll finds nothing: delivery already happened on POST.
        return Response.json({ room_id: roomId, messages: [], next_since: 0 });
      }
      return new Response(`unexpected ${href}`, { status: 500 });
    }
  );
  globalThis.RTCPeerConnection = /** @type {any} */ (FakePeerConnection);

  /**
   * @param {import("openpgp").PrivateKey} privateKey
   * @param {string} fpr
   * @param {"creator"|"joiner"} role
   * @returns {PairSide}
   */
  function makeSide(privateKey, fpr, role) {
    /** @type {any} */
    const side = { fpr, privateKey, errors: [], chats: [], statuses: [] };
    side.session = new QuorumSession({
      roomId,
      audienceFprs: audience,
      privateKey,
      myFingerprint: fpr,
      role,
      onChat: (/** @type {any} */ m) => side.chats.push(m),
      onStatus: (/** @type {string} */ s) => side.statuses.push(s),
      onError: (/** @type {Error} */ err) => side.errors.push(err),
    });
    sides.push(side);
    return side;
  }

  const creator = makeSide(a.privateKey, aFpr, "creator");
  const joiner = makeSide(b.privateKey, bFpr, "joiner");

  /** Let every queued envelope, and everything it causes, drain. */
  async function settle() {
    for (let i = 0; i < 40; i += 1) {
      await queue;
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  return {
    roomId,
    audience,
    creator,
    joiner,
    settle,
    async start() {
      await creator.session.start();
      await joiner.session.start();
    },
    stop() {
      stopped = true;
      for (const side of sides) {
        try {
          side.session.stop();
        } catch (_) {
          /* ignore */
        }
      }
      FakePeerConnection.reset();
      globalThis.fetch = realFetch;
      globalThis.RTCPeerConnection = realRtc;
    },
  };
}

/**
 * Poll until `check()` is true or the budget runs out. Real timers — the
 * handshake is a chain of promises and microtasks, not a fixed number of ticks.
 * @param {() => boolean} check
 * @param {number} [budgetMs]
 * @returns {Promise<boolean>}
 */
export async function until(check, budgetMs = 5000) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, 5));
  }
  return check();
}
