/**
 * Two live `NotebookSession`s meshing with each other, in node.
 *
 * Nothing about the session is stubbed: real OpenPGP keys, real signed and
 * encrypted signalling envelopes, real ECDH, real key confirmation. Only the
 * three things that are genuinely outside the process are replaced — the
 * keyserver and the negotiate endpoint (`globalThis.fetch`), the signalling
 * service (`globalThis.WebSocket`, see `webpubsub-double.js`) and the peer
 * transport (`globalThis.RTCPeerConnection`, see `fake-peer-connection.js`).
 *
 * The relay delivers by opening each envelope and **re-sealing it with the
 * original signer's own key**, which is what makes `tamper` meaningful: a
 * tampered payload is indistinguishable from an honest one to every check the
 * protocol makes — right signer, right room, right audience, valid signature.
 * The DTLS binding in the key transcript is the *only* thing that can catch it.
 * That is the oracle: weaken the binding and the tamper goes through unnoticed.
 *
 * The tamper sits in the relay's publish path rather than in a mailbox, which
 * is where a hostile signalling service would actually be — the session's own
 * `_envSeen` drops the copy echoed back to the sender, so a rewritten envelope
 * reaches only the peer it was aimed at.
 *
 * Envelopes are re-sealed on the honest path too, so both runs go through
 * identical machinery and a difference in outcome can only come from the
 * payload.
 */

import { generateKey } from "openpgp";
import {
  openSignalingEnvelope,
  sealSignalingEnvelope,
} from "../../lib/notebook/crypto.js";
import { deriveRoomId } from "../../lib/notebook/room.js";
import { NotebookSession } from "../../lib/notebook/session.js";
import { FakePeerConnection } from "./fake-peer-connection.js";
import { installWebPubSubDouble } from "./webpubsub-double.js";

/**
 * @typedef {object} PairSide
 * @property {string} fpr
 * @property {import("openpgp").PrivateKey} privateKey
 * @property {NotebookSession} session
 * @property {Error[]} errors
 * @property {{ from: string, text: string, ts: number }[]} chats
 * @property {any[]} manifests      manifests that arrived, verified and parsed
 * @property {any[]} attestations   attestations that arrived, verified and parsed
 * @property {any[]} offers         handoff offers that arrived and parsed — pending,
 *   never accepted: nothing in the session can accept one
 * @property {any[]} results        cell results that arrived, were checked against
 *   the sender's key and parsed — equally pending: no slot registered, no run
 *   restarted, and nothing in the session that could do either
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
  let stopped = false;

  /**
   * One published envelope, opened, optionally tampered, and re-sealed by its
   * own signer before the relay broadcasts it.
   * @param {string} armored
   * @returns {Promise<string>}
   */
  async function relayTransform(armored) {
    if (stopped) return armored;
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
      return armored; // an envelope the relay cannot read never happens here
    }
    const signer = opened.signerFpr;
    const signingKey = privateByFpr.get(signer);
    if (!signingKey) return armored;
    const payload = tamper ? tamper(opened.payload, signer) : opened.payload;
    return sealSignalingEnvelope({
      payload,
      signingKey,
      audienceKeys: [...keyByFpr.values()],
    });
  }

  const realFetch = globalThis.fetch;
  const realRtc = globalThis.RTCPeerConnection;
  const relay = installWebPubSubDouble({ transform: relayTransform });

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
      if (href.includes("/pks/v2/challenge")) {
        return Response.json({ nonce: "n", timestamp: 0, difficulty: 0, hint: "n:0:sig" });
      }
      if (href.includes("/api/v1/notebook/negotiate")) {
        const body = JSON.parse(String(init?.body || "{}"));
        return Response.json(await relay.grantFor(String(body.room || roomId)));
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
    const side = {
      fpr,
      privateKey,
      errors: [],
      chats: [],
      manifests: [],
      attestations: [],
      offers: [],
      results: [],
      statuses: [],
    };
    side.session = new NotebookSession({
      roomId,
      audienceFprs: audience,
      privateKey,
      myFingerprint: fpr,
      role,
      onChat: (/** @type {any} */ m) => side.chats.push(m),
      onManifest: (/** @type {any} */ d) => side.manifests.push(d),
      onAttestation: (/** @type {any} */ d) => side.attestations.push(d),
      onOffer: (/** @type {any} */ d) => side.offers.push(d),
      onResult: (/** @type {any} */ d) => side.results.push(d),
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
      await relay.settled();
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  return {
    roomId,
    audience,
    creator,
    joiner,
    settle,
    /**
     * The joiner first, deliberately.
     *
     * The invite is published exactly once, the moment the creator's own room
     * is joined, and the relay does not replay. So "creator first" only ever
     * worked here because the transform's OpenPGP round trip happened to
     * outlast the joiner's handshake — a margin measured in milliseconds that
     * any change to either side could spend. Starting the joiner first removes
     * the race rather than winning it, and matches the only ordering in which
     * a joiner is guaranteed to hear an invite at all.
     */
    async start() {
      await joiner.session.start();
      await creator.session.start();
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
      relay.restore();
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
