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
 * @property {any[]} notebooks      notebook proposals that arrived, were checked
 *   against the sender's key and parsed — pending, exactly as the rest are:
 *   nothing in the session adopts one, and this side has no notebook to adopt
 *   into. Adopting is `decideProposal` plus the shell.
 * @property {any[]} offers         handoff offers that arrived and parsed — pending,
 *   never accepted: nothing in the session can accept one
 * @property {any[]} results        cell results that arrived, were checked against
 *   the sender's key and parsed — equally pending: no slot registered, no run
 *   restarted, and nothing in the session that could do either
 * @property {string[]} statuses
 * @property {{ epoch: number, roomId: string, audience: string[],
 *   removed: string[] }[]} rotations
 *   Every time this session finished following the room to a new epoch —
 *   whether it ordered the move or was told about it. The layer above reads
 *   this to find out who is in the room, so which sides receive it is the
 *   whole question `notebook-rotation.test.js` asks of it.
 * @property {number} ownKeyElsewhere  times this session was told another
 *   session is signing as its key
 */

/**
 * @param {object} [opts]
 * @param {(payload: any, fromFpr: string) => any} [opts.tamper]
 *   Called on every signalling payload after it is opened and before it is
 *   re-sealed. Return the payload (mutated or not) to deliver it.
 * @param {boolean} [opts.sameKey]
 *   Give **both** sides `a`'s private key and `a`'s fingerprint, leaving the
 *   audience the same two fingerprints. That is two tabs of one browser whose
 *   user picked the same key in each: they share an IndexedDB vault, so both
 *   halves of the pair are one identity, and the second identity in the
 *   audience is nobody. Everything else — relay, keyserver, transport — is
 *   untouched, so what the pair does differently is only ever the key.
 * @returns {Promise<{
 *   roomId: string,
 *   audience: string[],
 *   creator: PairSide,
 *   joiner: PairSide,
 *   settle: () => Promise<void>,
 *   start: () => Promise<void>,
 *   stop: () => Promise<void>,
 * }>}
 */
export async function makeQuorumPair({ tamper, sameKey = false } = {}) {
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
      notebooks: [],
      offers: [],
      results: [],
      statuses: [],
      rotations: [],
      ownKeyElsewhere: 0,
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
      onNotebook: (/** @type {any} */ d) => side.notebooks.push(d),
      onOffer: (/** @type {any} */ d) => side.offers.push(d),
      onResult: (/** @type {any} */ d) => side.results.push(d),
      onStatus: (/** @type {string} */ s) => side.statuses.push(s),
      onRotate: (/** @type {any} */ m) => side.rotations.push(m),
      onOwnKeyElsewhere: () => {
        side.ownKeyElsewhere += 1;
      },
      onError: (/** @type {Error} */ err) => side.errors.push(err),
    });
    sides.push(side);
    return side;
  }

  const creator = makeSide(a.privateKey, aFpr, "creator");
  const joiner = sameKey
    ? makeSide(a.privateKey, aFpr, "joiner")
    : makeSide(b.privateKey, bFpr, "joiner");

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
     * The joiner first — the shortest path, no longer the only one.
     *
     * This ordering used to be a *requirement*: the invite was published exactly
     * once, the relay does not replay, and a creator that went first published
     * into an empty room and stranded the other end for good. A joiner now
     * knocks when it arrives and the creator answers (`NotebookSession._onKnock`),
     * so either order meshes — `startCreatorFirst` is the same pair the other way
     * round, and `notebook-late-join.test.js` drives both.
     *
     * It stays the default because it is still the cheapest: nothing has to be
     * re-sent, and no test that is about something else should pay for a second
     * round trip.
     */
    async start() {
      await joiner.session.start();
      await creator.session.start();
    },
    /**
     * The creator alone in the room first, and only then the joiner.
     *
     * `settle()` between them is the point rather than a precaution: it lets the
     * creator's invite, its `hello` and its offer all reach the relay and be
     * broadcast to nobody, so the joiner starts into a room where every
     * introduction has already been spent. That is the reported failure, made to
     * happen on purpose rather than raced for.
     */
    async startCreatorFirst() {
      await creator.session.start();
      await settle();
      await joiner.session.start();
    },
    /**
     * Tear the pair down, and **drain the relay first**.
     *
     * `NotebookSession.stop()` zeroes its OpenPGP private key in place, which is
     * right — key material should not outlive the session holding it. But this
     * double re-signs every envelope it carries, with the *sender's* key, on a
     * queue; and under `sameKey` the two sides and this transform are all
     * holding the one key object. A transform already past the `stopped` check
     * when `stop()` ran went on to sign with a key that had just been wiped
     * underneath it, which OpenPGP reports as `Invalid keyData` — an unhandled
     * rejection with no test to attach it to, of the kind vitest warns "might
     * cause false positive tests".
     *
     * So: stop accepting work, let what is already in flight finish while its
     * key is still alive, and only then tear down. Awaiting `settled()` before
     * `session.stop()` rather than after is the whole of the fix — after would
     * be draining a queue whose signer is already gone.
     *
     * Async for that await, which is why every `afterEach` that calls this one
     * awaits it. The session's own late traffic is a different problem with a
     * different fix — see `_sealAndSend`'s `_stopped` guard, which is about
     * transport callbacks nobody asked for rather than about this queue.
     */
    async stop() {
      stopped = true;
      await relay.settled();
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
