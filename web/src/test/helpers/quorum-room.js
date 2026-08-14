/**
 * A room: the two things a `QuorumSession` needs from outside the browser, and
 * nothing else.
 *
 * `browser-peers.js` serves static files, so a page it opens can construct a
 * peer connection but cannot run a *session* — the mesh bootstraps through an
 * HTTP mailbox (`/api/v1/quorum/room/…/messages`) and a keyserver
 * (`/pks/lookup`). That is the whole reason key confirmation had never been
 * shown between two real browsers: the transport was reachable and the protocol
 * was not. This module supplies both, in memory, for exactly the identities the
 * test itself generated.
 *
 * ## Why the room counts its members rather than destructuring them
 *
 * It minted `[a, b]` and named the two of them in a dozen places, which was
 * honest while every caller wanted a pair. A three-party ceremony wants three,
 * and almost nothing had to change to get it: the audience, the key maps and
 * the members array were already collections, so only the *minting* and the
 * decryption key were written as two. `count` is now a parameter and the
 * identities are an array.
 *
 * `members[0]` opens every envelope, which is what `a` did and is not a
 * shortcut: a signalling envelope is sealed to the whole audience, so any one
 * member's key opens any of them. Holding all the private keys is a property of
 * a fixture that minted them, not a claim about the protocol — each browser
 * still holds exactly one and learns the rest from `/pks/lookup`.
 *
 * ## Why the mailbox opens every envelope
 *
 * A relay does not have to. This one does, for the same reason
 * `helpers/quorum-pair.js` does: it is the seam where a **tamper** is possible
 * at all, and a tamper is the only way to show that key confirmation is doing
 * work rather than passing by construction.
 *
 * Every envelope is opened, optionally rewritten, and **re-sealed with the
 * original signer's own private key** — right signer, right room, right
 * audience, valid signature, correct `from`. Nothing in the PGP layer can tell
 * a rewritten payload from an honest one. Only the DTLS binding in the key
 * transcript can. Envelopes on the honest path go through the identical
 * open/re-seal machinery, so a difference in outcome between the two runs can
 * only have come from the payload.
 *
 * Both private keys are held here because the test generated both. That is a
 * property of a *fixture*, not a claim about the protocol: the sessions under
 * test each hold one key and learn the other from `/pks/lookup`, exactly as a
 * browser would.
 *
 * ## What it records
 *
 * Opening the envelopes also means this module sees every `offer` and `answer`
 * payload — the `sdp` a real Chromium minted and the `dtlsFingerprint` its
 * session claimed for it, together. Comparing those two is the provenance
 * check: it says the fingerprint that reached the transcript is the one the
 * transport actually committed to, read back out of the SDP by an independent
 * parser. A driver reporting one constant, or a fabricated value, fails it.
 *
 * ## Faults are not swallowed
 *
 * An envelope the mailbox cannot open, or a request for a room or key it does
 * not have, is recorded in `faults()` rather than answered vaguely. A harness
 * that quietly dropped signalling would show up as "the peers never meshed",
 * which reads as a transport defect — the exact mistranslation the skip
 * discipline in `browser-peers.js` exists to prevent.
 *
 * @module test/helpers/quorum-room
 */

import { generateKey } from "openpgp";
import {
  openSignalingEnvelope,
  sealSignalingEnvelope,
} from "../../lib/notebook/crypto.js";
import { deriveRoomId } from "../../lib/notebook/room.js";

/**
 * The loopback address `browser-peers.js` serves on. The room id is derived
 * from the audience *and the deployment scope*, and in a page that scope is
 * `location.hostname` — so a room derived in node under the default
 * ("localhost") would not be the room the browser is in.
 */
export const ROOM_SCOPE = "127.0.0.1";

/**
 * @typedef {object} SignalledFact
 * @property {number} seq
 * @property {string} signer       fingerprint of the signing key
 * @property {string} type         invite | hello | offer | answer | ice
 * @property {string} to           addressee, or "" for a broadcast
 * @property {string} dtlsFingerprint  what the sender claimed, "" if absent
 * @property {string} sdp          the description it claimed it for, "" if absent
 * @property {boolean} tampered    whether the tamper hook changed this payload
 */

/**
 * @typedef {object} RoomMember
 * @property {string} fpr
 * @property {string} armoredPublic
 * @property {string} armoredPrivate
 */

/**
 * @typedef {object} QuorumRoom
 * @property {string} roomId
 * @property {string[]} audience         canonical (sorted) fingerprints
 * @property {RoomMember[]} members      in audience order — [0] is the offerer
 * @property {(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => boolean} routes
 * @property {() => SignalledFact[]} signalled
 * @property {() => string[]} faults
 * @property {() => { posts: number, polls: number, lookups: number }} counts
 */

/**
 * `count` fresh identities, a room derived from them, and the HTTP surface a
 * session bootstraps through.
 *
 * @param {object} [opts]
 * @param {number} [opts.count]  how many identities to mint; two by default,
 *   which is every caller that predates the three-party ceremony.
 * @param {(payload: any, signerFpr: string) => any} [opts.tamper]
 *   Called on every opened payload before it is re-sealed. Mutate and return it
 *   to deliver something other than what was posted; return it untouched for an
 *   honest relay.
 * @returns {Promise<QuorumRoom>}
 */
export async function createQuorumRoom({ count = 2, tamper } = {}) {
  const size = Math.max(2, Math.trunc(count));
  const keys = await Promise.all(
    Array.from({ length: size }, (_, i) =>
      generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        // `a@`, `b@`, `c@` — the letters the two-party fixture used, continued,
        // so a fingerprint printed in a failure is still traceable to a person
        // by eye.
        userIDs: [{ email: `${String.fromCharCode(97 + i)}@quorum.test` }],
        format: "object",
      })
    )
  );

  const fprs = keys.map((k) => k.publicKey.getFingerprint().toUpperCase());
  const audience = [...fprs].sort();
  const roomId = await deriveRoomId(audience, { relyingPartyId: ROOM_SCOPE });

  /** @type {Map<string, import("openpgp").Key>} */
  const keyByFpr = new Map(fprs.map((f, i) => [f, keys[i].publicKey]));
  /** @type {Map<string, import("openpgp").PrivateKey>} */
  const privateByFpr = new Map(fprs.map((f, i) => [f, keys[i].privateKey]));
  const armoredByFpr = new Map(fprs.map((f, i) => [f, keys[i].publicKey.armor()]));
  // Whoever sorted first. Named rather than indexed into `keys` at the call
  // site so the reason — any audience member can open any envelope — is stated
  // once, where it is relied on.
  const reader = /** @type {import("openpgp").PrivateKey} */ (
    privateByFpr.get(audience[0])
  );

  /** @type {{ seq: number, payload: string }[]} */
  const log = [];
  /** @type {SignalledFact[]} */
  const facts = [];
  /** @type {string[]} */
  const faults = [];
  const counts = { posts: 0, polls: 0, lookups: 0 };
  let seq = 0;

  /**
   * Open, optionally rewrite, re-seal under the signer's own key, append.
   *
   * Serialised by the caller (one POST at a time) so the order envelopes were
   * posted in is the order they appear on the mailbox — a signalling relay that
   * reordered an offer past its own candidates would be testing something
   * nobody ships.
   *
   * Returns the re-sealed wire, so a caller that is *relaying* rather than
   * storing can forward it. Signalling used to arrive here as a mailbox POST
   * and be read back by polling; it now goes over a WebSocket, so the browser
   * suite hands frames in through `intercept` and forwards what comes back.
   *
   * @param {string} armored
   * @returns {Promise<string>} the envelope to deliver, tampered or not
   */
  async function accept(armored) {
    /** @type {{ payload: any, signerFpr: string }} */
    let opened;
    try {
      opened = await openSignalingEnvelope({
        armored,
        decryptionKey: reader,
        audienceKeyByFpr: keyByFpr,
        audienceFprs: audience,
        expectedRoomId: roomId,
      });
    } catch (err) {
      // Not a delivery decision: an envelope this room cannot read means the
      // fixture is broken, and saying so beats letting the peers fail to mesh.
      faults.push(
        `mailbox could not open a posted envelope: ${err instanceof Error ? err.message : String(err)}`
      );
      // Unreadable here is not a delivery decision: forward it untouched
      // rather than losing the frame, and let the peers fail on their own
      // terms with the fault already recorded.
      return armored;
    }
    const signer = opened.signerFpr;
    const signingKey = privateByFpr.get(signer);
    if (!signingKey) {
      faults.push(`mailbox has no private key for signer ${signer.slice(0, 8)}`);
      return armored;
    }
    const before = String(opened.payload?.dtlsFingerprint || "");
    const payload = tamper ? tamper(opened.payload, signer) : opened.payload;
    const after = String(payload?.dtlsFingerprint || "");
    seq += 1;
    facts.push({
      seq,
      signer,
      type: String(payload?.type || ""),
      to: String(payload?.to || ""),
      // Recorded *before* the tamper: this is the claim the sender made about
      // its own transport, which is what the provenance check compares to the
      // SDP sitting beside it.
      dtlsFingerprint: before,
      sdp: String(payload?.sdp || ""),
      tampered: before !== after,
    });
    const wire = await sealSignalingEnvelope({
      payload,
      signingKey,
      audienceKeys: [...keyByFpr.values()],
    });
    log.push({ seq, payload: wire });
    return wire;
  }

  /** POSTs are chained so `seq` is assigned in arrival order. */
  let queue = Promise.resolve();

  /**
   * @param {import("node:http").IncomingMessage} req
   * @returns {Promise<string>}
   */
  function readBody(req) {
    return new Promise((resolve, reject) => {
      /** @type {Buffer[]} */
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      req.on("error", reject);
    });
  }

  /**
   * @param {import("node:http").ServerResponse} res
   * @param {number} status
   * @param {unknown} body
   */
  function json(res, status, body) {
    const text = JSON.stringify(body);
    res.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      "content-length": String(Buffer.byteLength(text)),
      "cache-control": "no-store",
    });
    res.end(text);
  }

  const MESSAGES = new RegExp(`^/api/v1/quorum/room/([^/]+)/messages$`);

  /**
   * @param {import("node:http").IncomingMessage} req
   * @param {import("node:http").ServerResponse} res
   * @returns {boolean} whether this room answered the request
   */
  function routes(req, res) {
    const raw = req.url || "/";
    const [path, query = ""] = raw.split("?");
    const params = new URLSearchParams(query);

    if (path === "/pks/lookup") {
      counts.lookups += 1;
      const search = String(params.get("search") || "");
      const fpr = search.replace(/^0x/i, "").toUpperCase();
      const armored = armoredByFpr.get(fpr);
      if (!armored) {
        // A key this room does not have is news, not a 404 to shrug at: the
        // audience is exactly the two identities the fixture minted.
        faults.push(`keyserver asked for an unknown key: ${search}`);
        res.writeHead(404, { "content-type": "text/plain" }).end("not found");
        return true;
      }
      res.writeHead(200, {
        "content-type": "application/pgp-keys; charset=utf-8",
        "content-length": String(Buffer.byteLength(armored)),
        "cache-control": "no-store",
      });
      res.end(armored);
      return true;
    }

    const m = MESSAGES.exec(path);
    if (!m) return false;
    if (decodeURIComponent(m[1]).toUpperCase() !== roomId) {
      faults.push(`mailbox asked for room ${m[1]}, this room is ${roomId}`);
      json(res, 404, { error: "unknown room" });
      return true;
    }

    if (String(req.method || "GET").toUpperCase() === "POST") {
      counts.posts += 1;
      queue = queue
        .then(async () => {
          const body = await readBody(req);
          /** @type {any} */
          let parsed;
          try {
            parsed = JSON.parse(body || "{}");
          } catch {
            faults.push("mailbox got a POST body that is not JSON");
            json(res, 400, { error: "bad body" });
            return;
          }
          await accept(String(parsed.payload || ""));
          json(res, 200, { seq, room_id: roomId });
        })
        .catch((err) => {
          faults.push(`mailbox POST failed: ${err?.message || err}`);
          try {
            json(res, 500, { error: "mailbox failure" });
          } catch {
            /* response already gone */
          }
        });
      return true;
    }

    counts.polls += 1;
    const since = Number(params.get("since") || 0) || 0;
    const messages = log.filter((x) => x.seq > since);
    json(res, 200, {
      room_id: roomId,
      messages,
      next_since: messages.length ? messages[messages.length - 1].seq : since,
    });
    return true;
  }

  return {
    roomId,
    audience,
    members: audience.map((fpr) => ({
      fpr,
      armoredPublic: /** @type {string} */ (armoredByFpr.get(fpr)),
      armoredPrivate: /** @type {import("openpgp").PrivateKey} */ (
        privateByFpr.get(fpr)
      ).armor(),
    })),
    routes,
    signalled: () => facts.slice(),
    intercept: accept,
    faults: () => faults.slice(),
    counts: () => ({ ...counts }),
  };
}
