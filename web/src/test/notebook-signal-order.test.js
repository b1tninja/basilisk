/**
 * Signalling envelopes reach the wire in the order they were made.
 *
 * This is one specific pair and one specific failure. `setLocalDescription`
 * hands back the answer and, in the same breath, schedules the ICE candidates
 * gathered from it — so `answer` is sent first and `ice` a moment behind it.
 * Reverse them and the far end runs `addIceCandidate` on a connection that has
 * no remote description yet, which is `InvalidStateError` in the fake transport
 * and in every browser. The offering end reports it, and
 * `notebook-session-documents.test.js` and `notebook-session-handoff.test.js`
 * both assert an empty `errors` array, so it lands there as a flake in a file
 * that has nothing to do with negotiation.
 *
 * Nothing used to hold the order. Sealing an envelope is a few milliseconds of
 * OpenPGP and `onIceCandidate` starts its send without awaiting the answer's,
 * so the two sealed concurrently and arrived in whichever order their crypto
 * finished. Over 60 handshakes under load the answer won by 0.5–3 ms every
 * time — the margin of two seals that cost about the same, which is a
 * coincidence and not a guarantee. It was observed lost twice, under a full
 * suite, where WebCrypto calls queue behind other processes' work.
 *
 * So the test does not wait for the coincidence to fail. It makes the answer's
 * seal slow, which is the only thing the race needs, and asserts the answer
 * still leaves first. Against a session without the per-peer send queue this
 * fails on the exact error the two suites saw.
 */
import { afterEach, describe, expect, it } from "vitest";
import { NotebookSession } from "../lib/notebook/session.js";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;
/** @type {(() => void)|null} */
let unpatch = null;

afterEach(() => {
  unpatch?.();
  unpatch = null;
  pair?.stop();
  pair = null;
});

/**
 * Make one payload type take `ms` longer to seal than everything around it.
 *
 * The delay sits in front of `_sealAndSend` rather than inside the crypto,
 * because it is standing in for a slow seal and the send queue wraps exactly
 * that call. Patching `_sendTo` instead would reach in front of the queue and
 * test nothing.
 *
 * @param {string} type
 * @param {number} ms
 */
function slowSeal(type, ms) {
  const real = NotebookSession.prototype._sealAndSend;
  NotebookSession.prototype._sealAndSend = async function (toFpr, fields, opts) {
    if (fields?.type === type) await new Promise((r) => setTimeout(r, ms));
    return real.call(this, toFpr, fields, opts);
  };
  unpatch = () => {
    NotebookSession.prototype._sealAndSend = real;
  };
}

describe("a description and the candidates gathered from it", () => {
  it("reach the wire in that order even when the description is slow to seal", async () => {
    // 40 ms is far more than the 0.5–3 ms the unguarded ordering ever had in
    // hand, so this is not a tighter version of the same coincidence.
    slowSeal("answer", 40);

    /** @type {string[]} */
    const wire = [];
    pair = await makeQuorumPair({
      // The relay transform runs on every published envelope, in the order the
      // relay will broadcast them — which is the order under test.
      tamper: (payload, signerFpr) => {
        wire.push(`${signerFpr}:${payload.type}`);
        return payload;
      },
    });
    await pair.start();
    const { creator, joiner } = pair;
    const ready = await until(
      () =>
        creator.session.peers.get(joiner.fpr)?.kcVerified === true &&
        joiner.session.peers.get(creator.fpr)?.kcVerified === true
    );
    await pair.settle();

    // The answering end is whichever one the fingerprint comparison made
    // polite; the test does not care which, only that it kept its own order.
    const answerer = wire.find((e) => e.endsWith(":answer"))?.split(":")[0];
    expect(answerer, `no answer on the wire: ${wire.join(" ")}`).toBeTruthy();
    const mine = wire.filter((e) => e.startsWith(`${answerer}:`)).map((e) => e.split(":")[1]);
    expect(mine.indexOf("answer")).toBeGreaterThan(-1);
    expect(mine.indexOf("ice"), `order was ${mine.join(",")}`).toBeGreaterThan(
      mine.indexOf("answer")
    );

    // And the consequence, which is what the two suites were actually asserting.
    const errors = [...creator.errors, ...joiner.errors].map((e) => e.message);
    expect(errors).toEqual([]);
    expect(ready, `errors: ${errors.join(" | ")}`).toBe(true);
  });

  it("still orders the offering end's own candidates behind its offer", async () => {
    // Same rule, the other side of the handshake. It has never been seen to
    // fail — a candidate that beats its offer finds no peer connection at the
    // far end and is dropped silently rather than reported — but it is the same
    // send and the same queue, and a silent drop is worse to debug than a throw.
    slowSeal("offer", 40);

    /** @type {string[]} */
    const wire = [];
    pair = await makeQuorumPair({
      tamper: (payload, signerFpr) => {
        wire.push(`${signerFpr}:${payload.type}`);
        return payload;
      },
    });
    await pair.start();
    const { creator, joiner } = pair;
    await until(
      () =>
        creator.session.peers.get(joiner.fpr)?.kcVerified === true &&
        joiner.session.peers.get(creator.fpr)?.kcVerified === true
    );
    await pair.settle();

    const offerer = wire.find((e) => e.endsWith(":offer"))?.split(":")[0];
    expect(offerer, `no offer on the wire: ${wire.join(" ")}`).toBeTruthy();
    const mine = wire.filter((e) => e.startsWith(`${offerer}:`)).map((e) => e.split(":")[1]);
    expect(mine.indexOf("ice"), `order was ${mine.join(",")}`).toBeGreaterThan(
      mine.indexOf("offer")
    );
    expect([...creator.errors, ...joiner.errors].map((e) => e.message)).toEqual([]);
  });
});
