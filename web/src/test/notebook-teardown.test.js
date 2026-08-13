/**
 * What a session may still say after it has been stopped.
 *
 * Tearing a session down does not stop its transport mid-sentence. `stop()`
 * closes the peer links, but a connection that is closing still gathers an ICE
 * candidate or two, and `openPeerLink`'s `onIceCandidate` hands those straight
 * back as a bare `void this._sendTo(...)` — fire and forget, with nobody
 * holding the promise. The relay is null by then and the private key has been
 * zeroed in place, so those late sends used to throw into nothing: vitest
 * reported "Notebook signalling is not connected" and OpenPGP's "Invalid
 * keyData" as unhandled rejections attributed to whichever test was running,
 * with the warning that they "might cause false positive tests".
 *
 * The fix is not "make publishing quiet". It is that a *stopped* session has
 * nobody to report to, while a *running* one without signalling has somebody
 * who pressed something and is owed the reason — `rotateRoom` reaches
 * `_publish` through `_broadcast`, and `removeFromRoom` in `quorum-ops.js`
 * awaits it. Both halves are pinned here, because a fix for the first that took
 * the second with it would have looked exactly as green.
 */
import { afterEach, describe, expect, it } from "vitest";
import { makeQuorumPair } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;

afterEach(async () => {
  await pair?.stop();
  pair = null;
});

describe("a session that has been stopped", () => {
  it("drops the traffic its own teardown provoked, in silence", async () => {
    pair = await makeQuorumPair();
    await pair.start();
    await pair.settle();

    const { session } = pair.creator;
    session.stop();

    // Both doors the late traffic arrives at. `_publish` is where `_broadcast`
    // lands — a `_publishInvite` still sitting in the signal queue — and
    // `_sealAndSend` is where the ICE callback lands, one await earlier, before
    // the signature that would otherwise reach a wiped key.
    await expect(session._publish("late envelope")).resolves.toBeUndefined();
    await expect(
      session._sealAndSend(pair.joiner.fpr, { type: "ice", candidate: null }, {})
    ).resolves.toBeUndefined();
  });

  it("says nothing about it, because nobody asked", async () => {
    pair = await makeQuorumPair();
    await pair.start();
    await pair.settle();

    const { session } = pair.creator;
    const before = pair.creator.errors.length;
    session.stop();
    await session._publish("late envelope");

    // `onError` is the session's one channel to a person. A teardown race is
    // not an event in anybody's session, so it must not appear in it.
    expect(pair.creator.errors.length).toBe(before);
  });
});

describe("a session that is running without signalling", () => {
  it("still refuses by name, which is the sentence rotateRoom shows", async () => {
    // Never started, so `_relay` is null exactly as it is after `stop()` — the
    // one thing separating this case from the one above is that this session is
    // still alive and somebody is waiting on the answer.
    pair = await makeQuorumPair();
    const { session } = pair.creator;
    expect(session._stopped).toBe(false);

    await expect(session._publish("an envelope")).rejects.toThrow(
      /Notebook signalling is not connected/
    );
  });
});
