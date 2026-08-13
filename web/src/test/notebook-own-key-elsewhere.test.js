/**
 * Two tabs of one browser, both signing as the same key.
 *
 * Reported as a run stuck at `Paused at cell [1] — waiting for peer…` with no
 * further word. Two tabs share one IndexedDB vault, so they can share one
 * *identity* by accident — pick the same key in each and both sessions have the
 * same fingerprint. The audience still names two people, and the second one is
 * nobody.
 *
 * A session is never its own peer, and it must not become one: the roster is
 * the audience minus yourself, and a room where you meshed with yourself would
 * key-confirm a transcript against your own key and call it a witness. So the
 * *drop* here is right, and this file pins it. What was wrong is that the drop
 * said nothing — the joiner opened the creator's invite, verified the
 * signature, saw its own fingerprint on it and returned, and both ends then sat
 * on "waiting for peer" until a two-minute timeout blamed the other side for
 * not running a step it was running.
 *
 * The proof is airtight rather than heuristic, which is why it is an *invite*
 * that carries it: a joiner never publishes one, and a creator's own invite
 * always carries the nonce it minted. An invite signed by this key with any
 * other nonce cannot have come from this session, and only this key's holder
 * could have signed it.
 */
import { afterEach, describe, expect, it } from "vitest";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;

afterEach(async () => {
  await pair?.stop();
  pair = null;
});

describe("a second session signing as this session's key", () => {
  it("is named, on the side that can prove it", async () => {
    pair = await makeQuorumPair({ sameKey: true });
    await pair.start();
    await until(() => pair.joiner.ownKeyElsewhere > 0);

    // The joiner is the side an invite reaches. It publishes nothing of its
    // own until it has verified one, so the creator has nothing to hear back —
    // that end is left to the wait's own timeout, which now names this cause
    // among the others it lists.
    expect(pair.joiner.ownKeyElsewhere).toBeGreaterThan(0);
    expect(pair.creator.ownKeyElsewhere).toBe(0);
    expect(pair.joiner.session.ownKeyElsewhere).toBe(true);
  });

  it("is said once, however many envelopes carry it", async () => {
    // The creator broadcasts an invite and then addresses a `hello` to every
    // peer; both are signed by the same key and both reach the joiner. A
    // session that announced this per envelope would turn one fact into a
    // stream of them.
    pair = await makeQuorumPair({ sameKey: true });
    await pair.start();
    await until(() => pair.joiner.ownKeyElsewhere > 0);
    await pair.settle();
    expect(pair.joiner.ownKeyElsewhere).toBe(1);
  });

  it("changes nothing about who is a peer", async () => {
    pair = await makeQuorumPair({ sameKey: true });
    await pair.start();
    await until(() => pair.joiner.ownKeyElsewhere > 0);
    await pair.settle();

    for (const side of [pair.creator, pair.joiner]) {
      // Self is not in the roster, and the audience's other fingerprint — the
      // one nobody is running as — is there and unconfirmed. That is the room
      // as it truly is.
      expect(side.session.peers.has(side.fpr)).toBe(false);
      expect([...side.session.peers.keys()]).toEqual(
        pair.audience.filter((f) => f !== side.fpr)
      );
      for (const peer of side.session.peers.values()) {
        expect(peer.kcVerified).toBe(false);
      }
    }
    // The invite was still refused as an introduction: telling the user what
    // happened must not also make this session believe it met somebody.
    expect(pair.joiner.session.inviteVerified).toBe(false);
  });

  it("stays quiet through an ordinary session between two keys", async () => {
    // The rule has to be unable to fire on the case it shares a code path
    // with: a creator's own invite echoed back by the relay is signed by the
    // creator's key too.
    pair = await makeQuorumPair();
    await pair.start();
    await until(
      () =>
        [...pair.creator.session.peers.values()].some((p) => p.kcVerified) &&
        [...pair.joiner.session.peers.values()].some((p) => p.kcVerified)
    );
    await pair.settle();
    expect(pair.creator.ownKeyElsewhere).toBe(0);
    expect(pair.joiner.ownKeyElsewhere).toBe(0);
    expect(pair.creator.session.ownKeyElsewhere).toBe(false);
  });
});
