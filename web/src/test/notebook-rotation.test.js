/**
 * Rotating the room, with two live sessions on both ends of it.
 *
 * The gap this closes: a peer that obtained one token was present for as long
 * as it cared to hold the socket. Token expiry is checked when a connection is
 * made and never again, there is no membership to enumerate and no connection
 * this application can name, so there is nothing to *evict*. What there is, is
 * a group name — and a name can be changed.
 *
 * Nothing is stubbed but the three things outside the process (see
 * `helpers/notebook-pair.js`): real keys, real sealed envelopes, real ECDH, real
 * key confirmation. So "the room moved" here means the sessions re-derived
 * their material, re-negotiated, re-joined a different group, and re-confirmed
 * keys over a transcript bound to the new room — not that a field changed.
 */
import { afterEach, describe, expect, it } from "vitest";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";
import { deriveRoomMaterial } from "../lib/notebook/room.js";

/** @type {Awaited<ReturnType<typeof makeQuorumPair>>|null} */
let pair = null;

afterEach(async () => {
  await pair?.stop();
  pair = null;
});

/** @param {any} side @param {string} fpr */
const peerOf = (side, fpr) => side.session.peers.get(fpr);

/** Both ends key-confirmed with each other. */
async function meshed(p, budget = 8000) {
  return until(
    () =>
      peerOf(p.creator, p.joiner.fpr)?.kcVerified === true &&
      peerOf(p.joiner, p.creator.fpr)?.kcVerified === true,
    budget
  );
}

describe("rotating the room", () => {
  it("moves both members to a new group and re-confirms keys there", async () => {
    pair = await makeQuorumPair();
    const p = /** @type {any} */ (pair);
    await p.start();
    expect(await meshed(p)).toBe(true);

    const before = {
      room: p.creator.session.roomId,
      epoch: p.creator.session.epoch,
      creatorTranscript: peerOf(p.creator, p.joiner.fpr).transcriptHash,
      joinerTranscript: peerOf(p.joiner, p.creator.fpr).transcriptHash,
    };
    expect(before.epoch).toBe(0);
    expect(p.joiner.session.roomId).toBe(before.room);

    // The creator published the invite, so the creator is the one this room
    // takes rotations from.
    const result = await p.creator.session.rotateRoom();
    expect(result.epoch).toBe(1);
    expect(result.roomId).not.toBe(before.room);

    // The joiner is told over the link it already has, and follows.
    expect(
      await until(() => p.joiner.session.roomId === result.roomId, 8000),
      `joiner errors: ${p.joiner.errors.map((e) => e.message)}`
    ).toBe(true);
    expect(p.joiner.session.epoch).toBe(1);

    // Key confirmation re-ran rather than being carried over: the room id is
    // inside the transcript, so a session key that survived the move would be
    // a key bound to a room that no longer exists.
    expect(await meshed(p)).toBe(true);
    expect(peerOf(p.creator, p.joiner.fpr).transcriptHash).not.toBe(
      before.creatorTranscript
    );
    expect(peerOf(p.joiner, p.creator.fpr).transcriptHash).not.toBe(
      before.joinerTranscript
    );
    // Both ends agree on what the new transcript is, which is the whole
    // content of a key confirmation.
    expect(peerOf(p.creator, p.joiner.fpr).transcriptHash).toBe(
      peerOf(p.joiner, p.creator.fpr).transcriptHash
    );

    // And the room works after the move.
    await p.creator.session.sendChat("still here");
    expect(await until(() => p.joiner.chats.some((c) => c.text === "still here"))).toBe(
      true
    );
  });

  it("lands somewhere the audience alone cannot compute", async () => {
    // The point of the secret. Epoch plus audience is derivable by anyone who
    // was ever in the room — including whoever was just removed from it — so
    // if that were the whole recipe, "rotation" would mean "everybody move one
    // seat to the left, loudly".
    pair = await makeQuorumPair();
    const p = /** @type {any} */ (pair);
    await p.start();
    expect(await meshed(p)).toBe(true);

    const guessable = await deriveRoomMaterial(p.audience, { epoch: 1 });
    const { roomId } = await p.creator.session.rotateRoom();
    expect(roomId).not.toBe(guessable.roomId);
  });

  it("is not something any member can order", async () => {
    // The joiner is not the initiator. Its announcement is a perfectly valid
    // signed, sealed envelope from an audience member — which is exactly why
    // the signature cannot be the whole check. A member on the way out would
    // otherwise answer its own removal by moving the room itself.
    pair = await makeQuorumPair();
    const p = /** @type {any} */ (pair);
    await p.start();
    expect(await meshed(p)).toBe(true);
    const creatorRoom = p.creator.session.roomId;

    await p.joiner.session.rotateRoom();
    await p.settle();

    expect(p.joiner.session.epoch).toBe(1);
    // The creator ignored it and stayed put.
    expect(p.creator.session.epoch).toBe(0);
    expect(p.creator.session.roomId).toBe(creatorRoom);
  });

  it("refuses to rotate into a room that no longer has two members", async () => {
    pair = await makeQuorumPair();
    const p = /** @type {any} */ (pair);
    await p.start();
    await expect(
      p.creator.session.rotateRoom({ remove: [p.joiner.fpr] })
    ).rejects.toThrow(/at least two/);
    await expect(
      p.creator.session.rotateRoom({ remove: [p.creator.fpr] })
    ).rejects.toThrow(/no longer includes this key/);
    // A refused rotation leaves the room exactly where it was.
    expect(p.creator.session.epoch).toBe(0);
  });

  it("checks the remove list before it tears anything down", async () => {
    // The order matters more than the refusal. Removing peers first and
    // discovering afterwards that the remainder cannot derive a room would
    // leave this session with its links closed and nowhere to re-open them —
    // a worse outcome than the removal it refused to perform. A hostile
    // initiator reaches this path directly, with any remove list it likes.
    pair = await makeQuorumPair();
    const p = /** @type {any} */ (pair);
    await p.start();
    expect(await meshed(p)).toBe(true);
    const link = peerOf(p.creator, p.joiner.fpr).link;

    await expect(
      p.creator.session._applyRotation(1, new Set([p.joiner.fpr]), "a-secret")
    ).rejects.toThrow(/at least two/);

    expect(p.creator.session.peers.has(p.joiner.fpr)).toBe(true);
    expect(p.creator.session.audienceKeys.has(p.joiner.fpr)).toBe(true);
    expect(p.creator.session.epoch).toBe(0);
    expect(link.isTornDown()).toBe(false);
    // Still a working room, not a half-rotated one.
    await p.creator.session.sendChat("unharmed");
    expect(await until(() => p.joiner.chats.some((c) => c.text === "unharmed"))).toBe(
      true
    );
  });

  it("drops the removed member's transport, its key and its place", async () => {
    // Three in the room, so there is somewhere to rotate to. The removed
    // member's link is closed, its key is dropped, and its fingerprint is out
    // of the audience — which is what makes the next room's material
    // something it was never able to compute.
    pair = await makeQuorumPair();
    const p = /** @type {any} */ (pair);
    await p.start();
    expect(await meshed(p)).toBe(true);

    // A third audience member that never showed up: a peer record with no
    // transport, which is exactly the shape of someone being removed before
    // they connect.
    const ghost = "D4".repeat(20);
    p.creator.session.audienceFprs = [...p.creator.session.audienceFprs, ghost].sort();
    p.creator.session.peers.set(ghost, { fingerprint: ghost, status: "unknown" });

    const link = peerOf(p.creator, p.joiner.fpr).link;
    await p.creator.session._applyRotation(1, new Set([p.joiner.fpr]), "a-secret");

    expect(p.creator.session.peers.has(p.joiner.fpr)).toBe(false);
    expect(p.creator.session.audienceFprs).not.toContain(p.joiner.fpr);
    expect(p.creator.session.audienceKeys.has(p.joiner.fpr)).toBe(false);
    expect(link.isTornDown()).toBe(true);
    expect(p.creator.session.epoch).toBe(1);
  });
});
