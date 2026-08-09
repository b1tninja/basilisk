import { describe, expect, it } from "vitest";
import {
  bytesToBase32,
  canonicalAudience,
  deriveChannelId,
  deriveRoomId,
  deriveRoomMaterial,
  isValidRoomId,
  isValidRoomKey,
  quorumRelyingPartyId,
} from "../lib/quorum/room.js";

const ALICE =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BOB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const CAROL =
  "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

const SCOPE = "keys.example.org";

describe("canonicalAudience", () => {
  it("dedupes, uppercases, sorts", () => {
    expect(
      canonicalAudience([
        `0x${BOB.toLowerCase()}`,
        ALICE,
        `${BOB.slice(0, 4)} ${BOB.slice(4)}`,
        "not-a-fpr",
      ])
    ).toEqual([ALICE, BOB]);
  });
});

describe("quorumRelyingPartyId", () => {
  it("normalizes an explicit override", () => {
    expect(quorumRelyingPartyId(" Keys.Example.ORG ")).toBe("keys.example.org");
  });

  it("falls back to localhost when location is unavailable", () => {
    expect(quorumRelyingPartyId()).toBe("localhost");
  });
});

describe("deriveRoomId", () => {
  it("is stable for the same audience and scope regardless of order", async () => {
    const a = await deriveRoomId([ALICE, BOB], { relyingPartyId: SCOPE });
    const b = await deriveRoomId([BOB, ALICE], { relyingPartyId: SCOPE });
    expect(a).toBe(b);
    expect(a).toMatch(/^[A-Z2-7]{16}$/);
    expect(isValidRoomId(a)).toBe(true);
  });

  it("changes when audience changes", async () => {
    const ab = await deriveRoomId([ALICE, BOB], { relyingPartyId: SCOPE });
    const ac = await deriveRoomId([ALICE, CAROL], { relyingPartyId: SCOPE });
    expect(ab).not.toBe(ac);
  });

  it("changes when relying-party / domain changes", async () => {
    const a = await deriveRoomId([ALICE, BOB], {
      relyingPartyId: "keys.example.org",
    });
    const b = await deriveRoomId([ALICE, BOB], {
      relyingPartyId: "other.example.org",
    });
    expect(a).not.toBe(b);
  });

  it("rejects fewer than two fingerprints", async () => {
    await expect(
      deriveRoomId([ALICE], { relyingPartyId: SCOPE })
    ).rejects.toThrow(/at least two/i);
  });

  it("matches known vector", async () => {
    const id = await deriveRoomId([ALICE, BOB], { relyingPartyId: SCOPE });
    const material = `${SCOPE}|${ALICE}|${BOB}`;
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(material)
    );
    const expected = bytesToBase32(new Uint8Array(digest)).slice(0, 16);
    expect(id).toBe(expected);
  });
});

describe("deriveChannelId", () => {
  it("derives distinct labels from the same room", async () => {
    const room = await deriveRoomId([ALICE, BOB], { relyingPartyId: SCOPE });
    const chat = await deriveChannelId(room, "chat", { relyingPartyId: SCOPE });
    const file = await deriveChannelId(room, "file", { relyingPartyId: SCOPE });
    expect(chat).toMatch(/^[A-Z2-7]{16}$/);
    expect(chat).not.toBe(file);
  });

  it("scopes channel ids by relying party", async () => {
    const room = await deriveRoomId([ALICE, BOB], { relyingPartyId: SCOPE });
    const a = await deriveChannelId(room, "chat", {
      relyingPartyId: "keys.example.org",
    });
    const b = await deriveChannelId(room, "chat", {
      relyingPartyId: "other.example.org",
    });
    expect(a).not.toBe(b);
  });
});

describe("room material", () => {
  it("hands out the id as a prefix of the key, and nothing else", async () => {
    const { roomId, roomKey, epoch } = await deriveRoomMaterial([ALICE, BOB], {
      relyingPartyId: SCOPE,
    });
    expect(roomKey).toMatch(/^[A-Z2-7]{52}$/);
    expect(roomId).toBe(roomKey.slice(0, 16));
    expect(epoch).toBe(0);
    expect(isValidRoomKey(roomKey)).toBe(true);
    // The id is a truncation, which is what makes it cheap to say aloud and
    // useless as a way back to the key: 80 bits out of 256.
    expect(isValidRoomKey(roomId)).toBe(false);
  });

  it("leaves epoch 0 exactly where every existing room already is", async () => {
    // Rotation must be additive. If epoch 0 mixed anything, every room id in
    // circulation would move the day this shipped.
    const material = await deriveRoomMaterial([ALICE, BOB], { relyingPartyId: SCOPE });
    expect(material.roomId).toBe(await deriveRoomId([ALICE, BOB], { relyingPartyId: SCOPE }));
  });

  it("lands somewhere unrelated on every epoch", async () => {
    const seen = new Set();
    for (const epoch of [0, 1, 2, 3]) {
      const { roomId, roomKey } = await deriveRoomMaterial([ALICE, BOB], {
        relyingPartyId: SCOPE,
        epoch,
      });
      seen.add(roomId);
      seen.add(roomKey);
    }
    expect(seen.size).toBe(8);
  });

  it("needs the rotation secret, not just the epoch and the audience", async () => {
    // The property that makes rotation an eviction rather than a rename. A
    // removed member knows the audience it left behind and can count epochs;
    // what it does not have is the secret sealed to the members who stayed.
    const guessable = await deriveRoomMaterial([ALICE, BOB], {
      relyingPartyId: SCOPE,
      epoch: 1,
    });
    const actual = await deriveRoomMaterial([ALICE, BOB], {
      relyingPartyId: SCOPE,
      epoch: 1,
      secret: "8f2b1c",
    });
    const wrongSecret = await deriveRoomMaterial([ALICE, BOB], {
      relyingPartyId: SCOPE,
      epoch: 1,
      secret: "8f2b1d",
    });
    expect(actual.roomKey).not.toBe(guessable.roomKey);
    expect(actual.roomKey).not.toBe(wrongSecret.roomKey);
  });

  it("moves the room when the audience shrinks, secret or not", async () => {
    const three = await deriveRoomMaterial([ALICE, BOB, CAROL], { relyingPartyId: SCOPE });
    const two = await deriveRoomMaterial([ALICE, BOB], { relyingPartyId: SCOPE });
    expect(three.roomKey).not.toBe(two.roomKey);
  });
});
