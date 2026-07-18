import { describe, expect, it } from "vitest";
import {
  bytesToBase32,
  canonicalAudience,
  deriveChannelId,
  deriveRoomId,
  isValidRoomId,
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
