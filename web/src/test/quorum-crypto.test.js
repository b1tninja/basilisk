import { describe, expect, it } from "vitest";
import { generateKey } from "openpgp";
import {
  decryptSessionPayload,
  derivePairwiseSessionKey,
  encryptSessionPayload,
  exportEcdhPublicJwk,
  extractDtlsFingerprint,
  generateEcdhKeyPair,
  importEcdhPublicJwk,
  openSignalingEnvelope,
  sealSignalingEnvelope,
} from "../lib/quorum/crypto.js";
import { deriveRoomId } from "../lib/quorum/room.js";

describe("extractDtlsFingerprint", () => {
  it("parses a=fingerprint lines", () => {
    const sdp = [
      "v=0",
      "a=fingerprint:sha-256 AA:BB:CC:DD",
      "a=setup:actpass",
    ].join("\r\n");
    expect(extractDtlsFingerprint(sdp)).toBe("sha-256 AA:BB:CC:DD");
  });
});

describe("pairwise ECDH session keys", () => {
  it("derives equal AES keys in both directions", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();
    const roomId = "ABCD2345EFGH6789";
    const aFpr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const bFpr = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    const aliceView = await derivePairwiseSessionKey(
      alice.privateKey,
      bob.publicKey,
      roomId,
      aFpr,
      bFpr
    );
    const bobView = await derivePairwiseSessionKey(
      bob.privateKey,
      alice.publicKey,
      roomId,
      bFpr,
      aFpr
    );

    const ct = await encryptSessionPayload(aliceView, "hello quorum");
    const pt = await decryptSessionPayload(bobView, ct);
    expect(pt).toBe("hello quorum");
  });

  it("round-trips JWK export/import", async () => {
    const kp = await generateEcdhKeyPair();
    const jwk = await exportEcdhPublicJwk(kp.publicKey);
    const imported = await importEcdhPublicJwk(jwk);
    expect(imported.type).toBe("public");
  });
});

describe("signaling envelopes", () => {
  it("sign+encrypt and decrypt+verify for audience members", async () => {
    const alice = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "alice@quorum.test" }],
      format: "object",
    });
    const bob = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "bob@quorum.test" }],
      format: "object",
    });
    const aFpr = alice.publicKey.getFingerprint().toUpperCase();
    const bFpr = bob.publicKey.getFingerprint().toUpperCase();
    const roomId = await deriveRoomId([aFpr, bFpr]);

    /** @type {Map<string, import("openpgp").Key>} */
    const audience = new Map([
      [aFpr, alice.publicKey],
      [bFpr, bob.publicKey],
    ]);

    const armored = await sealSignalingEnvelope({
      payload: {
        v: 1,
        type: "hello",
        from: aFpr,
        to: null,
        roomId,
        ts: Date.now(),
        ecdhPublicJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
      },
      signingKey: alice.privateKey,
      audienceKeys: [alice.publicKey, bob.publicKey],
    });
    expect(armored).toContain("BEGIN PGP MESSAGE");

    const opened = await openSignalingEnvelope({
      armored,
      decryptionKey: bob.privateKey,
      audienceKeyByFpr: audience,
      audienceFprs: [aFpr, bFpr],
      expectedRoomId: roomId,
    });
    expect(opened.signerFpr).toBe(aFpr);
    expect(opened.payload.type).toBe("hello");
    expect(opened.payload.roomId).toBe(roomId);
  });

  it("rejects signer outside audience", async () => {
    const alice = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "alice2@quorum.test" }],
      format: "object",
    });
    const bob = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "bob2@quorum.test" }],
      format: "object",
    });
    const mallory = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "mallory@quorum.test" }],
      format: "object",
    });
    const aFpr = alice.publicKey.getFingerprint().toUpperCase();
    const bFpr = bob.publicKey.getFingerprint().toUpperCase();
    const mFpr = mallory.publicKey.getFingerprint().toUpperCase();
    const roomId = await deriveRoomId([aFpr, bFpr]);

    const armored = await sealSignalingEnvelope({
      payload: {
        v: 1,
        type: "hello",
        from: mFpr,
        roomId,
        ts: Date.now(),
      },
      signingKey: mallory.privateKey,
      audienceKeys: [alice.publicKey, bob.publicKey, mallory.publicKey],
    });

    await expect(
      openSignalingEnvelope({
        armored,
        decryptionKey: bob.privateKey,
        audienceKeyByFpr: new Map([
          [aFpr, alice.publicKey],
          [bFpr, bob.publicKey],
        ]),
        audienceFprs: [aFpr, bFpr],
        expectedRoomId: roomId,
      })
    ).rejects.toThrow();
  });
});
