import { describe, expect, it } from "vitest";
import { generateKey } from "openpgp";
import {
  assertInvite,
  buildInvitePayload,
  decryptSessionPayload,
  derivePairwiseSessionKey,
  encryptSessionPayload,
  exportEcdhPublicJwk,
  extractDtlsFingerprint,
  generateEcdhKeyPair,
  importEcdhPublicJwk,
  openSignalingEnvelope,
  randomNonceHex,
  requireSelfInAudience,
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

describe("requireSelfInAudience", () => {
  const a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const b = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

  it("merges self into audience", () => {
    expect(requireSelfInAudience(a, [b])).toEqual([a, b].sort());
  });

  it("rejects when audience would be only self", () => {
    expect(() => requireSelfInAudience(a, [a])).toThrow(/at least two/i);
  });

  it("rejects invalid local fingerprint", () => {
    expect(() => requireSelfInAudience("nope", [a, b])).toThrow(/Invalid local/);
  });
});

describe("pairwise ECDH session keys v2", () => {
  async function derivePair(alice, bob, extras = {}) {
    const roomId = "ABCD2345EFGH6789";
    const aFpr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const bFpr = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const audience = [aFpr, bFpr];
    const aJwk = await exportEcdhPublicJwk(alice.publicKey);
    const bJwk = await exportEcdhPublicJwk(bob.publicKey);
    const base = {
      roomId,
      audienceFprs: audience,
      inviteNonce: "aa".repeat(16),
      myHelloNonce: "11".repeat(16),
      peerHelloNonce: "22".repeat(16),
      dtlsFingerprint: "sha-256 AA:BB",
      ...extras,
    };
    const aliceView = await derivePairwiseSessionKey({
      privateKey: alice.privateKey,
      peerPublicKey: bob.publicKey,
      myFpr: aFpr,
      peerFpr: bFpr,
      myEcdhJwk: aJwk,
      peerEcdhJwk: bJwk,
      ...base,
    });
    const bobView = await derivePairwiseSessionKey({
      privateKey: bob.privateKey,
      peerPublicKey: alice.publicKey,
      myFpr: bFpr,
      peerFpr: aFpr,
      myEcdhJwk: bJwk,
      peerEcdhJwk: aJwk,
      myHelloNonce: base.peerHelloNonce,
      peerHelloNonce: base.myHelloNonce,
      roomId: base.roomId,
      audienceFprs: audience,
      inviteNonce: base.inviteNonce,
      dtlsFingerprint: base.dtlsFingerprint,
    });
    return { aliceView, bobView, aJwk, bJwk, aFpr, bFpr, roomId, audience };
  }

  it("derives equal AES keys and transcript hashes in both directions", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();
    const { aliceView, bobView } = await derivePair(alice, bob);

    expect(aliceView.transcriptHash).toBe(bobView.transcriptHash);
    const ct = await encryptSessionPayload(aliceView.aesKey, "hello quorum");
    const pt = await decryptSessionPayload(bobView.aesKey, ct);
    expect(pt).toBe("hello quorum");
  });

  it("changes key when invite nonce differs", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();
    const a = await derivePair(alice, bob, { inviteNonce: "aa".repeat(16) });
    const b = await derivePair(alice, bob, { inviteNonce: "bb".repeat(16) });
    expect(a.aliceView.transcriptHash).not.toBe(b.aliceView.transcriptHash);
  });

  it("changes key when DTLS fingerprint differs", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();
    const a = await derivePair(alice, bob, { dtlsFingerprint: "sha-256 AA" });
    const b = await derivePair(alice, bob, { dtlsFingerprint: "sha-256 BB" });
    expect(a.aliceView.transcriptHash).not.toBe(b.aliceView.transcriptHash);
  });

  it("round-trips JWK export/import", async () => {
    const kp = await generateEcdhKeyPair();
    const jwk = await exportEcdhPublicJwk(kp.publicKey);
    const imported = await importEcdhPublicJwk(jwk);
    expect(imported.type).toBe("public");
  });
});

describe("signed invites", () => {
  async function audiencePair() {
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
    const roomId = await deriveRoomId([aFpr, bFpr], {
      relyingPartyId: "localhost",
    });
    const ecdh = await generateEcdhKeyPair();
    const ecdhPublicJwk = await exportEcdhPublicJwk(ecdh.publicKey);
    return { alice, bob, aFpr, bFpr, roomId, ecdhPublicJwk };
  }

  it("build + assertInvite accepts a valid creator invite", async () => {
    const { alice, aFpr, bFpr, roomId, ecdhPublicJwk } = await audiencePair();
    const payload = buildInvitePayload({
      roomId,
      audience: [aFpr, bFpr],
      initiator: aFpr,
      ecdhPublicJwk,
      nonce: randomNonceHex(32),
    });
    const result = await assertInvite(payload, {
      signerFpr: aFpr,
      expectedRoomId: roomId,
      expectedAudience: [aFpr, bFpr],
    });
    expect(result.initiator).toBe(aFpr);
    expect(result.inviteNonce).toBe(payload.nonce);
  });

  it("rejects invite when initiator not in audience", async () => {
    const { aFpr, bFpr, roomId, ecdhPublicJwk } = await audiencePair();
    const outsider = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const payload = buildInvitePayload({
      roomId,
      audience: [aFpr, bFpr],
      initiator: aFpr,
      ecdhPublicJwk,
    });
    payload.initiator = outsider;
    payload.from = outsider;
    await expect(
      assertInvite(payload, {
        signerFpr: outsider,
        expectedRoomId: roomId,
        expectedAudience: [aFpr, bFpr],
      })
    ).rejects.toThrow(/initiator/i);
  });

  it("rejects invite when audience does not match pin", async () => {
    const { aFpr, bFpr, roomId, ecdhPublicJwk } = await audiencePair();
    const c = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const payload = buildInvitePayload({
      roomId,
      audience: [aFpr, bFpr],
      initiator: aFpr,
      ecdhPublicJwk,
    });
    await expect(
      assertInvite(payload, {
        signerFpr: aFpr,
        expectedRoomId: roomId,
        expectedAudience: [aFpr, c],
      })
    ).rejects.toThrow(/audience/i);
  });

  it("rejects invite when room id does not match derivation", async () => {
    const { aFpr, bFpr, ecdhPublicJwk } = await audiencePair();
    const payload = buildInvitePayload({
      roomId: "AAAAAAAAAAAAAA22",
      audience: [aFpr, bFpr],
      initiator: aFpr,
      ecdhPublicJwk,
    });
    await expect(
      assertInvite(payload, {
        signerFpr: aFpr,
        expectedRoomId: "AAAAAAAAAAAAAA22",
        expectedAudience: [aFpr, bFpr],
      })
    ).rejects.toThrow(/derivation/i);
  });

  it("sign+encrypt invite and decrypt+verify for audience members", async () => {
    const { alice, bob, aFpr, bFpr, roomId, ecdhPublicJwk } =
      await audiencePair();
    /** @type {Map<string, import("openpgp").Key>} */
    const audience = new Map([
      [aFpr, alice.publicKey],
      [bFpr, bob.publicKey],
    ]);
    const payload = buildInvitePayload({
      roomId,
      audience: [aFpr, bFpr],
      initiator: aFpr,
      ecdhPublicJwk,
    });
    const armored = await sealSignalingEnvelope({
      payload,
      signingKey: alice.privateKey,
      audienceKeys: [alice.publicKey, bob.publicKey],
    });
    const opened = await openSignalingEnvelope({
      armored,
      decryptionKey: bob.privateKey,
      audienceKeyByFpr: audience,
      audienceFprs: [aFpr, bFpr],
      expectedRoomId: roomId,
    });
    expect(opened.signerFpr).toBe(aFpr);
    expect(opened.payload.type).toBe("invite");
    await assertInvite(opened.payload, {
      signerFpr: opened.signerFpr,
      expectedRoomId: roomId,
      expectedAudience: [aFpr, bFpr],
    });
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
