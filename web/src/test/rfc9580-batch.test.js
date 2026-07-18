/**
 * Vitest: next Improvement Plan batch helpers (intent already covered elsewhere).
 */

import { describe, expect, it } from "vitest";
import {
  createCleartextMessage,
  createMessage,
  decrypt,
  encrypt,
  generateKey,
  readMessage,
  sign,
} from "openpgp";
import {
  checkIntendedRecipient,
  intendedRecipientsFromSigPacket,
} from "../lib/pgp/intended-recipient.js";
import { notationsFromSignature } from "../lib/pgp/notations.js";
import {
  PROFILE_MODERN,
  encryptArtifacts,
  summarizeEncryption,
} from "../lib/pgp/encrypt.js";
import {
  dearmorToBytes,
  describePacket,
  enrichSpansWithPackets,
  mapPacketSpans,
} from "../lib/packet-map.js";
import { compareFingerprints, normalizeFingerprintInput } from "../lib/pgp/verify-fpr.js";
import { richOpenpgpQrPayload } from "../lib/qr.js";

describe("sign+encrypt", () => {
  it("encryptArtifacts with signingKeys produces decryptable signed ciphertext", async () => {
    const alice = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "alice@example.com" }],
      format: "object",
    });
    const bob = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "bob@example.com" }],
      format: "object",
    });
    const [artifact] = await encryptArtifacts({
      recipients: [bob.publicKey],
      passwords: [],
      payloads: [{ kind: "text", text: "signed hello" }],
      profile: PROFILE_MODERN,
      signingKeys: [alice.privateKey],
    });
    expect(artifact.armored).toContain("BEGIN PGP MESSAGE");
    const dec = await decrypt({
      message: await readMessage({ armoredMessage: artifact.armored }),
      decryptionKeys: bob.privateKey,
      verificationKeys: [alice.publicKey],
    });
    expect(dec.data).toBe("signed hello");
    expect(dec.signatures?.length).toBeGreaterThan(0);
    await dec.signatures[0].verified;
  });
});

describe("packet salt / notations", () => {
  it("describePacket reports v4 salt absence or OpenPGP.js salt notation", async () => {
    const k = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "sig@example.com" }],
      format: "object",
    });
    const clear = await sign({
      message: await createCleartextMessage({ text: "hi" }),
      signingKeys: k.privateKey,
    });
    // Use encrypt+sign for a message with signature packets in binary map path
    const enc = await encrypt({
      message: await createMessage({ text: "hi" }),
      encryptionKeys: k.publicKey,
      signingKeys: k.privateKey,
      format: "armored",
    });
    const binary = dearmorToBytes(enc);
    const spans = mapPacketSpans(binary);
    const message = await readMessage({ armoredMessage: enc });
    const enriched = enrichSpansWithPackets(spans, message.packets);
    const sigSpan = enriched.find((s) => s.tag === 2);
    if (sigSpan?.packet) {
      const detail = describePacket(sigSpan);
      const joined = (detail.lines || []).join(" ");
      expect(joined.toLowerCase()).toMatch(/salt|v4 signature/);
    }
    const selfSig = await k.publicKey.getPrimarySelfSignature();
    const notations = notationsFromSignature(selfSig);
    expect(Array.isArray(notations)).toBe(true);
  });
});

describe("intended recipient check", () => {
  it("flags mismatch and absence", () => {
    const fpr = "AABBCCDDEEFF00112233445566778899AABBCCDD";
    expect(checkIntendedRecipient([], fpr).status).toBe("absent");
    expect(checkIntendedRecipient([fpr], fpr).status).toBe("ok");
    expect(
      checkIntendedRecipient(["00112233445566778899AABBCCDDEEFF00112233"], fpr)
        .status
    ).toBe("mismatch");
  });

  it("reads type-35 unknown subpackets", () => {
    const body = new Uint8Array(21);
    body[0] = 4;
    for (let i = 0; i < 20; i++) body[i + 1] = i;
    const pkt = {
      unknownSubpackets: [{ type: 35, body }],
    };
    const list = intendedRecipientsFromSigPacket(pkt);
    expect(list.length).toBe(1);
    expect(list[0]).toHaveLength(40);
  });
});

describe("verify fpr + rich QR", () => {
  it("accepts 40 and 64 hex fingerprints", () => {
    const v4 = "a".repeat(40);
    const v6 = "b".repeat(64);
    expect(normalizeFingerprintInput(`openpgp4fpr:${v4}`)).toBe(v4.toUpperCase());
    expect(normalizeFingerprintInput(v6)).toBe(v6.toUpperCase());
    expect(compareFingerprints(v4, v4).ok).toBe(true);
    expect(compareFingerprints(v6, v6).ok).toBe(true);
  });

  it("builds rich QR payload with UID + URI", () => {
    const fpr = "AABBCCDDEEFF00112233445566778899AABBCCDD";
    const payload = richOpenpgpQrPayload(fpr, {
      name: "Ada",
      email: "ada@example.com",
    });
    expect(payload).toContain("Ada <ada@example.com>");
    expect(payload).toContain(`openpgp4fpr:${fpr}`);
  });
});

describe("summarizeEncryption still works after signed encrypt", () => {
  it("returns a non-empty summary string", async () => {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "sum@example.com" }],
      format: "object",
    });
    const [artifact] = await encryptArtifacts({
      recipients: [publicKey],
      passwords: [],
      payloads: [{ kind: "text", text: "x" }],
      profile: PROFILE_MODERN,
      signingKeys: [privateKey],
    });
    const summary = await summarizeEncryption(artifact.armored);
    expect(summary.length).toBeGreaterThan(0);
  });
});
