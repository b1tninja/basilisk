/**
 * Vitest: packet-map parser + password encrypt/decrypt roundtrip.
 */
import { describe, expect, it } from "vitest";
import {
  createMessage,
  decrypt,
  decryptSessionKeys,
  encrypt,
  generateKey,
  readMessage,
} from "openpgp";
import {
  dearmorToBytes,
  enrichSpansWithPackets,
  mapPacketSpans,
  applySessionKeyDetails,
} from "../lib/packet-map.js";

describe("packet-map", () => {
  it("maps PKESK + SEIPD spans for a public-key encrypted message", async () => {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ email: "map@test.invalid" }],
      format: "object",
    });
    const armored = await encrypt({
      message: await createMessage({ text: "packet-map-canary" }),
      encryptionKeys: publicKey,
      format: "armored",
    });
    const binary = dearmorToBytes(String(armored));
    const spans = mapPacketSpans(binary);
    expect(spans.length).toBeGreaterThanOrEqual(2);
    expect(spans.some((s) => s.tag === 1)).toBe(true); // PKESK
    expect(spans.some((s) => s.tag === 18)).toBe(true); // SEIPD
    // Spans cover contiguous bytes from 0
    expect(spans[0].headerStart).toBe(0);
    for (let i = 1; i < spans.length; i++) {
      expect(spans[i].headerStart).toBe(spans[i - 1].end);
    }
    const msg = await readMessage({ armoredMessage: armored });
    const enriched = enrichSpansWithPackets(spans, msg.packets);
    const pkesk = enriched.find((s) => s.tag === 1);
    expect(pkesk?.detail?.lines?.some((l) => /X25519|ECDH|Session key wrapped/i.test(l))).toBe(
      true
    );

    const sessionKeys = await decryptSessionKeys({
      message: msg,
      decryptionKeys: privateKey,
    });
    const withSk = applySessionKeyDetails(enriched, sessionKeys);
    const seipd = withSk.find((s) => s.tag === 18);
    expect(seipd?.detail?.lines?.some((l) => /Session key:/i.test(l))).toBe(true);
  });

  it("maps SKESK for password-encrypted messages", async () => {
    const armored = await encrypt({
      message: await createMessage({ text: "pw-canary" }),
      passwords: ["test-passphrase-xyz"],
      format: "armored",
    });
    const binary = dearmorToBytes(String(armored));
    const spans = mapPacketSpans(binary);
    expect(spans.some((s) => s.tag === 3)).toBe(true);
    const msg = await readMessage({ armoredMessage: armored });
    const enriched = enrichSpansWithPackets(spans, msg.packets);
    const skesk = enriched.find((s) => s.tag === 3);
    expect(skesk?.detail?.lines?.some((l) => /passphrase/i.test(l))).toBe(true);
  });
});

describe("password encrypt/decrypt roundtrip", () => {
  it("decrypts a passphrase-only message", async () => {
    const pw = "roundtrip-secret-" + Math.random().toString(36).slice(2);
    const canary = "hello-basilisk-" + Math.random().toString(36).slice(2);
    const armored = await encrypt({
      message: await createMessage({ text: canary }),
      passwords: [pw],
      format: "armored",
    });
    const { data } = await decrypt({
      message: await readMessage({ armoredMessage: armored }),
      passwords: [pw],
    });
    expect(data).toBe(canary);
  });
});
