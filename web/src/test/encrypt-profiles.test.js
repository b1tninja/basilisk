/**
 * Vitest: encrypt profile → SEIPD version / AEAD / S2K assertions + roundtrips.
 *
 * Note: OpenPGP.js only emits SEIPD v2 for public-key encryption when every
 * recipient key advertises the seipdv2 feature (keys generated with
 * aeadProtect). Passphrase-only encryption uses config.aeadProtect directly.
 */

import { describe, expect, it } from "vitest";
import {
  config,
  decrypt,
  generateKey,
  readMessage,
} from "openpgp";
import {
  dearmorToBytes,
  enrichSpansWithPackets,
  mapPacketSpans,
} from "../lib/packet-map.js";
import {
  PROFILE_AUTO,
  PROFILE_COMPATIBLE,
  PROFILE_MODERN,
  encryptArtifacts,
  profileToConfig,
  summarizeEncryption,
} from "../lib/pgp/encrypt.js";
import { AEAD, SYMMETRIC, algoName, s2kTypeName } from "../lib/pgp/algos.js";
import { keyIdHex, isAnonymousKeyId } from "../lib/pgp/identity.js";

/** Keys that advertise SEIPDv2 so Modern AEAD can apply to PKESK encrypt. */
async function modernRecipientPair() {
  const prev = config.aeadProtect;
  config.aeadProtect = true;
  try {
    return await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: "Profile Test", email: "profile@example.com" }],
      format: "object",
    });
  } finally {
    config.aeadProtect = prev;
  }
}

async function legacyRecipientPair() {
  const prev = config.aeadProtect;
  config.aeadProtect = false;
  try {
    return await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: "Legacy Test", email: "legacy@example.com" }],
      format: "object",
    });
  } finally {
    config.aeadProtect = prev;
  }
}

/**
 * @param {string} armored
 */
async function enrichedSpans(armored) {
  const binary = dearmorToBytes(armored);
  const spans = mapPacketSpans(binary);
  const message = await readMessage({ armoredMessage: armored });
  return enrichSpansWithPackets(spans, message.packets);
}

/**
 * @param {Awaited<ReturnType<typeof enrichedSpans>>} enriched
 * @param {number} tag
 */
function findPacket(enriched, tag) {
  return enriched.find((s) => s.tag === tag)?.packet || null;
}

describe("encrypt-profiles", () => {
  it("profileToConfig maps Compatible and Modern correctly", () => {
    const compat = profileToConfig(PROFILE_COMPATIBLE);
    expect(compat.aeadProtect).toBe(false);
    expect(compat.preferredSymmetricAlgorithm).toBeDefined();
    expect(compat.s2kType).toBeDefined();

    const modern = profileToConfig(PROFILE_MODERN);
    expect(modern.aeadProtect).toBe(true);
    expect(modern.preferredAEADAlgorithm).toBeDefined();
  });

  it("Compatible profile → SEIPD v1 and decryptable roundtrip", async () => {
    const { privateKey, publicKey } = await legacyRecipientPair();
    const [artifact] = await encryptArtifacts({
      recipients: [publicKey],
      passwords: [],
      payloads: [{ kind: "text", text: "compatible hello" }],
      profile: PROFILE_COMPATIBLE,
    });
    expect(artifact.armored).toContain("BEGIN PGP MESSAGE");

    const enriched = await enrichedSpans(artifact.armored);
    const seipd = findPacket(enriched, 18);
    expect(seipd).toBeTruthy();
    expect(seipd.version ?? 1).toBe(1);

    const message = await readMessage({ armoredMessage: artifact.armored });
    const { data } = await decrypt({
      message,
      decryptionKeys: privateKey,
      format: "utf8",
    });
    expect(data).toBe("compatible hello");
  });

  it("Modern profile → SEIPD v2 with AES-256-OCB (SEIPDv2-capable recipient)", async () => {
    const { privateKey, publicKey } = await modernRecipientPair();
    const [artifact] = await encryptArtifacts({
      recipients: [publicKey],
      passwords: [],
      payloads: [{ kind: "text", text: "modern hello" }],
      profile: PROFILE_MODERN,
    });

    const enriched = await enrichedSpans(artifact.armored);
    const seipd = findPacket(enriched, 18);
    expect(seipd).toBeTruthy();
    expect(seipd.version).toBeGreaterThanOrEqual(2);
    expect(algoName(SYMMETRIC, seipd.cipherAlgorithm)).toBe("AES-256");
    expect(algoName(AEAD, seipd.aeadAlgorithm)).toBe("OCB");

    const summary = await summarizeEncryption(artifact.armored);
    expect(summary).toMatch(/AES-256-OCB/i);

    const message = await readMessage({ armoredMessage: artifact.armored });
    const { data } = await decrypt({
      message,
      decryptionKeys: privateKey,
      format: "utf8",
    });
    expect(data).toBe("modern hello");
  });

  it("Argon2 vs iterated S2K visible on SKESK packet", async () => {
    const plaintext = "passphrase-only";

    const [iterated] = await encryptArtifacts({
      recipients: [],
      passwords: ["secret-iter"],
      payloads: [{ kind: "text", text: plaintext }],
      profile: { ...PROFILE_COMPATIBLE, s2k: "iterated" },
    });
    const iterSkesk = findPacket(await enrichedSpans(iterated.armored), 3);
    expect(iterSkesk).toBeTruthy();
    expect(s2kTypeName(iterSkesk.s2k)).toBe("iterated");

    const [argon] = await encryptArtifacts({
      recipients: [],
      passwords: ["secret-argon"],
      payloads: [{ kind: "text", text: plaintext }],
      profile: { ...PROFILE_MODERN, s2k: "argon2" },
    });
    const argonSkesk = findPacket(await enrichedSpans(argon.armored), 3);
    expect(argonSkesk).toBeTruthy();
    expect(s2kTypeName(argonSkesk.s2k)).toBe("argon2");

    const argonSeipd = findPacket(await enrichedSpans(argon.armored), 18);
    expect(argonSeipd?.version).toBeGreaterThanOrEqual(2);

    for (const [armored, pw] of [
      [iterated.armored, "secret-iter"],
      [argon.armored, "secret-argon"],
    ]) {
      const message = await readMessage({ armoredMessage: armored });
      const { data } = await decrypt({
        message,
        passwords: [pw],
        format: "utf8",
      });
      expect(data).toBe(plaintext);
    }
  });

  it("AEAD mode GCM is reflected in SEIPD v2 metadata", async () => {
    const { publicKey } = await modernRecipientPair();
    const [artifact] = await encryptArtifacts({
      recipients: [publicKey],
      passwords: [],
      payloads: [{ kind: "text", text: "gcm" }],
      profile: {
        cipher: "aes256",
        aead: "gcm",
        compression: "uncompressed",
        s2k: "iterated",
      },
    });
    const seipd = findPacket(await enrichedSpans(artifact.armored), 18);
    expect(seipd.version).toBeGreaterThanOrEqual(2);
    expect(algoName(AEAD, seipd.aeadAlgorithm)).toBe("GCM");
  });

  it("file payload encrypts and decrypts with Modern profile", async () => {
    const { privateKey, publicKey } = await modernRecipientPair();
    const bytes = new TextEncoder().encode("file-bytes");
    const [artifact] = await encryptArtifacts({
      recipients: [publicKey],
      passwords: [],
      payloads: [{ kind: "file", bytes, filename: "note.txt" }],
      profile: PROFILE_MODERN,
    });
    expect(artifact.filename).toBe("note.txt.asc");
    expect(artifact.label).toBe("note.txt");

    const message = await readMessage({ armoredMessage: artifact.armored });
    const { data } = await decrypt({
      message,
      decryptionKeys: privateKey,
      format: "binary",
    });
    expect(new TextDecoder().decode(data)).toBe("file-bytes");
  });

  it("Auto profile degrades to SEIPD v1 for legacy recipients", async () => {
    const { privateKey, publicKey } = await legacyRecipientPair();
    const [artifact] = await encryptArtifacts({
      recipients: [publicKey],
      passwords: [],
      payloads: [{ kind: "text", text: "auto-legacy" }],
      profile: PROFILE_AUTO,
    });
    const seipd = findPacket(await enrichedSpans(artifact.armored), 18);
    expect(seipd.version ?? 1).toBe(1);

    const message = await readMessage({ armoredMessage: artifact.armored });
    const { data } = await decrypt({
      message,
      decryptionKeys: privateKey,
      format: "utf8",
    });
    expect(data).toBe("auto-legacy");
  });

  it("hideRecipients writes anonymous (wildcard) PKESK key IDs", async () => {
    const { privateKey, publicKey } = await modernRecipientPair();
    const [artifact] = await encryptArtifacts({
      recipients: [publicKey],
      passwords: [],
      payloads: [{ kind: "text", text: "anon" }],
      profile: PROFILE_COMPATIBLE,
      hideRecipients: true,
    });
    const pkesk = findPacket(await enrichedSpans(artifact.armored), 1);
    expect(pkesk).toBeTruthy();
    const kid = keyIdHex(pkesk.publicKeyID);
    expect(isAnonymousKeyId(kid)).toBe(true);

    const message = await readMessage({ armoredMessage: artifact.armored });
    const { data } = await decrypt({
      message,
      decryptionKeys: privateKey,
      format: "utf8",
    });
    expect(data).toBe("anon");
  });
});
