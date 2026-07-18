/**
 * Regression: OpenPGP.js Message objects are stateful. Calling
 * decryptSessionKeys then decrypt on the same instance throws
 * "Cannot destructure property 'V' of 'e' as it is null" (minified
 * sessionKeyParams). Fresh readMessage() per call is required.
 */
import {
  createMessage,
  decrypt,
  decryptSessionKeys,
  encrypt,
  generateKey,
  readKey,
  readMessage,
  readPrivateKey,
} from "openpgp";
import { describe, expect, it } from "vitest";

async function makeEncryptedPair(text) {
  const { privateKey: armoredPrivate, publicKey: armoredPublic } =
    await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Reuse", email: "reuse@example.com" }],
      format: "armored",
    });
  const privateKey = await readPrivateKey({ armoredKey: armoredPrivate });
  const publicKey = await readKey({ armoredKey: armoredPublic });
  const armoredMessage = await encrypt({
    message: await createMessage({ text }),
    encryptionKeys: publicKey,
    format: "armored",
  });
  return { privateKey, armoredMessage: String(armoredMessage) };
}

describe("decrypt after decryptSessionKeys", () => {
  it("fails when the same message object is reused", async () => {
    const { privateKey, armoredMessage } = await makeEncryptedPair(
      "hello stateful message"
    );

    const message = await readMessage({ armoredMessage });
    await decryptSessionKeys({ message, decryptionKeys: privateKey });

    await expect(
      decrypt({
        message,
        decryptionKeys: privateKey,
        config: { allowInsecureDecryptionWithSigningKeys: true },
      })
    ).rejects.toThrow(/destructure|null|session/i);
  }, 30_000);

  it("succeeds when each call uses a fresh readMessage", async () => {
    const { privateKey, armoredMessage } = await makeEncryptedPair(
      "hello fresh reads"
    );

    const sessionKeys = await decryptSessionKeys({
      message: await readMessage({ armoredMessage }),
      decryptionKeys: privateKey,
    });
    expect(sessionKeys.length).toBeGreaterThan(0);

    const result = await decrypt({
      message: await readMessage({ armoredMessage }),
      decryptionKeys: privateKey,
      config: { allowInsecureDecryptionWithSigningKeys: true },
    });
    expect(result.data).toBe("hello fresh reads");
  }, 30_000);
});
