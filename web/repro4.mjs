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

const { privateKey: privArmored, publicKey: pubArmored } = await generateKey({
  type: "ecc",
  curve: "curve25519",
  userIDs: [{ name: "T", email: "t@example.com" }],
  format: "armored",
});
const pub = await readKey({ armoredKey: pubArmored });
const pk = await readPrivateKey({ armoredKey: privArmored });

const armored = await encrypt({
  message: await createMessage({ text: "hello" }),
  encryptionKeys: [pub],
  format: "armored",
});

// Fixed sequence: decryptSessionKeys, then decrypt with sessionKeys
const message = await readMessage({ armoredMessage: armored });
let sessionKeys = [];
try {
  sessionKeys = await decryptSessionKeys({ message, decryptionKeys: pk });
} catch (_) {
  sessionKeys = [];
}
const result = await decrypt({
  message,
  ...(sessionKeys.length ? { sessionKeys } : { decryptionKeys: pk }),
  config: { allowInsecureDecryptionWithSigningKeys: true },
});
console.log("fixed sequence OK:", JSON.stringify(result.data), "cipher:", sessionKeys[0]?.algorithm);

// Key ID matching: encryption subkey ID vs primary fingerprint
const recipientIds = message.getEncryptionKeyIDs().map((k) => k.toHex().toUpperCase());
const allKeyIds = pk.getKeys().map((k) => k.getKeyID().toHex().toUpperCase());
console.log("recipient IDs:", recipientIds);
console.log("private key IDs:", allKeyIds);
console.log("primary fpr:", pk.getFingerprint().toUpperCase());
console.log("match via keyIds:", recipientIds.some((id) => allKeyIds.includes(id)));
console.log("match via fpr suffix:", recipientIds.some((id) => pk.getFingerprint().toUpperCase().endsWith(id)));
