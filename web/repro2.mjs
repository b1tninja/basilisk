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

// A: decrypt alone on a fresh message
{
  const message = await readMessage({ armoredMessage: armored });
  const r = await decrypt({ message, decryptionKeys: pk });
  console.log("A decrypt-only:", JSON.stringify(r.data));
}

// B: decryptSessionKeys then decrypt with sessionKeys (no decryptionKeys)
{
  const message = await readMessage({ armoredMessage: armored });
  const sks = await decryptSessionKeys({ message, decryptionKeys: pk });
  console.log("B sessionKeys:", sks.length, sks[0].algorithm);
  const r = await decrypt({ message, sessionKeys: sks });
  console.log("B decrypt with sessionKeys:", JSON.stringify(r.data));
}

// C: inspect PKESK.encrypted after decryptSessionKeys
{
  const message = await readMessage({ armoredMessage: armored });
  const before = message.packets.filterByTag(1)[0].encrypted;
  await decryptSessionKeys({ message, decryptionKeys: pk });
  const after = message.packets.filterByTag(1)[0].encrypted;
  console.log("C encrypted before:", before === null ? "null" : typeof before,
              "after:", after === null ? "null" : typeof after);
}
