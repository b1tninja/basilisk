import {
  createMessage,
  decrypt,
  decryptSessionKeys,
  encrypt,
  enums,
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

const profiles = {
  compatible: {
    preferredSymmetricAlgorithm: enums.symmetric.aes256,
    preferredCompressionAlgorithm: enums.compression.uncompressed,
    s2kType: enums.s2k.iterated,
    aeadProtect: false,
  },
  modern: {
    preferredSymmetricAlgorithm: enums.symmetric.aes256,
    preferredCompressionAlgorithm: enums.compression.uncompressed,
    s2kType: enums.s2k.argon2,
    aeadProtect: true,
    preferredAEADAlgorithm: enums.aead.ocb,
  },
};

for (const [name, config] of Object.entries(profiles)) {
  for (const wildcard of [false, true]) {
    const label = `${name} wildcard=${wildcard}`;
    try {
      const msg = await createMessage({ text: "hello world" });
      const armored = await encrypt({
        message: msg,
        encryptionKeys: [pub],
        format: "armored",
        config,
        wildcard,
      });
      // Worker decrypt sequence:
      const pk = await readPrivateKey({ armoredKey: privArmored });
      const message = await readMessage({ armoredMessage: armored });
      let sks = [];
      try {
        sks = await decryptSessionKeys({ message, decryptionKeys: pk });
      } catch (e) {
        console.log(label, "— decryptSessionKeys error:", e.message);
      }
      const result = await decrypt({
        message,
        decryptionKeys: pk,
        config: { allowInsecureDecryptionWithSigningKeys: true },
      });
      console.log(label, "— OK:", JSON.stringify(result.data), "sks:", sks.length);
    } catch (e) {
      console.log(label, "— FAIL:", e.message);
      if (e.stack) console.log(e.stack.split("\n").slice(0, 5).join("\n"));
    }
  }
}
