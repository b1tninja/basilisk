import {
  createMessage,
  decrypt,
  decryptSessionKeys,
  encrypt,
  readMessage,
} from "openpgp";

const armored = await encrypt({
  message: await createMessage({ text: "hello" }),
  passwords: ["secret"],
  format: "armored",
});

// SKESK: decryptSessionKeys then decrypt on the same message object
const message = await readMessage({ armoredMessage: armored });
const sks = await decryptSessionKeys({ message, passwords: ["secret"] });
console.log("sessionKeys:", sks.length);
try {
  const r = await decrypt({ message, passwords: ["secret"] });
  console.log("SKESK same-object decrypt OK:", JSON.stringify(r.data));
} catch (e) {
  console.log("SKESK same-object decrypt FAIL:", e.message);
}
