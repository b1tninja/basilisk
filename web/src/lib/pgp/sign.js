/**
 * OpenPGP sign / verify helpers for toolkit gpg.sign / gpg.verify.
 */
import {
  createCleartextMessage,
  createMessage,
  readCleartextMessage,
  readMessage,
  readSignature,
  sign,
  verify,
} from "openpgp";

/**
 * @param {string|Uint8Array} data
 * @param {import("openpgp").PrivateKey[]} signingKeys
 * @param {"cleartext"|"detached"} format
 * @returns {Promise<{ armored: string, detached: boolean }>}
 */
export async function signOpenPgp(data, signingKeys, format = "cleartext") {
  if (!signingKeys?.length) {
    throw new Error("gpg.sign requires a vault OpenPGP private key");
  }
  const detached = format === "detached";
  if (typeof data === "string") {
    if (!detached) {
      const message = await createCleartextMessage({ text: data });
      const armored = await sign({ message, signingKeys, format: "armored" });
      return { armored: String(armored), detached: false };
    }
    const message = await createMessage({ text: data });
    const armored = await sign({
      message,
      signingKeys,
      format: "armored",
      detached: true,
    });
    return { armored: String(armored), detached: true };
  }
  if (!(data instanceof Uint8Array)) {
    throw new Error("gpg.sign expects text or bytes");
  }
  const message = await createMessage({ binary: data });
  const armored = await sign({
    message,
    signingKeys,
    format: "armored",
    detached: true,
  });
  return { armored: String(armored), detached: true };
}

/**
 * @param {string} dataText  cleartext signed message, or original message for detached
 * @param {import("openpgp").Key[]} verificationKeys
 * @param {string} [detachedArmored]
 * @returns {Promise<boolean>}
 */
export async function verifyOpenPgp(dataText, verificationKeys, detachedArmored = "") {
  if (!verificationKeys?.length) {
    throw new Error("gpg.verify requires OpenPGP public key(s)");
  }
  if (detachedArmored) {
    const message = await createMessage({ text: dataText });
    const signature = await readSignature({ armoredSignature: detachedArmored });
    const result = await verify({
      message,
      signature,
      verificationKeys,
    });
    return signaturesValid(result.signatures);
  }
  try {
    const clear = await readCleartextMessage({ cleartextMessage: dataText });
    const result = await verify({
      message: clear,
      verificationKeys,
    });
    return signaturesValid(result.signatures);
  } catch (_) {
    /* try armored message */
  }
  const message = await readMessage({ armoredMessage: dataText });
  const result = await verify({
    message,
    verificationKeys,
  });
  return signaturesValid(result.signatures);
}

/**
 * @param {Array<{ verified?: Promise<true> }>} signatures
 */
async function signaturesValid(signatures) {
  if (!signatures?.length) return false;
  for (const s of signatures) {
    try {
      await s.verified;
      return true;
    } catch (_) {
      /* continue */
    }
  }
  return false;
}
