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
 * Verify a cleartext-signed document and hand back **the bytes that signature
 * covers**.
 *
 * `verifyOpenPgp` answers "is this signed by one of these keys" with a boolean,
 * which is the whole of what `gpg.verify` needs. A caller that then wants the
 * payload has to get the text from somewhere, and the tempting somewhere is a
 * second unwrapper — which is the defect `notebook/documents.js` states at
 * length: two answers to *which bytes were signed* agree until the first edge
 * case one of them learns about alone (dash-escaping, a stray `\r`, trailing
 * whitespace RFC 4880 excludes), "and then a signature vouches for bytes nobody
 * parsed". So verifying and reading are one act, here, and the text comes from
 * `getText()` — what OpenPGP hashed.
 *
 * Cleartext only. A detached signature is two objects and a binary message is
 * not a document a person reads; both are `verifyOpenPgp`'s to answer.
 *
 * Distinct from `documents.js`'s `verifySignedBy`, which asks a narrower
 * question: *is this signed by the peer whose pairwise key opened the frame*,
 * starting from a fingerprint. A recipe has no fingerprint claim to start from
 * — `key=$pub` is the claim — so the two take different inputs and say
 * different things when they fail. They share this one rule and no code, and
 * the rule is the paragraph above.
 *
 * @param {string} cleartext  armored cleartext-signed document
 * @param {import("openpgp").Key[]} verificationKeys
 * @param {string} [what]  noun for error messages
 * @returns {Promise<string>} the signed text
 */
export async function verifiedCleartextOpenPgp(cleartext, verificationKeys, what = "document") {
  if (!verificationKeys?.length) {
    throw new Error(`${what}: no OpenPGP public key to check the signature against`);
  }
  /** @type {import("openpgp").CleartextMessage} */
  let clear;
  try {
    clear = await readCleartextMessage({ cleartextMessage: String(cleartext ?? "") });
  } catch (err) {
    throw new Error(
      `${what}: not an OpenPGP cleartext-signed document ` +
        `(${err instanceof Error ? err.message : String(err)}). An unsigned one ` +
        "cannot be checked, and this step exists to check it."
    );
  }
  const { signatures } = await verify({ message: clear, verificationKeys });
  if (!signatures?.length) {
    throw new Error(`${what}: carries no signature`);
  }
  for (const sig of signatures) {
    try {
      await sig.verified;
    } catch (_) {
      // Wrong key, revoked key, expired binding, mangled body — every one of
      // them is "not signed by a key you gave me", and none is worth telling
      // apart in a message to somebody holding an untrusted file.
      continue;
    }
    // `getText()`, not the armor: the bytes OpenPGP hashed.
    return clear.getText();
  }
  throw new Error(
    `${what}: signature does not verify against that key. It may be a perfectly ` +
      "good signature by somebody else — a signature that verifies against some " +
      "key is not one that verifies against this one."
  );
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
