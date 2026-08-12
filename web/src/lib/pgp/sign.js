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
import {
  SIGNATURE_FUTURE_TOLERANCE_MS,
  describeGap,
  signatureVerificationDate,
} from "./clock.js";

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
      date: signatureVerificationDate(),
    });
    return signaturesValid(result.signatures);
  }
  try {
    const clear = await readCleartextMessage({ cleartextMessage: dataText });
    const result = await verify({
      message: clear,
      verificationKeys,
      date: signatureVerificationDate(),
    });
    return signaturesValid(result.signatures);
  } catch (_) {
    /* try armored message */
  }
  const message = await readMessage({ armoredMessage: dataText });
  const result = await verify({
    message,
    verificationKeys,
    date: signatureVerificationDate(),
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
  const { signatures } = await verify({
    message: clear,
    verificationKeys,
    // Ordinary clock skew, not an anomaly. See `clock.js`, and `refusalFor`
    // for what is said when the tolerance is exceeded.
    date: signatureVerificationDate(),
  });
  if (!signatures?.length) {
    throw new Error(`${what}: carries no signature`);
  }
  /** @type {string[]} */
  const refusals = [];
  for (const sig of signatures) {
    try {
      await sig.verified;
    } catch (err) {
      refusals.push(await refusalFor(sig, err, { clear, verificationKeys, what }));
      continue;
    }
    // `getText()`, not the armor: the bytes OpenPGP hashed.
    return clear.getText();
  }
  throw new Error(refusals[0] || `${what}: signature does not verify against that key.`);
}

/**
 * Say which check refused this signature — the one that happened.
 *
 * This used to be one sentence for every refusal: *"signature does not verify
 * against that key. It may be a perfectly good signature by somebody else."* It
 * is the right sentence for exactly one of the cases below and an accusation in
 * the rest. A colleague whose clock ran one second fast was told their document
 * was probably signed by an impostor — a conclusion the code had not reached and
 * could not have, because the check that failed was a date comparison.
 *
 * The verifier knows which one it was, so it says so:
 *
 * - **A key that is not among the ones given.** The original sentence, used
 *   where it is true. The key ID is named, because the reader's next move is
 *   finding out whose it is.
 * - **The right key over the wrong bytes.** Not impostorship — the document was
 *   edited after signing, or it is not the document this signature covers.
 * - **A creation time past the tolerance.** Saying "the signature is good, the
 *   date is not" is a claim about the signature, so it is *checked* rather than
 *   inferred: the message is re-verified at the signature's own instant, and
 *   only a pass there earns the sentence. In practice openpgp reports a bad
 *   digest ahead of a bad date, so a tampered document lands in the branch
 *   below and never reaches this one — but that ordering is an implementation
 *   detail of a library, and a security claim resting on it would be resting on
 *   nothing written down.
 * - **Anything else** — a revoked key, an expired binding — in openpgp's own
 *   words rather than translated into a guess.
 *
 * @param {{ keyID: import("openpgp").KeyID, signature: Promise<import("openpgp").Signature> }} sig
 * @param {unknown} err  why `verified` rejected
 * @param {{ clear: import("openpgp").CleartextMessage, verificationKeys: import("openpgp").Key[], what: string }} ctx
 * @returns {Promise<string>}
 */
async function refusalFor(sig, err, { clear, verificationKeys, what }) {
  const reason = err instanceof Error ? err.message : String(err);
  const keyId = String(sig.keyID?.toHex?.() || "").toUpperCase();

  // Structural, not a string match on openpgp's wording: is the signer among
  // the keys we were told to check against at all?
  const known = verificationKeys.some((key) =>
    (key.getKeyIDs?.() || []).some((id) => id.equals?.(sig.keyID))
  );
  if (!known) {
    return (
      `${what}: signed by key ${keyId || "(unknown)"}, which is not one of the keys ` +
      "you gave me. It may be a perfectly good signature by somebody else — a " +
      "signature that verifies against some key is not one that verifies against " +
      "this one."
    );
  }

  if (/creation time is in the future/i.test(reason)) {
    const created = await createdAt(sig);
    const ahead = created ? describeGap(created.getTime() - Date.now()) : "some time";
    // Re-run at the signature's own instant. If it verifies there, the only
    // thing wrong is the clock, and saying "does not verify" would be false.
    let otherwiseGood = false;
    if (created) {
      try {
        const { signatures } = await verify({
          message: clear,
          verificationKeys,
          date: created,
        });
        for (const s of signatures) {
          try {
            await s.verified;
            otherwiseGood = true;
          } catch (_) {
            /* still bad at its own instant */
          }
        }
      } catch (_) {
        /* leave it false — the re-check is evidence, not a second verdict */
      }
    }
    const stamp = created ? created.toISOString() : "an unreadable time";
    return otherwiseGood
      ? `${what}: the signature is good, but it is stamped ${stamp} — ${ahead} ahead ` +
          `of this device's clock, past the ${Math.round(SIGNATURE_FUTURE_TOLERANCE_MS / 1000)}s ` +
          "allowed for ordinary skew. One of the two clocks is wrong, or the document " +
          "was dated deliberately; nothing here can tell you which."
      : `${what}: the signature does not verify, and it is also stamped ${stamp} — ` +
          `${ahead} ahead of this device's clock.`;
  }

  if (/digest|hash|integrity/i.test(reason)) {
    return (
      `${what}: this is not the document that signature covers. The signature is by ` +
      `key ${keyId}, which you did give me — the bytes underneath it are not the ones ` +
      "it was made over, so it has been edited since, or paired with the wrong document."
    );
  }

  return `${what}: the signature by key ${keyId} could not be checked — ${reason}.`;
}

/**
 * When the signature claims it was made. Best effort: the packet is readable
 * even when verification refused it, which is what lets the clock case say
 * something specific.
 * @param {{ signature: Promise<import("openpgp").Signature> }} sig
 * @returns {Promise<Date|null>}
 */
async function createdAt(sig) {
  try {
    const created = (await sig.signature)?.packets?.[0]?.created;
    return created instanceof Date ? created : null;
  } catch (_) {
    return null;
  }
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
