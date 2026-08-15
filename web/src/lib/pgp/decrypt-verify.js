/**
 * The signature verdict a decrypt carries out with its plaintext.
 *
 * ## Why this is not inlined in the two ops that decrypt
 *
 * `gpg.decrypt` and `agent.decrypt` open the same messages with different keys
 * from different places — one from the session vault, one from behind a
 * per-use approval — and neither difference reaches the signature. What a
 * reader is owed about *who wrote this* is one question, so it gets one
 * answer; two spellings of it is how the two ops come to disagree about what
 * "verified" means, which is the failure `intended-recipient.js` describes at
 * length for the case where neither op said anything at all.
 *
 * ## The order is the whole point, and it is `openSignalingEnvelope`'s
 *
 * Name the signer first, then verify. Verifying first means a message from a
 * key the verification set does not hold never reaches the set check: OpenPGP
 * cannot verify a signature it has no key for, so it rejects with *"Could not
 * find signing key with key ID <16 hex>"* and that string is what a reader
 * gets — a key id they cannot look up, in place of the sentence that says
 * which set was consulted and why this signer is not in it. Naming the signer
 * first costs nothing in strength: the key id is an unauthenticated packet
 * header, used here only to choose which sentence to raise, and `verified` is
 * still awaited before any verdict says a signature held.
 *
 * ## Three states a verdict may report, and two it may not
 *
 * A verdict is only ever `verified`, `unverified` or `unsigned`, and the
 * sentence is built here rather than in the widget for the reason the JOSE
 * body rides on `meta`: whether a signature was *checked* is something only
 * the op that ran knows, and anything re-deriving it from the ciphertext could
 * only ever report unverified. **Unverified never looks verified** — there is
 * no state in which `signer` is set and `state` is not `verified`, so a tile
 * cannot print a fingerprint that nothing stands behind.
 *
 * ## What refuses, and the line it is drawn on
 *
 * **An explicit written claim that is violated is a refusal; an ambient default
 * that does not match is a report.** That one sentence decides every case here,
 * and it is why two situations that look alike are treated differently:
 *
 * - **`signers=` names a key and somebody else signed** — a refusal. The author
 *   wrote a claim into the recipe text and the message contradicts it. The text
 *   is the agreement, so the run stops and says which claim failed.
 * - **The room does not name the signer** — a *report*. The room is not a claim
 *   anybody wrote; it is ambient context that happens to be live, and it is not
 *   the universe of legitimate signers, only whoever is in this ceremony. A
 *   friend's signed letter pasted in during a custody ceremony is an ordinary
 *   thing and not a security event.
 *
 * Refusing there would have been wrong three ways, and each is worth keeping
 * written down because the mistake is easy to make again:
 *
 * 1. It inverts this ladder. Tier 3 — *no session at all* — reports unverified,
 *    so refusing at tier 2 means the same message decrypts clean with no session
 *    and throws with one. Opening a session would break a decrypt that worked a
 *    minute earlier.
 * 2. It breaks *the text is the agreement* (`docs/LANGUAGE.md`). The recipe is
 *    character-for-character identical in both cases; only ambient state
 *    differs, so a reader cannot see from what they wrote why it failed.
 * 3. The room-is-the-list observation is true and is still said — as narration
 *    in the sentence, explaining why the room could not confirm this signer. It
 *    just does not gate the run.
 *
 * **A bad signature still throws at every tier.** That is a failed cryptographic
 * check rather than a question about set membership: the bytes do not say what
 * the signature says they say, and no amount of ambient context makes that
 * ordinary. Only outside-the-set-at-tier-2 is a report.
 *
 * The one refusal is escapable with `-q` (`soft=true`), symmetric with
 * `gpg.verify -q`. What it cannot do is what that flag does there: a decrypt's
 * output type is fixed by `count=` before the run, so `-q` cannot collapse the
 * tip to a bool the way it does on `gpg.verify`. What it changes is whether the
 * failure stops the run or is written down on the value — and written down, it
 * is still `unverified`, in a sentence naming which failure happened.
 *
 * ## Naming a signer we cannot vouch for
 *
 * A report about a signer outside the set still names them by **whole
 * fingerprint**, read from the signature's own Issuer Fingerprint subpacket.
 * That value is an unauthenticated packet header — it is what the message
 * *claims* — so it goes into the **sentence only** and never into `signer`.
 * The structured field a widget colours on stays empty unless the signature was
 * actually checked, which is what keeps "unverified never looks verified" true
 * while still telling a reader which key to go and look up.
 *
 * @module lib/pgp/decrypt-verify
 */

import { formatFingerprint } from "../utils.js";
import { signatureVerificationDate } from "./clock.js";
import { normalizeFingerprintInput } from "./verify-fpr.js";
import {
  checkIntendedRecipient,
  intendedRecipientsFromDecryptSignatures,
} from "./intended-recipient.js";

/**
 * Where a verification set came from, in the words the verdict prints.
 *
 * `room` and `signers` are the two tiers that produce a set at all; the empty
 * string is the third, where there is nothing to verify against and the
 * verdict says so rather than guessing one up.
 * @typedef {""|"room"|"signers"} VerificationSource
 */

/**
 * @typedef {object} DecryptVerdict
 * @property {"verified"|"unverified"|"unsigned"} state
 * @property {string} signer  whole uppercase fingerprint, and **only** ever set
 *   when `state` is `verified` — see the module header
 * @property {VerificationSource} against
 * @property {"ok"|"mismatch"|"absent"} intended  RFC 9580 §13.12, which changes
 *   what the verdict says and never whether the plaintext is returned
 * @property {string} sentence  what a reader sees, whole fingerprints
 */

/** How the sentence names each tier's set. */
const AGAINST_PHRASE = Object.freeze({
  room: "in this room",
  signers: "named by signers=",
});

/**
 * The refusal for a signer `signers=` does not name — tier 1 only.
 *
 * Names the claimed fingerprint when the message carries one, because that is
 * what makes the remedy performable: the reader can copy it straight into
 * `signers=` if it is a key they meant to accept. This is where the rule
 * `openSignalingEnvelope` follows — never print a bare key id, which is the one
 * fact in hand and the one nobody can act on — stops applying: a whole
 * fingerprint *is* actionable, and the sentence says it is a claim.
 *
 * @param {string} claimed  whole fingerprint the signature claims, or ""
 * @param {string} what
 */
function outsideSignersMessage(claimed, what) {
  return (
    `${what}: this message is signed by a key \`signers=\` does not name` +
    (claimed
      ? ` — the signature claims ${formatFingerprint(claimed)}, which nothing ` +
        "here has checked. Write that fingerprint if it is the signer you mean"
      : ". Write the fingerprint that actually signed it") +
    ", or `-q` to read the plaintext with the signature left unverified."
  );
}

/**
 * What a signature says about who made it, before anybody has checked.
 *
 * The Issuer Fingerprint subpacket (RFC 9580 §5.2.3.35), which openpgp.js
 * writes on every v4 signature it produces and which survives a decrypt that
 * had no verification key to try. Unauthenticated by construction — it is a
 * header field, and a forger can put anything in it — so every caller here puts
 * it in a *sentence* and none puts it in `signer`.
 *
 * @param {*} sig  one entry of openpgp's `decrypt()` result signatures
 * @returns {Promise<string>} whole uppercase fingerprint, or ""
 */
async function claimedSigner(sig) {
  try {
    const sigObj = await sig?.signature;
    for (const pkt of sigObj?.packets || []) {
      const raw = pkt?.issuerFingerprint;
      if (raw instanceof Uint8Array && raw.length >= 20) {
        return normalizeFingerprintInput(
          [...raw].map((b) => b.toString(16).padStart(2, "0")).join("")
        );
      }
    }
  } catch (_) {
    /* a signature that will not parse claims nothing, which is not an error */
  }
  return "";
}

/**
 * Build the verdict for one decrypted message.
 *
 * @param {object} args
 * @param {Array<*>} args.signatures  openpgp's `decrypt()` result signatures
 * @param {Map<string, import("openpgp").Key>} args.keyByFpr  the verification
 *   set, keyed by whole fingerprint. Empty is tier 3 and is not a failure.
 * @param {VerificationSource} args.against
 * @param {string} args.decryptFpr  the key that opened it, for §13.12
 * @param {boolean} args.soft
 * @param {string} args.what  the step, so its refusals name it and not a neighbour
 * @returns {Promise<DecryptVerdict>}
 */
export async function decryptSignatureVerdict({
  signatures,
  keyByFpr,
  against,
  decryptFpr,
  soft,
  what,
}) {
  const sigs = Array.isArray(signatures) ? signatures : [];
  if (!sigs.length) {
    // No claim was made, so none is reported. This is most messages, and
    // dressing it as a failure would teach people to ignore the state that
    // matters — `intended-recipient.js` settled the same question for the
    // §13.12 subpacket's absence, in the same words.
    return {
      state: "unsigned",
      signer: "",
      against,
      intended: "absent",
      sentence: "unsigned",
    };
  }

  if (!keyByFpr.size) {
    // Tier 3. There is a signature and nothing to check it with, and the
    // honest report of that is neither "verified" nor a refusal: the message
    // decrypted, which is what was asked for, and who wrote it is unanswered.
    return {
      state: "unverified",
      signer: "",
      against: "",
      intended: "absent",
      sentence: "signature present, no key to verify against — unverified",
    };
  }

  // Who, before whether — see the module header.
  const signer = matchSigner(sigs[0], keyByFpr);
  if (!signer) {
    /**
     * The set does not hold this signer, and what happens next depends on
     * *whose* set it was — the whole of the refusal/report line.
     *
     * The room is ambient: it is live because a ceremony is happening, not
     * because anybody said "only these people may have written to me". So a
     * message from outside it is reported, in a sentence that names the claimed
     * signer and says why the room could not confirm them. `signers=` is the
     * opposite — a claim written into the recipe — so a message contradicting
     * it stops the run unless `-q` says otherwise.
     */
    const claimed = await claimedSigner(sigs[0]);
    if (against === "signers" && !soft) {
      throw new Error(outsideSignersMessage(claimed, what));
    }
    /**
     * Named, and still `unverified`. `signer` stays empty because nothing
     * checked this — the fingerprint is the message's own claim about itself,
     * and a widget colouring on `signer` must never see it.
     */
    const who = claimed ? `signed by ${formatFingerprint(claimed)}` : "signed by a key";
    return {
      state: "unverified",
      signer: "",
      against,
      intended: "absent",
      sentence:
        against === "room"
          ? `${who}, who is not in this room — unverified. A room is derived ` +
            "from its audience's fingerprints and admits exactly those keys, so " +
            "there is no list to add this signer to — the audience is the list. " +
            "Name the key with `signers=` to check the signature against it."
          : `${who}, whom \`signers=\` does not name — unverified.`,
    };
  }

  // Only now, and unconditionally: this is what decides whether the signature
  // is believed at all.
  try {
    await sigs[0].verified;
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    if (!soft) {
      throw new Error(
        `${what}: the signature from ${formatFingerprint(signer)} did not ` +
          `verify — ${why}. The message decrypted; what failed is the claim ` +
          "about who wrote it. Use `-q` to read the plaintext anyway, with " +
          "the signature left unverified."
      );
    }
    return {
      state: "unverified",
      signer: "",
      against,
      intended: "absent",
      sentence:
        `signature from ${formatFingerprint(signer)} did not verify — ` +
        `${why} — unverified`,
    };
  }

  /**
   * Who the signer meant it for, now that there is a signature worth asking
   * about. A mismatch changes what this sentence *says* and never whether the
   * plaintext came back: the plaintext is already recovered, and refusing
   * would hide the evidence from the one person who needs to see it. That is
   * `intended-recipient.js`'s decision, made before this call site existed and
   * unchanged by its arrival.
   */
  const intendedFprs = await intendedRecipientsFromDecryptSignatures(sigs);
  /**
   * Both halves, or no comparison — and the guard is not defensive tidiness.
   *
   * `checkIntendedRecipient` answers `absent` for an empty *intended* list and
   * has no case for an empty *decryption* fingerprint: given one, every
   * `i === fpr` fails and it returns **`mismatch`**. A message with hidden
   * recipients names no key id in its PKESK, so the caller cannot say which key
   * opened it and hands over `""` — and that message would then be reported as
   * possible surreptitious forwarding for the crime of being addressed
   * privately, which is a legitimate thing to do and the opposite of evidence.
   *
   * A confident wrong verdict is the failure this whole verb is built to avoid,
   * so the missing half is treated as what it is: no claim this run can check.
   */
  const status =
    decryptFpr && intendedFprs.length
      ? checkIntendedRecipient(intendedFprs, decryptFpr).status
      : "absent";
  const base = `signed by ${formatFingerprint(signer)} (${AGAINST_PHRASE[against]})`;
  return {
    state: "verified",
    signer,
    against,
    intended: status,
    sentence:
      status === "mismatch"
        ? `${base}, but addressed to a different key — its Intended Recipient ` +
          "Fingerprint is not the key that opened it, which is what " +
          "surreptitious forwarding looks like (RFC 9580 §13.12)"
        : base,
  };
}

/**
 * Which key of the set signed this, by the signature's own key id.
 *
 * Both spellings openpgp offers are tried — the primary fingerprint's tail and
 * the key's full id list — because a signature made by a subkey carries the
 * subkey's id while the set is keyed by primary fingerprints, and matching
 * only the first would report a room member's subkey-signed message as coming
 * from outside the room.
 *
 * @param {*} sig
 * @param {Map<string, import("openpgp").Key>} keyByFpr
 * @returns {string} whole fingerprint, or "" when no key in the set is it
 */
function matchSigner(sig, keyByFpr) {
  const kidHex = String(sig?.keyID?.toHex?.() || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  for (const [fpr, key] of keyByFpr) {
    const primary = normalizeFingerprintInput(key?.getFingerprint?.() || fpr);
    if (kidHex && primary.endsWith(kidHex)) return primary;
    try {
      for (const id of key?.getKeyIDs?.() || []) {
        if (sig?.keyID && id?.equals?.(sig.keyID)) return primary;
      }
    } catch (_) {
      /* a key that will not enumerate its ids is simply not the match */
    }
  }
  return "";
}

/**
 * The `date` every decrypt in this codebase verifies signatures at.
 *
 * Re-exported here so the two decrypt ops reach it through the module that
 * owns the verdict rather than each importing the clock and each being free to
 * forget. Not `new Date()`: the peer that signed this is a different machine
 * with a different clock — `lib/pgp/clock.js` argues the tolerance.
 */
export { signatureVerificationDate };
