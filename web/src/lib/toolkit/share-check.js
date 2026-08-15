/**
 * The custodian's check — "is the share I am holding genuine?"
 *
 * `vss.split` makes shares that can be *checked*, and `vss.verify` is the op
 * that checks them. What was missing is the situation: a person who was handed
 * one card at a ceremony months ago, opening the toolkit on a machine with no
 * session, no notebook, and no other share. They have two things — a mnemonic
 * (and maybe a QR of it) and a commitments document that reached them by some
 * other route — and exactly one question.
 *
 * This module is the model behind that surface. It is deliberately not a
 * component and deliberately not a new op:
 *
 * - **Not a component**, because the interesting part is the verdict wording,
 *   and wording that can drift from the thing it describes is how a UI ends up
 *   saying "verified" about a check it did not perform. The verdicts are
 *   unit-tested strings.
 * - **Not a new op.** The actual verification goes through `execVssVerify`,
 *   the same code path `… | vss.verify` runs. `shareCheckRecipe()` prints the
 *   recipe that does this by hand, so the panel is a convenience over the
 *   notebook rather than a second implementation of it.
 *
 * ## The distinctions this module exists to keep straight
 *
 * **Well-formed is not genuine.** A BLIP39 mnemonic carries an RS1024
 * checksum, so it can be decoded, indexed, and shown to be internally
 * consistent without anything at all being known about which split it came
 * from. A surface that renders "share 2 of 5 ✓" off a successful decode has
 * told the custodian nothing and implied everything. `share-only` is therefore
 * its own status with its own explicitly negative wording.
 *
 * **A failed check does not mean a bad share.** Because the checksum already
 * catches transcription errors, a mnemonic that decodes cleanly and then fails
 * `vss.verify` is very unlikely to be mistyped. The realistic causes are: the
 * commitments belong to a *different* split, or the share does (a card from
 * last year's ceremony), or the share came from `sss.split`, which has no
 * commitments to match and never will. The check cannot tell these apart, so
 * the verdict names all three rather than picking the alarming one.
 *
 * **Nothing here reveals anything.** Commitments are public by construction,
 * the share bytes never leave the device, and a verification result is one bit.
 * That is worth saying on the surface, because "paste your secret share into a
 * web page" is otherwise advice a careful person should refuse.
 *
 * @module lib/toolkit/share-check
 */

import { decodeMnemonic, formatSetId } from "../slip39/blip39.js";
import { publicKeyOf } from "../quorum/vss.js";
import { execVssVerify } from "./vss-ops.js";

/**
 * @typedef {"empty"|"bad-share"|"bad-commitments"|"share-only"|"commitments-only"
 *   |"verified"|"mismatch"} ShareCheckStatus
 */

/**
 * @typedef {object} ShareFacts
 * @property {number} index      1-based share number
 * @property {number} total      shares in the set, as recorded at encode time
 * @property {number} threshold  how many recombine
 * @property {string} setId      4 hex digits, assigned when the mnemonics were made
 * @property {Uint8Array} bytes
 */

/**
 * @typedef {object} SplitFacts
 * @property {string[]} commitments
 * @property {string} publicKey  compressed P-256 point — the split's identity
 * @property {string} splitId    grouped short form of `publicKey`, for reading aloud
 * @property {number} degree     commitments minus one = the polynomial's degree
 */

/**
 * @typedef {object} ShareCheckVerdict
 * @property {ShareCheckStatus} status
 * @property {"ok"|"error"|"warn"|"pending"} tone
 * @property {string} headline
 * @property {string} detail
 * @property {ShareFacts|null} share
 * @property {SplitFacts|null} split
 * @property {string} shareError
 * @property {string} commitmentsError
 */

/** @param {Uint8Array} b */
function bytesToHex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/**
 * A short, speakable name for a split.
 *
 * Derived from the public key rather than assigned, so two people reading it
 * to each other over a phone are comparing the same cryptographic object. It
 * is a prefix, so it is a *label*, not a commitment — matching split ids is
 * how you notice you are looking at the wrong document, not how you verify a
 * share. The verification is the verification.
 *
 * @param {string} publicKeyHex
 * @returns {string}
 */
export function splitIdFor(publicKeyHex) {
  const hex = String(publicKeyHex || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
  // Skip the 02/03 parity prefix — it is one of two values and carries no
  // distinguishing power, so including it would waste two of the digits a
  // person has to read out.
  const body = hex.length > 2 ? hex.slice(2) : hex;
  const groups = [body.slice(0, 4), body.slice(4, 8), body.slice(8, 12)].filter(Boolean);
  return groups.join("-");
}

/**
 * Read a BLIP39 mnemonic without asserting anything about its provenance.
 *
 * @param {string} text
 * @returns {{ ok: boolean, empty: boolean, error: string, facts: ShareFacts|null }}
 */
export function readShareMnemonic(text) {
  const raw = String(text || "").trim();
  if (!raw) return { ok: false, empty: true, error: "", facts: null };
  try {
    const m = decodeMnemonic(raw);
    return {
      ok: true,
      empty: false,
      error: "",
      facts: {
        index: m.index,
        total: m.shareCount,
        threshold: m.threshold,
        // The codec's own spelling, so the `set XXXX` this panel prints is
        // character-for-character the `set XXXX` a recovery's refusal names —
        // the two are read against each other by a person holding cards.
        setId: formatSetId(m.id),
        bytes: m.data,
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, empty: false, error: message, facts: null };
  }
}

/**
 * Read a commitments document.
 *
 * Three input shapes are accepted because three are what actually arrive:
 * `vss.commitments`' own JSON object, a bare JSON array (someone pulled the
 * field out), and whitespace-separated hex points (someone typed them off a
 * printout). Being liberal here costs nothing — every one of these is public
 * data, and a wrong guess fails the verification, not the parse.
 *
 * @param {string} text
 * @returns {{ ok: boolean, empty: boolean, error: string, facts: SplitFacts|null }}
 */
export function readCommitments(text) {
  const raw = String(text || "").trim();
  if (!raw) return { ok: false, empty: true, error: "", facts: null };

  /** @type {string[]|null} */
  let list = null;
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) list = parsed.map(String);
    else if (Array.isArray(parsed?.commitments)) list = parsed.commitments.map(String);
  } catch {
    /* not JSON — try the hex-list form below */
  }
  if (!list) {
    const tokens = raw.split(/[\s,]+/).filter(Boolean);
    if (tokens.length && tokens.every((t) => /^(02|03|04)[0-9a-f]+$/i.test(t))) {
      list = tokens;
    }
  }
  if (!list || !list.length) {
    return {
      ok: false,
      empty: false,
      error:
        "Not a commitments document. Expected the JSON that `vss.commitments` writes (a `commitments` array of hex points).",
      facts: null,
    };
  }

  try {
    const publicKey = publicKeyOf(list);
    return {
      ok: true,
      empty: false,
      error: "",
      facts: {
        commitments: list,
        publicKey,
        splitId: splitIdFor(publicKey),
        degree: list.length - 1,
      },
    };
  } catch (err) {
    return {
      ok: false,
      empty: false,
      error:
        "The commitments are not valid P-256 points — the document is truncated or from another curve.",
      facts: null,
    };
  }
}

/**
 * The recipe that does exactly what this panel does.
 *
 * Shown on the surface, not hidden behind it: a custodian who does not trust a
 * form should be able to run the check as ordinary notebook cells and get the
 * same answer, and a custodian who *does* trust it should still be able to see
 * that it is not doing anything else.
 *
 * @returns {string}
 */
export function shareCheckRecipe() {
  return [
    "shares | blip39.decode",
    "| vss.verify commitments=$commitments",
    "| out $checked",
  ].join(" ");
}

/**
 * @param {ShareFacts} share
 * @param {SplitFacts} split
 * @returns {boolean}
 */
function runVerify(share, split) {
  try {
    execVssVerify(
      {
        type: "shares",
        data: {
          encoding: "raw",
          raw: [{ index: share.index, data: share.bytes }],
          threshold: share.threshold,
          shares: share.total,
          commitments: split.commitments,
        },
      },
      {},
      {}
    );
    return true;
  } catch {
    // `execVssVerify` throws with the failing indices; with one share in the
    // set that message adds nothing the verdict does not already say better.
    return false;
  }
}

/**
 * The whole verdict, in one call.
 *
 * @param {{ shareText?: string, commitmentsText?: string }} input
 * @returns {ShareCheckVerdict}
 */
export function checkShare({ shareText = "", commitmentsText = "" } = {}) {
  const s = readShareMnemonic(shareText);
  const c = readCommitments(commitmentsText);

  /** @type {ShareCheckVerdict} */
  const base = {
    status: "empty",
    tone: "pending",
    headline: "",
    detail: "",
    share: s.facts,
    split: c.facts,
    shareError: s.error,
    commitmentsError: c.error,
  };

  if (!s.ok && !s.empty) {
    return {
      ...base,
      status: "bad-share",
      tone: "error",
      headline: "That is not a readable share.",
      detail:
        `${s.error}. Every BLIP39 mnemonic carries a checksum, so a single wrong or ` +
        "missing word is caught here rather than later — re-read the card, and mind that " +
        "the words are ordinary English ones that autocorrect likes to change.",
    };
  }

  if (!c.ok && !c.empty) {
    return {
      ...base,
      status: "bad-commitments",
      tone: "error",
      headline: "Those are not readable commitments.",
      detail: `${c.error} Commitments are public, so it is safe to ask whoever ran the ceremony to send them again.`,
    };
  }

  if (s.empty && c.empty) {
    return {
      ...base,
      status: "empty",
      tone: "pending",
      headline: "Nothing to check yet.",
      detail:
        "Paste the mnemonic from your card and the commitments the ceremony published. " +
        "Both stay on this device: the check is arithmetic on a curve, not a lookup.",
    };
  }

  if (s.empty && c.ok && c.facts) {
    return {
      ...base,
      status: "commitments-only",
      tone: "pending",
      headline: `Commitments read — split ${c.facts.splitId}.`,
      detail:
        `They describe a polynomial of degree ${c.facts.degree}, so ${c.facts.degree + 1} shares ` +
        "recombine. Now paste the mnemonic from your card.",
    };
  }

  if (s.ok && s.facts && c.empty) {
    const f = s.facts;
    return {
      ...base,
      status: "share-only",
      tone: "warn",
      headline: `Share ${f.index} of ${f.total} — well-formed, and unverified.`,
      detail:
        "Nothing has been checked. A mnemonic that decodes cleanly proves only that it was " +
        "typed correctly; it does not show which split it came from, or that the person who " +
        "handed it to you dealt it honestly. Paste the published commitments to find that out.",
    };
  }

  if (s.ok && s.facts && c.ok && c.facts) {
    const f = s.facts;
    const split = c.facts;
    if (runVerify(f, split)) {
      return {
        ...base,
        status: "verified",
        tone: "ok",
        headline: `Share ${f.index} is genuine — split ${split.splitId}.`,
        detail:
          `It lies on the same polynomial as every other share in this split, so any ` +
          `${f.threshold} of the ${f.total} cards reconstruct the secret and yours will be one ` +
          "of them. The check revealed nothing: it compared a point on the curve against " +
          "public commitments, and it ran here, offline.",
      };
    }
    return {
      ...base,
      status: "mismatch",
      tone: "error",
      headline: `Share ${f.index} is not from split ${split.splitId}.`,
      detail:
        "The mnemonic is internally valid, so this is almost certainly not a typing mistake — " +
        "the checksum would have caught that. Three things look like this: these are another " +
        "split's commitments, this card is from another ceremony, or the card came from " +
        "`sss.split`, which produces shares that carry no commitments and can never match any. " +
        "The check cannot tell them apart. Confirm the split id with whoever published the " +
        "commitments before treating the card as broken.",
    };
  }

  return base;
}
