/**
 * The notebook itself, as a document one peer can hand another.
 *
 * ## What was missing, and why nothing worked without it
 *
 * Every check in `handoff.js` is made against text the recipient already holds:
 * an offer names a manifest digest and a cell digest, and `acceptHandoffOffer`
 * compares both against a manifest and a notebook of the recipient's own. That
 * is the good part — it is what makes a shared run a reproducible build rather
 * than a screen share, because the value you accept is proof that the cell you
 * ran is the cell they offered.
 *
 * The doctrine had no mechanism. Nothing in the product ever gave a joiner the
 * text. An invite (`#j=`) carries an audience and deliberately no recipe; the
 * session carried a manifest, an attestation, an offer and a result and no
 * notebook. So a joiner arrived with an empty notebook, derived a manifest from
 * it, and refused every offer with `unknown-manifest` — whose own sentence tells
 * the reader to "ask for the signed manifest, check it, and offer again",
 * naming a step no code performed. The gate was a wall.
 *
 * This document is the missing transport, and it weakens nothing: both ends
 * still hold the same text and still prove it by digest. What changes is that
 * one of them may now *receive* it, signed, instead of being required to retype
 * it.
 *
 * ## It is signed, unlike an offer
 *
 * `handoff.js` argues an offer travels unsigned because "it asserts nothing the
 * recipient takes on trust, since every field is checked against the recipient's
 * own copy of the notebook". A proposal is the exact inverse of that sentence:
 * it *is* the recipient's copy of the notebook, or is about to be, and there is
 * nothing on the receiving machine to check it against. It is the one carried
 * document with no prior document behind it.
 *
 * So `_onDocument`'s rule applies at its strongest — *who signed this is the
 * question the document exists to answer*. Three things follow from adopting
 * somebody's text, and each of them outlives the channel that delivered it:
 * every later cell digest is computed over these bytes, the manifest digest the
 * offer will name is derived from them, and the receipt a person may show to
 * somebody who was not in the room says this notebook is what ran. A pairwise
 * session key says who is on the channel now; a signature is what is left when
 * the channel is gone. That is `readSignedResult`'s argument, and it transfers
 * whole.
 *
 * The proposal therefore carries no `from`, no fingerprint and no assignee, for
 * the reason every other document here carries none: the sender is the peer
 * whose key the signature verifies against, and a second answer in a field the
 * sender chose is a second thing that can be wrong.
 *
 * ## Why `title` travels with `source`
 *
 * Because the manifest digest is computed over both. `handoffContext` folds
 * `title` into `buildRunManifest`, so two peers holding character-identical
 * recipe text and different titles derive different manifests and the offer is
 * still refused `unknown-manifest` — the same wall, one field further in. It is
 * not decoration on the document; it is half of what makes the digests meet.
 *
 * ## The manifest does not travel, and does not need to
 *
 * `handoffContext` *derives* the manifest from `{source, roster, title}` and
 * `buildRunManifest` is deterministic — no timestamp, no nonce. The roster is
 * `roomRoster` over the audience, which is fixed for the session and identical
 * in every browser. So `source` and `title` are the whole of what differs
 * between two peers of one room, and once they agree, the manifest digests agree
 * by construction rather than by delivery.
 *
 * **`session.publishManifest` is gone, and this paragraph is why.** It used to
 * end by saying that publishing a *signed* commitment was a use a derived object
 * could not serve — which is true of the signature and not of the manifest. The
 * signature over the digest is the whole of what cannot be derived, and that
 * document already existed: `publishAttestation` carries four fields where the
 * manifest carried the notebook's entire recipe source, past the
 * `recipeLooksSecret` gate this module holds precisely because that text can
 * contain a private key. One carrier for the text, gated; one for the signature.
 *
 * ## It refuses to carry secret material
 *
 * `recipeLooksSecret` decides, the same predicate that stands between a recipe
 * and a URL. A recipe holding a private key must not go on the wire because
 * somebody typed it into a cell, and "the channel is encrypted" is not an
 * answer: the peer at the other end is a different person, and the ceiling on
 * what they may learn is not the ceiling on what the transport protects.
 *
 * @module lib/toolkit/notebook-share
 */

import { canonicalJson, isoTimestamp } from "./receipt.js";
import { recipeLooksSecret } from "./recipe-secrets.js";

/**
 * Proposal envelope version. Bump when the *shape* changes, or when a field
 * keeps its shape and changes which thing it names.
 *
 * Its own number, as `HANDOFF_VERSION` and `RESULT_VERSION` are their own: six
 * documents now, six reasons to break. This one's first reason to break would
 * be a change to how `handoffContext` derives a manifest from a notebook, since
 * `title` is here only because that derivation reads it.
 */
export const NOTEBOOK_PROPOSAL_VERSION = 1;

/** The `kind` discriminator, so no other document can be read as a proposal. */
export const NOTEBOOK_PROPOSAL_KIND = "basilisk.notebook-proposal";

/**
 * Every field a proposal may carry — the whole document.
 *
 * A closed list rather than a minimum, for `attest.js`'s reason: "carries no
 * fingerprint" and "names no assignee" are only enforceable if there is nowhere
 * to put one. There is deliberately no digest of `source` in here either — the
 * bytes are present, so a digest beside them would be a second answer to what
 * the text is, and this stack has paid for second answers repeatedly.
 * @type {readonly string[]}
 */
export const NOTEBOOK_PROPOSAL_FIELDS = Object.freeze([
  "v",
  "kind",
  "title",
  "source",
  "proposedAt",
]);

/**
 * The longest recipe text a proposal will carry.
 *
 * Well under `MAX_DOCUMENT_BYTES` (32 KiB), which is the ceiling on the whole
 * armored document once the JSON, the signature and the encryption are on it.
 * Refused here as well as there so the sentence a person reads names the
 * notebook rather than the frame.
 */
export const MAX_PROPOSAL_SOURCE = 16384;

/**
 * @typedef {object} NotebookProposal
 * @property {number} v
 * @property {"basilisk.notebook-proposal"} kind
 * @property {string} title   the notebook's title — half of the manifest digest
 * @property {string} source  the recipe text, exactly as the sender holds it
 * @property {string} proposedAt  ISO — the sender's own word, witnessed by nothing
 */

/**
 * Build the proposal for the notebook on this machine.
 *
 * Refuses rather than trimming, and refuses *before* anything is signed: a
 * proposal that dropped a cell would be an offer to run a notebook nobody has,
 * and a signature over it would make that everyone's problem instead of the
 * sender's.
 *
 * @param {{ title?: string, source: string, proposedAt?: string|number|Date }} spec
 * @returns {NotebookProposal}
 */
export function buildNotebookProposal(spec) {
  const source = String(spec?.source ?? "");
  if (!source.trim()) {
    throw new Error(
      "notebook proposal: there is nothing in this notebook to propose. An empty " +
        "proposal would ask the other end to adopt a blank notebook, which is the " +
        "state they are already in and the reason nothing can be handed over."
    );
  }
  if (source.length > MAX_PROPOSAL_SOURCE) {
    throw new Error(
      `notebook proposal: this notebook is ${source.length} characters and the ` +
        `ceiling for one on this channel is ${MAX_PROPOSAL_SOURCE} — refused whole, ` +
        "because half a notebook is text whose cell numbering means nothing on " +
        "either side. Split it, or send the recipe out of band and let both ends " +
        "load the same link."
    );
  }
  if (recipeLooksSecret(source)) {
    throw new Error(
      "notebook proposal: this notebook looks like it holds secret material — " +
        "private key armor, or a JWK with a private component. It is refused " +
        "whole rather than redacted: a recipe carries a secret because " +
        "somebody typed it into a " +
        "cell, and the fix is to move it into Inputs, where it stays on this " +
        "machine, rather than to send a version of the notebook that does not run."
    );
  }
  return {
    v: NOTEBOOK_PROPOSAL_VERSION,
    kind: /** @type {"basilisk.notebook-proposal"} */ (NOTEBOOK_PROPOSAL_KIND),
    title: String(spec?.title ?? "").trim() || "Untitled notebook",
    source,
    // The sender's claim, not a fact — `attest.js`'s `claimedAt` under another
    // name, and no more evidence than that one is.
    proposedAt: isoTimestamp(spec?.proposedAt),
  };
}

/**
 * Canonical bytes of a proposal — what gets signed, and what travels.
 *
 * The signing is not here, for `attest.js`'s and `handoff.js`'s shared reason:
 * a signer buried in a module signs without anybody having read what it signed.
 * A proposal goes out through the session's own key at the moment a person
 * presses Share, which is the same consent boundary `sendCellResult` crosses.
 * @param {NotebookProposal} proposal
 * @returns {string}
 */
export function proposalToJson(proposal) {
  return canonicalJson(proposal);
}

/**
 * Parse a proposal out of text.
 *
 * **The text is the bytes a signature covered, and this does not unwrap armor.**
 * `parseCellResult` refuses an armored body by name for this reason and this
 * does the same: a second answer to *which bytes were signed* is the defect
 * `documents.js` warns about, and this is the document where it would matter
 * most, because these bytes become the notebook every later digest is taken
 * over.
 *
 * Refuses any field outside `NOTEBOOK_PROPOSAL_FIELDS`, for `parseHandoffOffer`'s
 * reason: a document that grew a `from`, an `fpr` or a `runNow` is not a richer
 * proposal, it is a peer putting a claim where this document deliberately has
 * none.
 *
 * @param {string} text
 * @returns {NotebookProposal}
 */
export function parseNotebookProposal(text) {
  const body = String(text ?? "");
  if (/^\s*-----BEGIN PGP SIGNED MESSAGE-----/.test(body)) {
    throw new Error(
      "notebook proposal: this is a signed document and not a proposal — check " +
        "the signature against the key of the peer proposing it, and parse what " +
        "that check hands back. Adopting a notebook is what every later digest " +
        "is computed over, so the bytes worth reading are only ever the bytes " +
        "somebody signed."
    );
  }
  /** @type {*} */
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (_) {
    throw new Error("notebook proposal: not JSON (expected a Basilisk notebook proposal)");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("notebook proposal: not a Basilisk notebook proposal");
  }
  if (parsed.kind !== NOTEBOOK_PROPOSAL_KIND) {
    throw new Error("notebook proposal: not a Basilisk notebook proposal");
  }
  if (Number(parsed.v) !== NOTEBOOK_PROPOSAL_VERSION) {
    throw new Error(
      `notebook proposal: unsupported version ${parsed.v} (this build writes and ` +
        `reads v${NOTEBOOK_PROPOSAL_VERSION})`
    );
  }
  const extra = Object.keys(parsed).filter((k) => !NOTEBOOK_PROPOSAL_FIELDS.includes(k));
  if (extra.length) {
    throw new Error(
      `notebook proposal: unexpected field${extra.length === 1 ? "" : "s"} ` +
        `${extra.sort().join(", ")} — a proposal carries a title and the recipe ` +
        "text, and nothing else. It does not say who should run anything and it " +
        "does not ask for a run: the plan on the receiving machine decides the " +
        "first, and a person decides the second."
    );
  }
  const source = String(parsed.source ?? "");
  if (!source.trim()) {
    throw new Error(
      "notebook proposal: carries no recipe text, so there is nothing to adopt"
    );
  }
  if (source.length > MAX_PROPOSAL_SOURCE) {
    throw new Error(
      `notebook proposal: carries ${source.length} characters of recipe and the ` +
        `ceiling is ${MAX_PROPOSAL_SOURCE}`
    );
  }
  if (typeof parsed.title !== "string") {
    throw new Error(
      "notebook proposal: title must be text — it is folded into the manifest " +
        "digest the offer will name, so a proposal without one names a different " +
        "run than the sender is in"
    );
  }
  // Checked on the way in as well as on the way out. The sender's refusal is an
  // argument about a document this build produced; this is the one that holds
  // when the document was produced by something else.
  if (recipeLooksSecret(source)) {
    throw new Error(
      "notebook proposal: the recipe text in this proposal looks like it holds " +
        "private key material. Refused rather than adopted — a notebook is text " +
        "this machine is about to put in front of a person and digest into every " +
        "later document, and a peer's private key belongs in neither."
    );
  }
  return /** @type {NotebookProposal} */ (parsed);
}

/**
 * Whether two notebooks are the same notebook, for the one purpose this
 * question is asked for: would `handoffContext` derive the same manifest.
 *
 * Exact text, not a canonicalisation. `handoffContext` is explicit that it takes
 * `source` and never a re-serialisation, because serialising drops blank cells
 * and shifts every index after one — so two texts that differ only in whitespace
 * really are two notebooks as far as every digest in this stack is concerned,
 * and saying otherwise here would make an adoption look unnecessary and leave
 * the offer refused.
 *
 * @param {{ title?: string, source?: string }} a
 * @param {{ title?: string, source?: string }} b
 * @returns {boolean}
 */
export function sameNotebook(a, b) {
  return (
    String(a?.source ?? "") === String(b?.source ?? "") &&
    String(a?.title ?? "") === String(b?.title ?? "")
  );
}

/**
 * @typedef {object} NotebookHere
 * @property {string} title
 * @property {string} source  exactly what the editor is showing, serialized
 */

/**
 * What to do about a notebook a peer just proposed.
 *
 * **A pure function, deliberately.** This is the rule that decides whether
 * somebody's work is replaced, and it lived for about an hour inside a React
 * hook where the only thing a test could assert about it was that the source
 * text mentioned the right words. It takes three plain objects and returns one
 * of three words; the hook does the replacing.
 *
 * - **`same`** — this is the notebook already here. Nothing to adopt and nothing
 *   to ask: a peer sharing the text you are holding has told you something
 *   reassuring, not something to decide.
 * - **`adopt`** — take it without asking. Two states reach this, and both are
 *   states where there is no local work to lose. *Nothing here at all* is one,
 *   and the reading of it in this comment was wrong: it was written as "the
 *   joiner's case and the entire reason this document exists", and it is not
 *   the joiner's case, because a joiner is never empty. Pressing Join runs
 *   `startSession`, which appends `agent.unlock` and `quorum.join` to the
 *   notebook *before* the exchange it opens can carry anything — and a proposal
 *   can only arrive over an exchange. So the shell reaches this branch by one
 *   route only: a notebook emptied by hand while a session is already live.
 *   The rule is still the right rule for that state — an empty notebook has no
 *   work to lose — and the argument for it is the smaller one, not the founding
 *   one. What the founding argument actually justified is the *document*: until
 *   it existed nobody could give a joiner the text, so every offer was refused
 *   `unknown-manifest` against a manifest derived from two session cells.
 *   *Here, and untouched since this same peer's last proposal* is the second: a
 *   room where one person is driving should not need a press per revision, and
 *   what is being protected is the local user's own work, of which there is
 *   none.
 * - **`ask`** — there is work here, it is not their text, and this browser did
 *   not get it from them. Do not clobber it.
 *
 * **`adopted` is the whole edit-detector, and it detects edits by comparing text
 * to text.** A boolean "has the user typed since the last adopt" would have to
 * be maintained at every mutator in the editor, and the failure mode of missing
 * one is silent and destructive — a peer's proposal lands on work the flag said
 * was not there. This cannot miss a mutator, cannot be defeated by a new one,
 * and answers honestly when somebody types a character and deletes it again.
 *
 * **The untouched case is scoped to one peer on purpose.** Two people in a room
 * both sharing notebooks are two people disagreeing, and letting the second
 * one's revision land silently because the first one's did would make *whose
 * notebook you are running* depend on packet order.
 *
 * @param {object} spec
 * @param {{ from: string, title: string, source: string }} spec.proposal
 * @param {NotebookHere} spec.here  the notebook on this machine right now
 * @param {{ from: string, title: string, source: string }|null} [spec.adopted]
 *   the last proposal this browser adopted, and who from — null if none
 * @returns {{ action: "same"|"adopt"|"ask", why: string }}
 */
export function decideProposal({ proposal, here, adopted = null }) {
  if (sameNotebook(proposal, here)) {
    return {
      action: "same",
      why:
        "This is the notebook already open here, so there is nothing to adopt. " +
        "Both ends are holding the same text, which is what a cell handed " +
        "across is checked against.",
    };
  }
  if (!String(here?.source ?? "").trim()) {
    return {
      action: "adopt",
      why:
        "There was no notebook open here, so nothing was replaced. Until this " +
        "arrived, every cell a peer handed over was refused against a manifest " +
        "derived from an empty notebook.",
    };
  }
  if (adopted && adopted.from === proposal.from && sameNotebook(adopted, here)) {
    return {
      action: "adopt",
      why:
        "This notebook came from the same peer it came from last time and has " +
        "not been edited here since, so there was no work of your own to keep.",
    };
  }
  return {
    action: "ask",
    why:
      "There is a notebook open here that is not the one they sent, and this " +
      "browser did not get it from them — so nothing was replaced. Adopting " +
      "takes theirs; keeping yours leaves every cell handed across refused as " +
      "a notebook this peer has not seen.",
  };
}
