/**
 * Recipe playbooks — a signed procedure, meant to be read by a stranger years
 * later.
 *
 * The problem this exists for is the one a printed share card leaves open. A
 * custodian holds a card; it names the split, the threshold and `vss.combine`,
 * because `share-cards.js` puts those on paper for exactly this moment. What it
 * cannot hold is the *procedure*: which recipe recombines, what to do with the
 * result — the envelope, the PEM, the key that was split — and in what order.
 * The author may be gone. A playbook is that procedure, signed by somebody
 * whose key can still be checked, and stored somewhere that outlives the room.
 *
 * ## Why this is not a run manifest
 *
 * A manifest already carries a notebook's recipe source and every cell's text
 * and digest, and it is already signable, so it looks like the document for
 * this. It is not, and the reason is a security one rather than a taxonomic
 * one: a manifest also carries `peersSha`, `audienceSha`, the pinned `inputs`
 * of one run, and `vault[].keyId` — and `manifest.js` says of that last field,
 * in its own words, that a vault key id is key-identifying material and *"a
 * manifest is a room-internal document — do not hand one to a bystander"*.
 *
 * A playbook exists precisely to be handed to a bystander. So it is a different
 * document with a closed field list, and the list has nowhere to put any of
 * that.
 *
 * ## What it carries, and why the recipe rather than its digest
 *
 * `recipeSource` is the whole recipe, verbatim, inside the signed bytes. A
 * digest would be the smaller and more fashionable choice and it would be
 * useless here: in disaster recovery the reader has the playbook and nothing
 * else, so a digest would send them to find the text somewhere they would then
 * have to trust. Carrying the text means the signature covers the thing they
 * actually run.
 *
 * It is the **canonical** text — `serializeRecipe`'s — not whatever the author
 * typed. Two reasons, and the second is the one that bites: canonical text is
 * stable under load-and-save, so a reader who opens the playbook and saves the
 * notebook gets the same bytes and the same digest, which is the divergence
 * that shows up as `cell-mismatch` between two peers holding one notebook.
 *
 * `purpose` used to be justified by the recipe being unable to hold a sentence
 * at all — `#` comments were dropped by `serializeRecipe`. They survive now, so
 * that is no longer the reason and this field stands on a narrower one: a
 * comment is *inside* the recipe and therefore inside `recipeDigest`, which
 * makes editing the instruction indistinguishable from editing the procedure.
 * `purpose` is addressed to the custodian and is signed alongside the recipe
 * without being part of what the recipe means. A comment explaining a step
 * belongs in the recipe; the paragraph telling a stranger what to do with what
 * they recover belongs here.
 *
 * `splitId` is a label, and the disaster-recovery case is the reason it is
 * here: a custodian holding two ceremonies' envelopes has no way to tell which
 * playbook belongs with which cards without it. It is `share-check.js`'s own
 * identifier — a prefix of the split's public key, derived rather than assigned
 * — so this reuses a name the system already has, and a split label is not
 * key-identifying material.
 *
 * ## What it deliberately does not carry
 *
 * No values, ever, on `receipt.js`'s invariant. No fingerprints, no vault key
 * ids, no `peersSha` or `audienceSha`: `630dc96` refuses fingerprint-shaped
 * peer labels and `786070b` domain-separates the audience digest because a
 * digest of the audience is the room key, and a free-text field on a document
 * that travels to strangers is exactly where a fingerprint ends up. No pinned
 * inputs and no seeds. Not the shares, and **not the commitments** — those
 * travel with the cards, which is what the ceremony already does, and
 * `share-check.js` matches them by split id.
 *
 * It also carries no summary of what the recipe needs or produces.
 * `validateRecipe` already computes `inputNeeds` and the type walk already
 * computes the outputs, so a reader derives both from the recipe the signature
 * covers. Storing them would be a second answer that can disagree with the
 * first, which is the defect this stack has paid for repeatedly.
 *
 * `createdAt` is the author's own word for the moment, corroborated by nothing
 * — `attest.js` says the same of `claimedAt`, and for the same reason: a
 * signature covers a lie about the time as faithfully as it covers the truth.
 *
 * ## Verification is not optional, and it is one act
 *
 * There is no function here that opens a playbook. `playbook.verify` — the op —
 * verifies the signature and parses the document **out of the bytes OpenPGP
 * hashed**, in that order, in one step. `documents.js` states the rule this
 * follows: two answers to "which bytes were signed" agree until the first edge
 * case one of them learns about alone, "and then a signature vouches for bytes
 * nobody parsed". So `parsePlaybook` takes text, and the op only ever hands it
 * verified text.
 *
 * A reader with no key at all is not stuck. A playbook travels as OpenPGP
 * cleartext armor, so the recipe is legible between the header and the
 * signature with no software at all — paper and eyes always work. The op is
 * what turns *I read it* into *I checked it*.
 *
 * @module lib/toolkit/playbook
 */

import { canonicalJson, digestText, isoTimestamp, unwrapCleartext } from "./receipt.js";

/**
 * Playbook envelope version. Bump when the *shape* changes.
 *
 * Independent of `MANIFEST_VERSION`, `RECEIPT_VERSION` and
 * `ATTESTATION_VERSION` — four documents now, four reasons to break, and this
 * one's reason will be the field list rather than a numbering or a role table.
 */
export const PLAYBOOK_VERSION = 1;

/** The `kind` discriminator, so no other document can be read as a playbook. */
export const PLAYBOOK_KIND = "basilisk.recipe-playbook";

/**
 * Every field a playbook may carry — the whole document.
 *
 * A closed list rather than a minimum, and enforced by `parsePlaybook` rather
 * than described here. "Must not carry a fingerprint, a key id or an audience"
 * is only true if there is nowhere to put one, and a document that travels to
 * people who were never in the room is the one where that matters most.
 * @type {readonly string[]}
 */
export const PLAYBOOK_FIELDS = Object.freeze([
  "v",
  "kind",
  "title",
  "purpose",
  "splitId",
  "createdAt",
  "registry",
  "recipeSource",
  "recipeDigest",
]);

/** A SHA-256 digest as this codebase writes one: 64 lowercase hex characters. */
const DIGEST_RE = /^[0-9a-f]{64}$/;

/**
 * A split id as `share-check.js` writes one: hex groups a person reads aloud.
 * Bounded and character-restricted because this is the one free-ish string on a
 * document whose whole design is having nowhere to hide identifying material —
 * a 40-hex fingerprint must not fit through it.
 */
const SPLIT_ID_RE = /^[0-9A-F]{1,4}(-[0-9A-F]{1,4}){0,2}$/;

/** Longest title / purpose a playbook records. Prose, not a payload. */
export const PLAYBOOK_TITLE_MAX = 120;
export const PLAYBOOK_PURPOSE_MAX = 2000;

/**
 * @typedef {object} RecipePlaybook
 * @property {number} v
 * @property {"basilisk.recipe-playbook"} kind
 * @property {string} title         what this procedure is called
 * @property {string} purpose       the instruction to a stranger, kept beside
 *   the recipe rather than inside it: a `#` comment survives serialization now
 *   but is part of `recipeDigest`, so prose that belongs to the reader would
 *   otherwise be indistinguishable from prose that changes the agreement
 * @property {string} splitId       `share-check.js`'s label for the split these
 *   cards belong to, "" when the procedure is not about one
 * @property {string} createdAt     ISO — the author's own word, witnessed by nothing
 * @property {string} registry      `opsRegistryVersion()` when it was written,
 *   so a reader can tell whether the ops have moved under them
 * @property {string} recipeSource  the canonical recipe text, verbatim
 * @property {string} recipeDigest  digest of `recipeSource`
 */

/**
 * Assemble a playbook. Pure apart from the digest of `recipeSource`.
 *
 * Refuses an empty recipe rather than minting a playbook that says to run
 * nothing: the whole document is a pointer at a procedure, and one with no
 * procedure in it is a signature somebody would rely on.
 *
 * @param {{
 *   title?: string,
 *   purpose?: string,
 *   splitId?: string,
 *   createdAt?: string|number|Date,
 *   registry?: string,
 *   recipeSource?: string,
 * }} spec
 * @returns {Promise<RecipePlaybook>}
 */
export async function buildPlaybook(spec = {}) {
  const recipeSource = String(spec.recipeSource ?? "").trim();
  if (!recipeSource) {
    throw new Error(
      "playbook: there is no recipe to write a playbook for — a playbook is a " +
        "procedure somebody will follow when nobody is left to ask, so an empty " +
        "one is a signature over nothing"
    );
  }
  const splitId = String(spec.splitId ?? "").trim().toUpperCase();
  if (splitId && !SPLIT_ID_RE.test(splitId)) {
    throw new Error(
      `playbook: "${splitId.slice(0, 24)}" is not a split id — it is ` +
        "`share-check.js`'s short label (`A1B2-C3D4-E5F6`), and this field is " +
        "narrow on purpose so that a fingerprint cannot travel through it"
    );
  }
  return {
    v: PLAYBOOK_VERSION,
    kind: /** @type {"basilisk.recipe-playbook"} */ (PLAYBOOK_KIND),
    title: String(spec.title || "Untitled procedure").slice(0, PLAYBOOK_TITLE_MAX),
    purpose: String(spec.purpose ?? "").slice(0, PLAYBOOK_PURPOSE_MAX),
    splitId,
    // The author's claim, not a fact. See the module header.
    createdAt: isoTimestamp(spec.createdAt),
    registry: String(spec.registry ?? ""),
    recipeSource,
    recipeDigest: await digestText(recipeSource),
  };
}

/**
 * Canonical bytes of a playbook — what gets signed, and what a reader hashes.
 * @param {RecipePlaybook} playbook
 * @returns {string}
 */
export function playbookToJson(playbook) {
  return canonicalJson(playbook);
}

/**
 * SHA-256 of a playbook's canonical JSON.
 *
 * Over the canonical form rather than the bytes that arrived, for
 * `readSignedAttestation`'s reason: two people who serialised the same playbook
 * with different key order still name the same digest, and any change to a
 * field changes it.
 * @param {RecipePlaybook} playbook
 * @returns {Promise<string>}
 */
export function playbookDigest(playbook) {
  return digestText(playbookToJson(playbook));
}

/**
 * Parse a playbook out of text, tolerating an OpenPGP cleartext wrapper.
 *
 * **Being able to parse one is not being able to trust one.** This checks
 * shape, and shape is not provenance: an unsigned playbook and a playbook
 * signed by a stranger both parse. The op that reads one verifies first and
 * hands this the bytes the signature covered — see the module header.
 *
 * `unwrapCleartext` is the receipt's, parameterised on the noun, so there is
 * one answer to "strip the armor" across all four documents.
 *
 * @param {string} text
 * @returns {RecipePlaybook}
 */
export function parsePlaybook(text) {
  const body = unwrapCleartext(text, "playbook");
  /** @type {*} */
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (_) {
    throw new Error("playbook: not JSON (expected a Basilisk recipe playbook)");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("playbook: not a Basilisk recipe playbook");
  }
  if (parsed.kind !== PLAYBOOK_KIND) {
    throw new Error("playbook: not a Basilisk recipe playbook");
  }
  if (Number(parsed.v) !== PLAYBOOK_VERSION) {
    throw new Error(`playbook: unsupported version ${parsed.v}`);
  }
  const extra = Object.keys(parsed).filter((k) => !PLAYBOOK_FIELDS.includes(k));
  if (extra.length) {
    throw new Error(
      `playbook: unexpected field${extra.length === 1 ? "" : "s"} ` +
        `${extra.sort().join(", ")} — a playbook carries a procedure and the ` +
        "prose to follow it, and nothing else, so that it has nowhere to carry " +
        "a fingerprint, a vault key id or an audience. This document travels to " +
        "people who were never in the room."
    );
  }
  if (!String(parsed.recipeSource ?? "").trim()) {
    throw new Error("playbook: carries no recipe, so there is no procedure to follow");
  }
  if (!DIGEST_RE.test(String(parsed.recipeDigest ?? ""))) {
    throw new Error(
      "playbook: recipeDigest must be a SHA-256 digest as 64 lowercase hex characters"
    );
  }
  if (String(parsed.splitId ?? "") && !SPLIT_ID_RE.test(String(parsed.splitId))) {
    throw new Error(
      "playbook: splitId is not a split label — see `share-check.js`'s `splitIdFor`"
    );
  }
  return /** @type {RecipePlaybook} */ (parsed);
}

/**
 * Does the playbook's digest describe the recipe it carries?
 *
 * Separate from `parsePlaybook` because it is async and that one is not, and
 * kept because the two fields are the one place this document can contradict
 * itself: a reader who cites `recipeDigest` while running `recipeSource` would
 * be naming a procedure other than the one they performed. Cheap, and it fires
 * before anybody runs anything.
 *
 * @param {RecipePlaybook} playbook
 * @returns {Promise<RecipePlaybook>} the same playbook, when it agrees with itself
 */
export async function assertPlaybookIntegrity(playbook) {
  const actual = await digestText(String(playbook?.recipeSource ?? ""));
  if (actual !== String(playbook?.recipeDigest ?? "")) {
    throw new Error(
      "playbook: the recipe in this playbook is not the recipe its digest " +
        "names. The signature covers both, so this is not tampering that got " +
        "past a check — it is a document that was inconsistent when it was " +
        "signed, and neither half of it can be relied on."
    );
  }
  return playbook;
}

/**
 * Who vouched for a playbook, and what it said.
 *
 * `by` is the key that actually verified it, not the key somebody hoped would.
 * A caller renders it: **"signed by a key you hold" and "signed by a key you
 * trust" are different sentences**, and a surface that showed a tick without a
 * name would be saying the second while meaning the first.
 *
 * @typedef {object} PlaybookOpening
 * @property {boolean} ok
 * @property {RecipePlaybook|null} playbook  parsed out of the *verified* bytes
 * @property {{ fingerprint: string, uid: string }|null} by
 * @property {"unsigned"|"no-keys"|"not-yours"|"malformed"|""} reason  a
 *   machine-readable why, so a surface can tell "I have no key for this" from
 *   "this signature is bad" — they call for different actions and only one of
 *   them is alarming
 * @property {string} message  the sentence a person reads
 */

/**
 * Verify a signed playbook against keys you hold, and say who signed it.
 *
 * The same act `playbook.verify` performs, against a *set* of candidate keys
 * rather than one named in a recipe — a person opening a file from an envelope
 * has a keyring, not a `key=$author`. It goes through the same
 * `verifiedCleartextOpenPgp`, so there is one answer to "which bytes were
 * signed" across the op and every surface.
 *
 * Imported lazily for `engine.js`'s reason: this module is the document shape
 * and is cheap to load, and OpenPGP is not. Nothing pays for it until somebody
 * opens a playbook.
 *
 * **Refusing is not the same as failing.** A document nobody's key matches is
 * not evidence of tampering — it is a key you do not have — and `reason` keeps
 * the two apart so a surface can say the true one.
 *
 * @param {string} armored  the cleartext-signed document, as stored or imported
 * @param {{ fingerprint?: string, uid?: string, publicArmored?: string }[]} candidates
 * @returns {Promise<PlaybookOpening>}
 */
export async function openSignedPlaybook(armored, candidates = []) {
  const text = String(armored ?? "").trim();
  /** @param {PlaybookOpening["reason"]} reason @param {string} message */
  const no = (reason, message) => ({ ok: false, playbook: null, by: null, reason, message });

  if (!/^-----BEGIN PGP SIGNED MESSAGE-----/m.test(text)) {
    return no(
      "unsigned",
      "This is not a signed playbook. A playbook says what to do with a secret " +
        "when nobody is left to ask, so an unsigned one names nobody who stands " +
        "behind it — read it by eye if you like, but nothing here will vouch for it."
    );
  }
  const usable = candidates.filter((c) => String(c?.publicArmored || "").trim());
  if (!usable.length) {
    return no(
      "no-keys",
      "There is no public key here to check this signature against. Add the " +
        "author's key to My Keys, or fetch it with `hkp.get`, and open it again."
    );
  }

  const { readKey } = await import("openpgp");
  const { verifiedCleartextOpenPgp } = await import("../pgp/sign.js");
  for (const candidate of usable) {
    /** @type {string} */
    let verified;
    try {
      const key = await readKey({ armoredKey: String(candidate.publicArmored) });
      verified = await verifiedCleartextOpenPgp(text, [key], "playbook");
    } catch (_) {
      // Wrong key, revoked key, mangled body: all of them are "not this key",
      // and the next candidate gets its turn. The distinction that matters is
      // made once, below, after every key has failed.
      continue;
    }
    try {
      const playbook = await assertPlaybookIntegrity(parsePlaybook(verified));
      return {
        ok: true,
        playbook,
        by: {
          fingerprint: String(candidate.fingerprint || ""),
          uid: String(candidate.uid || ""),
        },
        reason: "",
        message: "",
      };
    } catch (err) {
      // The signature is good and the document is not. Reported as itself
      // rather than as a signature failure — telling somebody their key is
      // wrong when the document is malformed sends them hunting for the wrong
      // thing.
      return no("malformed", err instanceof Error ? err.message : String(err));
    }
  }
  return no(
    "not-yours",
    "This playbook is signed, and not by any key you hold. That is not proof " +
      "it was tampered with — a signature that verifies against some key is " +
      "not one that verifies against yours — but nothing here can tell you who " +
      "wrote it until you have their key."
  );
}

/**
 * A one-line human summary — the shape `summarizePlan`, `summarizeHonour` and
 * `summarizeAttestation` return.
 * @param {RecipePlaybook} playbook
 * @returns {string}
 */
export function summarizePlaybook(playbook) {
  const cells = String(playbook?.recipeSource ?? "")
    .split(/\n\s*\n+/)
    .filter((c) => c.trim()).length;
  const split = playbook?.splitId ? `, split ${playbook.splitId}` : "";
  return `${playbook?.title || "Untitled procedure"} — ${cells} ${
    cells === 1 ? "cell" : "cells"
  }${split}, written ${String(playbook?.createdAt || "").slice(0, 10) || "at an unstated time"}`;
}
