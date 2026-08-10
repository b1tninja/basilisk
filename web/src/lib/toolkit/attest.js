/**
 * Manifest attestations — a peer's assertion that they saw a run manifest, and
 * the check that a set of those assertions covers one.
 *
 * Not WebAuthn attestation (`lib/webauthn/attestation.js`), which is an
 * authenticator vouching for its own make and model. This is one line of JSON
 * carrying a manifest's digest, meant to be handed to `gpg.sign` — the same way
 * `run.receipt | gpg.sign` is the only signing path a receipt has. There is no
 * signing function in this module for the reason there is none in `receipt.js`:
 * the recipe is the thing the user reads before pressing Run, and a signer
 * buried in a module signs without anyone having read a recipe.
 *
 * ## What an attestation proves
 *
 * **The attester held the key, and saw that digest.** That is the whole of it.
 * The document names a manifest and nothing else; the signature around it names
 * the signer. Since the manifest's digest covers every field of the manifest —
 * recipe source, every cell's text, the op registry, the pinned inputs — an
 * attestation over that digest is an assertion about all of them at once.
 *
 * ## What it does not prove
 *
 * - **When.** `claimedAt` is the attester's own word for the moment, corroborated
 *   by nothing. An attester who wants a different time writes a different time,
 *   and the signature covers the lie as faithfully as it would the truth. A
 *   third-party timestamp — an RFC 3161 token, a transparency-log inclusion
 *   proof — is what would fix this, and none is in scope here for the reason
 *   `manifest.js`'s header gives about `manifestHonouredBy`: this unit binds
 *   documents to each other by correspondence, and a commitment to a *moment* is
 *   a different mechanism with a different trusted party.
 * - **That the attester read the manifest**, as opposed to signing a digest
 *   someone handed them. A signature is not comprehension.
 * - **That the attester will honour it.** Attesting is not consenting to run.
 *
 * ## The ordering property is mutual, not temporal
 *
 * The thing this is *for* is establishing that a manifest came first — that the
 * run was committed to before it happened, rather than described afterwards to
 * fit whatever it did. Read plainly, the property is this:
 *
 * > If every participant attests to a manifest before the run, and the run's
 * > receipt is checked against that manifest, then **among those participants**
 * > the ordering holds — because each of them was there, each remembers
 * > attesting before anything ran, and each holds a signature they can produce.
 *
 * Two consequences a reader should not have to infer:
 *
 * - **It does not hold for anyone who was not present.** A bystander handed the
 *   manifest, the attestations and the receipt afterwards sees a mutually
 *   consistent bundle and cannot tell the honest ordering from a bundle
 *   assembled in one sitting after the run. Nothing here is evidence to a third
 *   party; it is evidence *between the people who were in the room*.
 * - **It does not survive every participant colluding.** The ordering rests on
 *   each participant being able to testify, so a room where all of them agree to
 *   say the same false thing produces a perfect bundle. That is not a defect to
 *   be patched — it is what "mutual" means. The guarantee is against *one*
 *   participant rewriting history on the others, which is the case it was built
 *   for.
 *
 * ## No fingerprints, and no room for one
 *
 * The document carries `v`, `kind`, `manifest` and `claimedAt`, and
 * `parseAttestation` refuses any field beyond those. That refusal is the
 * mechanism, not decoration: `630dc96` refuses fingerprint-shaped peer labels
 * and `786070b` domain-separates `peersSha` because a digest of the audience is
 * the room key, and a free-text field on a document that travels between peers
 * is exactly where a fingerprint would end up. The signature already names the
 * signer, so there is nothing a name field could add except a leak.
 *
 * The consequence is that *who attested* is not in the document. It is
 * established by verifying the signature — `gpg.verify`'s job — and handed to
 * `manifestAttestedBy` by the caller as `by`. An entry with no `by` is counted
 * for nothing beyond naming a digest, and the result says so.
 *
 * @module lib/toolkit/attest
 */

import {
  canonicalJson,
  isoTimestamp,
  mismatchLog,
  unwrapCleartext,
} from "./receipt.js";
import { manifestDigest } from "./manifest.js";

/**
 * Attestation envelope version. Bump when the *shape* changes.
 *
 * Independent of `MANIFEST_VERSION` and `RECEIPT_VERSION` — three documents,
 * three reasons to break, and an attestation is deliberately the one whose
 * shape has almost nothing in it to change.
 */
export const ATTESTATION_VERSION = 1;

/** The `kind` discriminator, so a receipt cannot be read as an attestation. */
export const ATTESTATION_KIND = "basilisk.manifest-attestation";

/**
 * Every field an attestation may carry — the whole document.
 *
 * A closed list rather than a minimum, because "must not carry fingerprints" is
 * only enforceable if there is nowhere to put one. See the module header.
 * @type {readonly string[]}
 */
export const ATTESTATION_FIELDS = Object.freeze(["v", "kind", "manifest", "claimedAt"]);

/** A SHA-256 digest as this codebase writes one: 64 lowercase hex characters. */
const DIGEST_RE = /^[0-9a-f]{64}$/;

/**
 * @typedef {object} ManifestAttestation
 * @property {number} v
 * @property {"basilisk.manifest-attestation"} kind
 * @property {string} manifest   SHA-256 of the manifest's canonical JSON
 * @property {string} claimedAt  ISO — the attester's own claim, witnessed by nothing
 */

/**
 * One attestation, plus whoever the *caller* established signed it.
 *
 * `by` is not in the document and must not be: it is the output of checking a
 * signature, which happens outside this module. Leaving it off is allowed and
 * honest — an attestation nobody authenticated still says which manifest it is
 * about — and `manifestAttestedBy` will not count it toward coverage.
 * @typedef {object} AttestationEntry
 * @property {ManifestAttestation} attestation
 * @property {string} [by]  peer label the signature resolved to, never a fingerprint
 */

/**
 * Build an attestation over a manifest.
 *
 * Takes either the manifest or its digest, because both callers exist: the
 * `run.attest` op parses a manifest it was handed, and a peer who already has
 * the digest should not have to reconstruct the document to attest to it.
 *
 * Async only because of the digest, and only when one has to be computed.
 *
 * @param {{
 *   manifest?: import("./manifest.js").RunManifest,
 *   manifestSha?: string,
 *   claimedAt?: string|number|Date,
 * }} spec
 * @returns {Promise<ManifestAttestation>}
 */
export async function buildAttestation(spec = {}) {
  const sha = String(
    spec.manifestSha ?? (spec.manifest ? await manifestDigest(spec.manifest) : "")
  ).trim();
  if (!DIGEST_RE.test(sha)) {
    throw new Error(
      "attestation: needs the manifest's SHA-256 digest as 64 lowercase hex " +
        `characters (got ${sha ? JSON.stringify(sha) : "nothing"}) — pass the ` +
        "manifest itself and it will be digested"
    );
  }
  return {
    v: ATTESTATION_VERSION,
    kind: /** @type {"basilisk.manifest-attestation"} */ (ATTESTATION_KIND),
    manifest: sha,
    // The attester's claim, not a fact. See the module header before treating
    // this as ordering evidence.
    claimedAt: isoTimestamp(spec.claimedAt),
  };
}

/**
 * Canonical bytes of an attestation — what gets signed.
 * @param {ManifestAttestation} attestation
 * @returns {string}
 */
export function attestationToJson(attestation) {
  return canonicalJson(attestation);
}

/**
 * Parse an attestation out of text, tolerating an OpenPGP cleartext wrapper.
 *
 * `unwrapCleartext` is the receipt's, parameterised on the noun — one answer to
 * "which bytes were signed", for all three documents.
 *
 * Refuses any field outside `ATTESTATION_FIELDS`. A document with a `signer`,
 * an `fpr` or a `note` on it is not a stricter attestation, it is a different
 * document that has grown somewhere to hide a fingerprint, and reading it as
 * this one would let that field ride out under a signature this module vouched
 * for.
 *
 * @param {string} text
 * @returns {ManifestAttestation}
 */
export function parseAttestation(text) {
  const body = unwrapCleartext(text, "attestation");
  /** @type {*} */
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (_) {
    throw new Error("attestation: not JSON (expected a Basilisk manifest attestation)");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("attestation: not a Basilisk manifest attestation");
  }
  if (parsed.kind !== ATTESTATION_KIND) {
    throw new Error("attestation: not a Basilisk manifest attestation");
  }
  if (Number(parsed.v) !== ATTESTATION_VERSION) {
    throw new Error(`attestation: unsupported version ${parsed.v}`);
  }
  const extra = Object.keys(parsed).filter((k) => !ATTESTATION_FIELDS.includes(k));
  if (extra.length) {
    throw new Error(
      `attestation: unexpected field${extra.length === 1 ? "" : "s"} ` +
        `${extra.sort().join(", ")} — an attestation carries a manifest digest ` +
        "and a claimed time and nothing else, so that it has nowhere to carry a " +
        "fingerprint. The signature says who signed it."
    );
  }
  if (!DIGEST_RE.test(String(parsed.manifest ?? ""))) {
    throw new Error(
      "attestation: manifest must be a SHA-256 digest as 64 lowercase hex characters"
    );
  }
  return /** @type {ManifestAttestation} */ (parsed);
}

/**
 * Does this set of attestations cover this manifest?
 *
 * Reports in `mismatchLog()`'s `{path, field, expected, actual}` vocabulary, the
 * same one `compareReceipts` and `manifestHonouredBy` use, because "two
 * descriptions of a run do not match, here" is one idea and deserves one
 * spelling. `expected` is always this manifest's side; `actual` is always the
 * attestation's.
 *
 * Both directions, as `checkInputs` does for pinned inputs. A missing attester
 * is the obvious lie; an attester who is not in the room is the one a
 * count-them check waves through, and a room of two where a third signed is a
 * different room.
 *
 * **Read `caveats` before trusting `ok`.** A `true` here means *these
 * attestations are over this manifest, and the expected set is covered*. It does
 * not mean anyone signed before the run, and if no `by` was supplied it does not
 * mean anyone was authenticated at all.
 *
 * @param {import("./manifest.js").RunManifest} manifest
 * @param {AttestationEntry[]} entries
 * @param {{ expect?: string[] }} [opts]  peer labels required; defaults to the
 *   manifest's own `peers`
 * @returns {Promise<{
 *   ok: boolean,
 *   mismatches: import("./receipt.js").ReceiptMismatch[],
 *   checked: number,
 *   digest: string,
 *   attested: string[],
 *   missing: string[],
 *   caveats: string[],
 * }>}
 */
export async function manifestAttestedBy(manifest, entries = [], opts = {}) {
  const log = mismatchLog();
  const digest = await manifestDigest(manifest);
  const expect = [...new Set((opts.expect ?? manifest?.peers ?? []).map(String))].sort();

  /** @type {Set<string>} */
  const seen = new Set();
  let unattributed = 0;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i] || {};
    const a = /** @type {*} */ (entry.attestation);
    const by = String(entry.by ?? "").trim();
    const where = by ? `attestation from ${by}` : `attestation ${i + 1}`;
    log.compare(where, "kind", ATTESTATION_KIND, a?.kind);
    log.compare(where, "v", ATTESTATION_VERSION, a?.v);
    log.compare(where, "manifest", digest, a?.manifest);
    if (!by) {
      unattributed++;
      continue;
    }
    // Only an attestation that is over *this* manifest counts as covering it.
    // Anything else has already been reported above; counting it here as well
    // would let a signature over yesterday's manifest fill today's slot.
    if (a?.kind === ATTESTATION_KIND && String(a?.manifest ?? "") === digest) {
      seen.add(by);
    }
  }

  for (const label of expect) {
    if (seen.has(label)) continue;
    log.note(`peer ${label}`, "attestation", `an attestation over ${digest}`, "");
  }
  if (expect.length) {
    for (const by of [...seen].sort()) {
      if (expect.includes(by)) continue;
      log.note(`attestation from ${by}`, "unlisted", "", by);
    }
  }

  /** @type {string[]} */
  const caveats = [
    "an attestation is evidence its signer saw this digest, never evidence of " +
      "when — the ordering it supports is mutual among the participants, not a " +
      "fact a third party can check (see lib/toolkit/attest.js)",
  ];
  if (!expect.length) {
    caveats.push(
      "the manifest lists no peers and none were expected, so coverage is " +
        "vacuous — this says the attestations are over this manifest, not that " +
        "everyone attested"
    );
  }
  if (unattributed) {
    caveats.push(
      `${unattributed} attestation${unattributed === 1 ? "" : "s"} arrived with ` +
        "no attester — no signature was checked, so they count toward nothing"
    );
  }

  return {
    ...log.result(),
    digest,
    attested: [...seen].sort(),
    missing: expect.filter((label) => !seen.has(label)),
    caveats,
  };
}

/**
 * A one-line human summary, for a status line or a tile.
 * @param {Awaited<ReturnType<typeof manifestAttestedBy>>} result
 * @returns {string}
 */
export function summarizeAttestation(result) {
  if (result.ok) {
    const n = result.attested.length;
    return (
      `manifest attested — ${n} ${n === 1 ? "attester" : "attesters"}, ` +
      `${result.checked} facts checked, and nothing here says when`
    );
  }
  const first = result.mismatches[0];
  const rest = result.mismatches.length - 1;
  return `manifest not attested at ${first.path} (${first.field})${
    rest > 0 ? ` and ${rest} more` : ""
  }`;
}
