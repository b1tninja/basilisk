/**
 * The two documents a notebook session carries between peers, and the checks
 * that must pass before either one is believed.
 *
 * **The session is a courier, not a signer.** A run manifest and a manifest
 * attestation are produced by recipes the user read before pressing Run —
 * `run.manifest | gpg.sign key=$me` and `input | run.attest | gpg.sign key=$me`.
 * Nothing in this module signs, and nothing in it can: no private key reaches
 * it and none is asked for. `approval-gate.js` states the rule this follows —
 * *"Grants are minted only by a human clicking, never by a param."* A manifest
 * minted by a transport is a commitment nobody made.
 *
 * Symmetrically, nothing here *runs* anything. A verified manifest is a parsed
 * object handed back to the caller, the same way `useNotebook.loadFromHash`
 * loads an `#r=` recipe without running it. Deciding what a promise means is
 * the reader's; this module only decides whether it is worth reading.
 *
 * ## "Signed by this peer", which is not "signed by some key"
 *
 * A session knows peers by **fingerprint**. An OpenPGP signature verifies
 * against a **key**. Conflating the two is the whole attack: `verify()` handed
 * every key in the room returns "valid" for a document any member signed, and a
 * caller that reads that as "the sender signed it" will accept peer B replaying
 * peer A's signed manifest as B's own commitment.
 *
 * The bridge is drawn so that it cannot be misread:
 *
 * 1. The caller says which fingerprint it believes it is talking to. In
 *    `session.js` that is the peer whose **pairwise session key decrypted the
 *    frame** — a key derived from a transcript bound to that fingerprint, the
 *    room, and both DTLS certificates, then confirmed end to end. There is no
 *    weaker claim available at that point.
 * 2. That fingerprint resolves to exactly one key, and the key is re-asked for
 *    its own fingerprint before it is used. `fetchAudienceKeys` already keys its
 *    map by what each key says about itself, so a keyserver that answers a
 *    lookup with somebody else's key lands it under the wrong fingerprint and
 *    the session refuses to start; this is the second lock on that door.
 * 3. `verify()` is given **that one key and nothing else**. A signature by any
 *    other member is then not a weaker match, it is an unverifiable one —
 *    OpenPGP cannot find the signing key at all. The comparison that could be
 *    got wrong is never made, because the material to get it wrong with is
 *    never in the room.
 *
 * ## One answer to "which bytes were signed"
 *
 * The document is parsed out of `CleartextMessage.getText()` — the same text
 * OpenPGP hashed — rather than out of the armor by a second unwrapper. Both
 * spellings exist (`unwrapCleartext` strips the wrapper by hand, for a document
 * pasted into a recipe with no key to check it against), and two answers to
 * "which bytes were signed" is the defect `manifest.js` warns about for
 * `canonicalJson`: they agree until the first edge case one of them learns
 * about alone — dash-escaping, a stray `\r`, trailing whitespace RFC 4880 says
 * is not part of the signed text — and then a signature vouches for bytes
 * nobody parsed.
 *
 * ## Size
 *
 * A manifest is unbounded in principle: it carries the notebook's whole recipe
 * source and every cell's text. The wire is not. See `MAX_DOCUMENT_BYTES`.
 *
 * @module lib/notebook/documents
 */

import { readCleartextMessage, verify } from "openpgp";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";
import { parseAttestation } from "../toolkit/attest.js";
import { manifestDigest, parseManifest } from "../toolkit/manifest.js";

/**
 * The largest signed document this session will send or accept, in bytes of
 * the armored text as it travels.
 *
 * **Where the number comes from.** A document rides the encrypted session frame
 * — the same `{ v, blob }` envelope as `kc` and `chat` — over a data channel.
 * RFC 8831 §6.6 requires every SCTP stack to accept a 64 KiB message; engines
 * negotiate more in practice and some historically offered far less, so 64 KiB
 * is the only ceiling that can be relied on without asking the transport, and
 * this layer deliberately does not ask it anything. Working back from there:
 * 32 KiB of armor, JSON-escaped into the payload (~×1.02), AES-GCM (+28 bytes),
 * base64 (×4/3) and the frame's own wrapper lands near 45 KiB — inside the
 * guarantee with room for the envelope to grow.
 *
 * **What happens at the boundary is refusal, never truncation.** A document is
 * one signed object; half of one is not a smaller commitment, it is a
 * signature over bytes that no longer exist. The sender is told before anything
 * is encrypted, so an oversized manifest fails in the author's hands rather
 * than in the room. The receiver drops the frame and reports it, before
 * OpenPGP is asked to parse an attacker-sized blob.
 *
 * **What to do with a notebook too big to commit to.** Nothing here chunks it,
 * because a chunked document is a reassembly buffer an unconfirmed peer can
 * fill. Split the notebook, or carry the manifest out of band and exchange only
 * attestations — which are four fields and never approach this.
 */
export const MAX_DOCUMENT_BYTES = 32768;

const encoder = new TextEncoder();

/**
 * @param {string} text
 * @returns {number} UTF-8 bytes
 */
export function documentByteLength(text) {
  return encoder.encode(String(text ?? "")).length;
}

/**
 * @param {string} text
 * @param {string} what  the noun for the error message
 * @returns {number} the size, when it fits
 */
export function assertDocumentFits(text, what = "document") {
  const bytes = documentByteLength(text);
  if (bytes > MAX_DOCUMENT_BYTES) {
    throw new Error(
      `notebook: ${what} is ${bytes} bytes and the ceiling for a document on ` +
        `this channel is ${MAX_DOCUMENT_BYTES} — refused whole, because half a ` +
        "signed document is a signature over bytes that no longer exist"
    );
  }
  return bytes;
}

/** The one form a carried document may take. See the module header. */
const CLEARTEXT_HEAD = /^-----BEGIN PGP SIGNED MESSAGE-----/;

/**
 * Is this text an OpenPGP cleartext-signed document at all?
 *
 * Cheap and structural, for the send path: it separates "the user piped
 * something through `gpg.sign`" from "the user piped raw JSON", and it is the
 * check that keeps `publishManifest` from becoming a place where an unsigned
 * document quietly acquires the room's trust on the strength of the channel it
 * arrived on.
 * @param {string} text
 * @returns {boolean}
 */
export function looksCleartextSigned(text) {
  return CLEARTEXT_HEAD.test(String(text ?? "").trim());
}

/** @param {string} fpr */
function short(fpr) {
  const f = normalizeFingerprintInput(fpr);
  return f ? `${f.slice(0, 8)}…` : "(none)";
}

/** @param {unknown} err */
function reason(err) {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Verify a cleartext-signed document against **one** peer's key, and hand back
 * the bytes that signature actually covers.
 *
 * Read the module header before changing the shape of this: `verificationKeys`
 * holding a single key is the mechanism, not an optimisation.
 *
 * @param {string} signed  armored cleartext-signed document
 * @param {object} opts
 * @param {import("openpgp").Key|undefined} opts.key  the sender's public key
 * @param {string} opts.fpr  the fingerprint the caller believes it is talking to
 * @param {string} [opts.what]  noun for error messages
 * @returns {Promise<string>} the signed text
 */
export async function verifySignedBy(signed, { key, fpr, what = "document" }) {
  const expected = normalizeFingerprintInput(fpr);
  if (!expected) {
    throw new Error(`notebook: cannot check a ${what} without a sender fingerprint`);
  }
  if (!key) {
    throw new Error(
      `notebook: no public key is held for ${short(expected)}, so a ${what} from ` +
        "them can be checked against nothing"
    );
  }
  // The key is asked what it is rather than trusted to be what it was filed
  // under. Step 2 of the bridge in the module header.
  const keyFpr = normalizeFingerprintInput(key.getFingerprint?.() || "");
  if (keyFpr !== expected) {
    throw new Error(
      `notebook: the key held for ${short(expected)} carries fingerprint ` +
        `${short(keyFpr)} — refusing to check a ${what} against a key that is ` +
        "not this peer's"
    );
  }

  /** @type {import("openpgp").CleartextMessage} */
  let clear;
  try {
    clear = await readCleartextMessage({ cleartextMessage: String(signed ?? "") });
  } catch (err) {
    throw new Error(
      `notebook: ${what} from ${short(expected)} is not an OpenPGP ` +
        `cleartext-signed document (${reason(err)}). A detached signature is two ` +
        "objects and this frame carries one; sign with the default cleartext form."
    );
  }

  const { signatures } = await verify({ message: clear, verificationKeys: [key] });
  if (!signatures?.length) {
    throw new Error(`notebook: ${what} from ${short(expected)} carries no signature`);
  }
  const keyIDs = key.getKeyIDs?.() || [];
  for (const sig of signatures) {
    try {
      await sig.verified;
    } catch (_) {
      // Wrong key, revoked key, expired binding, mangled body: every one of
      // them is "not this peer's signature", and none of them is worth telling
      // a remote peer apart from the others.
      continue;
    }
    // Redundant while `verificationKeys` holds one key, and written down so it
    // stays true if someone ever widens that list: a verified signature is only
    // this peer's if the key that verified it is this peer's, primary or subkey.
    if (!keyIDs.some((id) => id.equals?.(sig.keyID))) continue;
    // `getText()`, not the armor: the bytes OpenPGP hashed.
    return clear.getText();
  }
  throw new Error(
    `notebook: ${what} from ${short(expected)} is not signed by that peer. The ` +
      "signature may be perfectly good — it is not theirs, and a signature that " +
      "verifies against some key is not one that verifies against this one."
  );
}

/**
 * A verified run manifest, and the digest every attestation will name.
 *
 * The digest is `manifestDigest`'s — over the manifest's *canonical* JSON, not
 * over the bytes that arrived. That is deliberate and is what makes the two
 * documents join up: an attestation names a canonical digest, so two peers who
 * serialised the same manifest with different key order or indentation still
 * attest to the same thing, and any change to a field changes the digest.
 *
 * @param {string} signed
 * @param {{ key: import("openpgp").Key|undefined, fpr: string }} opts
 * @returns {Promise<{ manifest: import("../toolkit/manifest.js").RunManifest,
 *   digest: string, text: string }>}
 */
export async function readSignedManifest(signed, { key, fpr }) {
  assertDocumentFits(signed, "manifest");
  const text = await verifySignedBy(signed, { key, fpr, what: "manifest" });
  const manifest = parseManifest(text);
  return { manifest, digest: await manifestDigest(manifest), text };
}

/**
 * A verified manifest attestation, and the manifest digest it names.
 *
 * `parseAttestation` refuses any field beyond `v`/`kind`/`manifest`/`claimedAt`,
 * which is the no-fingerprints rule expressed as a shape. That refusal is worth
 * more here than anywhere: this is the one path on which a remote peer chooses
 * the bytes, and a `signer` field smuggled through would be a peer naming
 * somebody other than themselves on a document the session just authenticated.
 *
 * @param {string} signed
 * @param {{ key: import("openpgp").Key|undefined, fpr: string }} opts
 * @returns {Promise<{ attestation: import("../toolkit/attest.js").ManifestAttestation,
 *   digest: string, text: string }>}
 */
export async function readSignedAttestation(signed, { key, fpr }) {
  assertDocumentFits(signed, "attestation");
  const text = await verifySignedBy(signed, { key, fpr, what: "attestation" });
  const attestation = parseAttestation(text);
  return { attestation, digest: String(attestation.manifest), text };
}
