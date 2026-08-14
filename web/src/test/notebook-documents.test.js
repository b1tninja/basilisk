/**
 * The document checks the session leans on, tested where they can be pushed.
 *
 * The weight is entirely on the refusals. A verifier that only ever says yes
 * proves nothing, and the one this module exists for is the yes that *looks*
 * right: a signature that verifies perfectly, against a key that is not the
 * peer's. `verify()` handed the whole room's keys says "valid" for a document
 * any member signed — so the negative case here is not a corrupt signature, it
 * is a **good** signature from the wrong member.
 *
 * `notebook-session-documents.test.js` runs the same refusals over two live
 * meshed sessions. This file is the unit underneath them, so a failure says
 * whether the check is wrong or the wiring is.
 *
 * A run manifest is signed here as *text*, because `verifySignedBy` takes text
 * and a manifest is a real document this product produces. It is no longer a
 * document this channel carries — see `documents.js`'s header — so there is no
 * `readSignedManifest` to test, and the parses below are the two documents that
 * do travel.
 */
import { generateKey } from "openpgp";
import { describe, expect, it } from "vitest";
import {
  MAX_DOCUMENT_BYTES,
  assertDocumentFits,
  documentByteLength,
  looksCleartextSigned,
  readSignedAttestation,
  verifySignedBy,
} from "../lib/notebook/documents.js";
import { signOpenPgp } from "../lib/pgp/sign.js";
import { buildAttestation, attestationToJson } from "../lib/toolkit/attest.js";
import {
  buildRunManifest,
  manifestDigest,
  manifestToJson,
} from "../lib/toolkit/manifest.js";

/**
 * @param {string} email
 * @returns {Promise<{ fpr: string, key: import("openpgp").Key,
 *   privateKey: import("openpgp").PrivateKey }>}
 */
async function identity(email) {
  const { publicKey, privateKey } = await generateKey({
    type: "ecc",
    curve: "curve25519Legacy",
    userIDs: [{ email }],
    format: "object",
  });
  return {
    fpr: publicKey.getFingerprint().toUpperCase(),
    key: publicKey,
    privateKey,
  };
}

const ALICE = await identity("alice@documents.test");
const MALLORY = await identity("mallory@documents.test");

/**
 * @param {string} text
 * @param {import("openpgp").PrivateKey} privateKey
 */
async function cleartext(text, privateKey) {
  const { armored } = await signOpenPgp(text, [privateKey], "cleartext");
  return armored;
}

const MANIFEST = await buildRunManifest({
  title: "Thursday key ceremony",
  recipeSource: "bytes deadbeef | encode hex | out $a",
  cells: [{ index: 0, recipe: "bytes deadbeef | encode hex | out $a" }],
  peers: { mara: "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9" },
});
const MANIFEST_SHA = await manifestDigest(MANIFEST);

/* ─────────────────────────── signed by *this* peer ─────────────────────── */

describe("a document is checked against the sender's key and no other", () => {
  it("accepts the sender's own signature and hands back the bytes it covers", async () => {
    const signed = await cleartext(manifestToJson(MANIFEST), ALICE.privateKey);
    const text = await verifySignedBy(signed, { key: ALICE.key, fpr: ALICE.fpr });
    // The bytes OpenPGP hashed, not a second unwrapping of the armor.
    expect(JSON.parse(text)).toEqual(MANIFEST);
  });

  it("refuses a perfectly good signature made by somebody else", async () => {
    // Not a forgery, not corruption: Mallory signed this and the signature is
    // valid. It is simply not Alice's, and this session believes it is talking
    // to Alice. This is the case a `verificationKeys: [...everyone]` call waves
    // through.
    const signed = await cleartext(manifestToJson(MANIFEST), MALLORY.privateKey);
    await expect(
      verifySignedBy(signed, { key: ALICE.key, fpr: ALICE.fpr })
    ).rejects.toThrow(/not signed by that peer/);
    // …and the same bytes verify fine against the key that did sign them, so
    // the refusal above is about attribution rather than about a bad signature.
    await expect(
      verifySignedBy(signed, { key: MALLORY.key, fpr: MALLORY.fpr })
    ).resolves.toContain("basilisk.run-manifest");
  });

  it("refuses a key filed under a fingerprint that is not its own", async () => {
    // The keyserver lookup already keys its map by what each key says about
    // itself; this is the second lock on that door.
    const signed = await cleartext(manifestToJson(MANIFEST), MALLORY.privateKey);
    await expect(
      verifySignedBy(signed, { key: MALLORY.key, fpr: ALICE.fpr })
    ).rejects.toThrow(/not this peer's/);
  });

  it("refuses when no key is held for the sender, rather than skipping the check", async () => {
    const signed = await cleartext(manifestToJson(MANIFEST), ALICE.privateKey);
    await expect(
      verifySignedBy(signed, { key: undefined, fpr: ALICE.fpr })
    ).rejects.toThrow(/no public key is held/);
  });

  it("refuses a body edited inside its own signature", async () => {
    const signed = await cleartext(manifestToJson(MANIFEST), ALICE.privateKey);
    const tampered = signed.replace("Thursday key ceremony", "Thursday key cerembny");
    expect(tampered).not.toBe(signed);
    await expect(
      verifySignedBy(tampered, { key: ALICE.key, fpr: ALICE.fpr })
    ).rejects.toThrow(/not signed by that peer/);
  });

  it("refuses an unsigned document and a detached signature alike", async () => {
    await expect(
      verifySignedBy(manifestToJson(MANIFEST), { key: ALICE.key, fpr: ALICE.fpr })
    ).rejects.toThrow(/not an OpenPGP cleartext-signed document/);

    const { armored, detached } = await signOpenPgp(
      manifestToJson(MANIFEST),
      [ALICE.privateKey],
      "detached"
    );
    expect(detached).toBe(true);
    // A detached signature is two objects and this frame carries one.
    await expect(
      verifySignedBy(armored, { key: ALICE.key, fpr: ALICE.fpr })
    ).rejects.toThrow(/not an OpenPGP cleartext-signed document/);
  });
});

/* ──────────────────────────── parse after verify ────────────────────────── */

describe("a verified document is then read as the document it claims to be", () => {
  it("names the same digest whichever way the manifest behind it was serialised", async () => {
    // The digest is over canonical JSON, which is what makes an attestation
    // over "the manifest" mean something when two peers pretty-printed theirs
    // differently — and it is the whole reason the manifest itself does not
    // have to travel for the two ends to be talking about one document.
    const pretty = JSON.parse(JSON.stringify(MANIFEST, null, 2));
    const signed = await cleartext(
      attestationToJson(await buildAttestation({ manifest: pretty })),
      ALICE.privateKey
    );
    const { digest } = await readSignedAttestation(signed, {
      key: ALICE.key,
      fpr: ALICE.fpr,
    });
    expect(digest).toBe(MANIFEST_SHA);
  });

  it("parses an attestation and reports the digest it names", async () => {
    const attestation = await buildAttestation({ manifestSha: MANIFEST_SHA });
    const signed = await cleartext(attestationToJson(attestation), ALICE.privateKey);
    const read = await readSignedAttestation(signed, {
      key: ALICE.key,
      fpr: ALICE.fpr,
    });
    expect(read.digest).toBe(MANIFEST_SHA);
    expect(read.attestation.kind).toBe("basilisk.manifest-attestation");
  });

  it("refuses a signed attestation carrying a field it may not carry", async () => {
    // `parseAttestation`'s closed field list is the no-fingerprints rule as a
    // shape, and this is the one path where a remote peer picks the bytes. The
    // signature is Alice's and valid; the document is still refused.
    const smuggled = JSON.stringify({
      v: 1,
      kind: "basilisk.manifest-attestation",
      manifest: MANIFEST_SHA,
      claimedAt: new Date(0).toISOString(),
      signer: "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9",
    });
    await expect(
      readSignedAttestation(await cleartext(smuggled, ALICE.privateKey), {
        key: ALICE.key,
        fpr: ALICE.fpr,
      })
    ).rejects.toThrow(/unexpected field signer/);
  });

  it("refuses a signed document of the wrong kind", async () => {
    // A run manifest, signed by the right peer, arriving where an attestation
    // is expected. The `kind` discriminator is what stops one being read as the
    // other, and it matters more now that only one of the two travels.
    const signed = await cleartext(manifestToJson(MANIFEST), ALICE.privateKey);
    await expect(
      readSignedAttestation(signed, { key: ALICE.key, fpr: ALICE.fpr })
    ).rejects.toThrow(/not a Basilisk manifest attestation/);
  });

  it("refuses signed nonsense without throwing anything but an Error", async () => {
    const signed = await cleartext("not json at all", ALICE.privateKey);
    await expect(
      readSignedAttestation(signed, { key: ALICE.key, fpr: ALICE.fpr })
    ).rejects.toThrow(/attestation: not JSON/);
  });
});

/* ───────────────────────────────── size ────────────────────────────────── */

describe("an oversized document is refused, never truncated", () => {
  it("measures UTF-8 bytes rather than characters", () => {
    expect(documentByteLength("abc")).toBe(3);
    // A recipe comment can hold anything a keyboard can type, and a ceiling
    // counted in JS string units would let a multi-byte document through at
    // three times the size.
    expect(documentByteLength("🜁")).toBe(4);
  });

  it("accepts a document exactly at the ceiling and refuses one byte more", () => {
    const atCap = "a".repeat(MAX_DOCUMENT_BYTES);
    expect(assertDocumentFits(atCap, "manifest")).toBe(MAX_DOCUMENT_BYTES);
    expect(() => assertDocumentFits(`${atCap}a`, "manifest")).toThrow(
      /refused whole/
    );
  });

  it("refuses an oversized arrival before OpenPGP is asked to parse it", async () => {
    // Deliberately *not* signed, and deliberately not a legal document either:
    // the size check has to come first, or an attacker's ceiling is however
    // much armor OpenPGP will chew through. An honest attestation is four
    // fields and can never reach this, which is exactly why the sender's
    // ceiling cannot be the only one.
    await expect(
      readSignedAttestation("a".repeat(MAX_DOCUMENT_BYTES + 1), {
        key: ALICE.key,
        fpr: ALICE.fpr,
      })
    ).rejects.toThrow(new RegExp(`ceiling for a document on this channel is ${MAX_DOCUMENT_BYTES}`));
  });

  it("leaves room for the frame that carries it inside a 64 KiB SCTP message", () => {
    // The derivation in the header, asserted rather than asserted-in-prose:
    // armor → JSON escape → AES-GCM → base64 → frame, against the message size
    // RFC 8831 requires every stack to accept.
    const body = JSON.stringify({
      kind: "notebook",
      doc: "a".repeat(MAX_DOCUMENT_BYTES),
      ts: Date.now(),
    });
    const framed = Math.ceil((documentByteLength(body) + 28) / 3) * 4 + 32;
    expect(framed).toBeLessThan(65536);
  });
});

/* ─────────────────────────────── the shape ─────────────────────────────── */

describe("only an already-signed document is recognised as one", () => {
  it("tells a cleartext-signed document from raw JSON", async () => {
    expect(looksCleartextSigned(manifestToJson(MANIFEST))).toBe(false);
    expect(looksCleartextSigned("")).toBe(false);
    expect(
      looksCleartextSigned(await cleartext(manifestToJson(MANIFEST), ALICE.privateKey))
    ).toBe(true);
  });
});
