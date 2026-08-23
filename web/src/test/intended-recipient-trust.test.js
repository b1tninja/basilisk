/**
 * The Intended Recipient Fingerprint is worth what the signature covering it is.
 *
 * Subpacket 35 (RFC 9580 §5.2.3.36 / §13.12) names who a signer meant a message
 * for, and comparing it against the key that opened the message is what detects
 * **surreptitious forwarding**: Mallory takes Alice's message signed to Bob,
 * re-encrypts it to Carol, and Carol reads a good signature from Alice as
 * though Alice had written to her.
 *
 * That defence turns entirely on *where the subpacket was*. A signature's
 * hashed area is covered by the signature; the unhashed area is not, and can be
 * added to, altered, or stripped by anyone handling the message without
 * disturbing verification at all.
 *
 * ## How openpgp.js sorts the two, which is not obvious
 *
 * There is no `hashedSubpackets` array. `readSubPacket(bytes, hashed)` pushes
 * every unhashed subpacket into `unhashedSubpackets` and then **returns early**
 * for any type outside `allowedUnhashedSubpackets` — issuer key id, issuer
 * fingerprint, embedded signature. Type 35 is not one of those, so it reaches
 * the `default:` arm, and therefore `unknownSubpackets`, **only when it arrived
 * hashed**.
 *
 * So `unknownSubpackets` is the protected area and `unhashedSubpackets` is not,
 * and the two must not be unioned. This file exists because they were.
 */
import { describe, expect, it } from "vitest";
import {
  SUBPACKET_INTENDED_RECIPIENT,
  checkIntendedRecipient,
  intendedRecipientsFromSigPacket,
} from "../lib/pgp/intended-recipient.js";

const CAROL = "00112233445566778899AABBCCDDEEFF00112233";
const BOB = "AABBCCDDEEFF00112233445566778899AABBCCDD";

/** A subpacket-35 body: one version byte, then twenty fingerprint bytes. */
function irfBody(fpr) {
  const body = new Uint8Array(21);
  body[0] = 4;
  const octets = fpr.match(/../g);
  for (let i = 0; i < 20; i++) body[i + 1] = parseInt(octets[i], 16);
  return body;
}

/** What openpgp.js hands back for a subpacket 35 that arrived **hashed**. */
const signedClaim = (fpr) => ({
  unknownSubpackets: [{ type: SUBPACKET_INTENDED_RECIPIENT, body: irfBody(fpr) }],
});

/** What anyone at all can bolt on without touching the signature. */
const unsignedClaim = (fpr) => ({
  unhashedSubpackets: [{ type: SUBPACKET_INTENDED_RECIPIENT, body: irfBody(fpr) }],
});

describe("only the signed half of a signature makes a claim", () => {
  it("finds the reader it is measuring", () => {
    // An empty sweep passes every assertion below it: if the reader stopped
    // recognising the subpacket entirely, every "rejects" test would pass for
    // the wrong reason.
    expect(
      intendedRecipientsFromSigPacket(signedClaim(BOB)),
      "the reader no longer recognises a conforming subpacket 35"
    ).toEqual([BOB]);
  });

  it("ignores a fingerprint that is only in the unhashed area", () => {
    // The forgery, in one line. Nothing signs the unhashed area, so Mallory
    // appends this to Alice's signature, the signature still verifies, and the
    // union that used to be here reported it as Alice's own statement.
    expect(
      intendedRecipientsFromSigPacket(unsignedClaim(CAROL)),
      "an unsigned fingerprint was reported as the signer's claim"
    ).toEqual([]);
  });

  it("does not let an unsigned fingerprint join a signed one", () => {
    // The sharper version: the signer really did address this to Bob, and
    // Mallory adds Carol beside it rather than replacing her. A union answers
    // `ok` for Carol's key while Alice never named it.
    const both = {
      ...signedClaim(BOB),
      ...unsignedClaim(CAROL),
    };
    const seen = intendedRecipientsFromSigPacket(both);
    expect(seen).toEqual([BOB]);
    expect(checkIntendedRecipient(seen, CAROL).status).toBe("mismatch");
  });

  it("still detects the forwarding it exists to detect", () => {
    // Alice signed to Bob; Carol's key opened it. That is the whole point, and
    // it must survive the tightening above.
    const seen = intendedRecipientsFromSigPacket(signedClaim(BOB));
    expect(checkIntendedRecipient(seen, CAROL).status).toBe("mismatch");
    expect(checkIntendedRecipient(seen, BOB).status).toBe("ok");
  });
});

describe("a fingerprint is compared whole", () => {
  it("refuses a suffix of the fingerprint it is checked against", () => {
    // Was `i.endsWith(fpr) || fpr.endsWith(i)`, so this answered `ok`. It is
    // the short-key-id problem in the one comparison that decides whether a
    // signed message was addressed to this key.
    for (const truncated of [CAROL.slice(-16), CAROL.slice(-8), CAROL.slice(20)]) {
      expect(
        checkIntendedRecipient([CAROL], truncated).status,
        `a ${truncated.length}-character tail satisfied a 40-character claim`
      ).toBe("mismatch");
    }
  });

  it("refuses a fingerprint the claim is merely a suffix of", () => {
    // The other direction of the same weakened test.
    expect(checkIntendedRecipient([CAROL.slice(-16)], CAROL).status).toBe("mismatch");
  });

  it("accepts the whole fingerprint, in either case", () => {
    expect(checkIntendedRecipient([CAROL], CAROL).status).toBe("ok");
    expect(checkIntendedRecipient([CAROL], CAROL.toLowerCase()).status).toBe("ok");
  });

  it("says nothing when the signer made no claim", () => {
    // Most messages carry no subpacket. `absent` is "no claim made", not a
    // failed one — warning on the common case teaches people to ignore the
    // rare one.
    expect(checkIntendedRecipient([], CAROL).status).toBe("absent");
  });
});
