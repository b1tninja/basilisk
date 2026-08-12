/**
 * Two peers do not share a clock, and the mesh used to require that they did.
 *
 * OpenPGP verification is evaluated at an instant, and openpgp.js defaults that
 * instant to `new Date()`. A signature stamped later than the verifier's clock
 * is refused outright — **one second was enough**, which is what the first test
 * below pins. Between two real machines that is not an attack, it is ordinary
 * skew, and the person whose clock ran fast could not join a session with
 * anybody: their envelopes were dropped and the failure reached the other end
 * as a peer who never arrived.
 *
 * It was found from the other direction. `quorum-key-confirmation.e2e.js` failed
 * intermittently for weeks with nothing to read; once the tunnel learned to name
 * what it could not open, one run said "mailbox could not open a posted
 * envelope: Signature creation time is in the future". In the suite signer and
 * verifier are the same machine, so the skew was sub-second and the two
 * timestamps merely landed either side of a tick — a rounding boundary standing
 * in for a defect that between real peers is seconds wide.
 *
 * The fix is a bounded tolerance, `SIGNATURE_FUTURE_TOLERANCE_MS`, applied by
 * verifying as of now-plus-tolerance. It is a security parameter — the same
 * number is how far a signer may postdate before anyone notices — so the second
 * test is as load-bearing as the first: a signature far enough ahead is still
 * refused. The check is relaxed, never disabled.
 */
import { createCleartextMessage, createMessage, encrypt, generateKey, sign } from "openpgp";
import { beforeAll, describe, expect, it } from "vitest";
import {
  SIGNATURE_FUTURE_TOLERANCE_MS,
  openSignalingEnvelope,
} from "../lib/notebook/crypto.js";
import { verifySignedBy } from "../lib/notebook/documents.js";

const SECOND = 1000;

/** @type {any} */
let alice;
/** @type {any} */
let bob;
let aliceFpr = "";
let bobFpr = "";
/** @type {Map<string, any>} */
let keyByFpr = new Map();

beforeAll(async () => {
  const ecc = {
    /** @type {"ecc"} */ type: "ecc",
    /** @type {"curve25519Legacy"} */ curve: "curve25519Legacy",
    /** @type {"object"} */ format: "object",
  };
  [alice, bob] = await Promise.all([
    generateKey({ ...ecc, userIDs: [{ email: "alice@skew.test" }] }),
    generateKey({ ...ecc, userIDs: [{ email: "bob@skew.test" }] }),
  ]);
  aliceFpr = alice.publicKey.getFingerprint().toUpperCase();
  bobFpr = bob.publicKey.getFingerprint().toUpperCase();
  keyByFpr = new Map([
    [aliceFpr, alice.publicKey],
    [bobFpr, bob.publicKey],
  ]);
});

/**
 * An envelope Alice signed at `date` — the seam a fast clock creates. The real
 * `sealSignalingEnvelope` always stamps "now", so the creation time is set here
 * rather than by moving the process clock.
 * @param {Date} date
 */
async function envelopeSignedAt(date) {
  const payload = {
    v: 1,
    type: "hello",
    from: aliceFpr,
    to: bobFpr,
    roomId: "ROOM",
    ts: Date.now(),
  };
  return encrypt({
    message: await createMessage({ text: JSON.stringify(payload) }),
    encryptionKeys: [alice.publicKey, bob.publicKey],
    signingKeys: alice.privateKey,
    format: "armored",
    date,
  });
}

/** Bob opening what Alice sent. */
const bobOpens = (armored) =>
  openSignalingEnvelope({
    armored,
    decryptionKey: bob.privateKey,
    audienceKeyByFpr: keyByFpr,
    audienceFprs: [aliceFpr, bobFpr],
    expectedRoomId: "ROOM",
  });

describe("a signalling envelope from a peer whose clock runs fast", () => {
  it("opened at all — the case that used to fail one second out", async () => {
    // The regression, at the smallest size that showed it. Before the
    // tolerance this threw "Signature creation time is in the future" and the
    // peer simply never meshed.
    const { payload, signerFpr } = await bobOpens(
      await envelopeSignedAt(new Date(Date.now() + 1 * SECOND))
    );
    expect(signerFpr).toBe(aliceFpr);
    expect(payload.type).toBe("hello");
  });

  it("opens across the whole span the tolerance claims to cover", async () => {
    // Sampled inside the window rather than at one point, so a tolerance that
    // was quietly narrowed would show up here and not only at the edge.
    for (const ahead of [3, 20, 45]) {
      const { signerFpr } = await bobOpens(
        await envelopeSignedAt(new Date(Date.now() + ahead * SECOND))
      );
      expect(signerFpr, `${ahead}s ahead`).toBe(aliceFpr);
    }
  });

  it("still refuses one stamped an hour ahead", async () => {
    // The half that keeps this a tolerance and not a hole, and the hour is
    // **absolute on purpose**. Written as a multiple of the constant it would
    // scale with it, so widening the window to a year would leave this test
    // green — which is the failure mode a security parameter's own test must
    // not have. An hour is far outside any clock this is meant to forgive.
    const far = new Date(Date.now() + 3600 * SECOND);
    await expect(bobOpens(await envelopeSignedAt(far))).rejects.toThrow(
      /creation time is in the future/i
    );
  });

  it("states its tolerance as a bounded number of seconds", () => {
    // Pinned because the argument for the number is written beside it: big
    // enough for two unsynchronised consumer clocks, small enough to sit well
    // inside the 300 s life of the relay token the same peer needs anyway.
    // Changing it should mean re-reading that argument, not editing a test.
    expect(SIGNATURE_FUTURE_TOLERANCE_MS).toBe(60 * SECOND);
    expect(SIGNATURE_FUTURE_TOLERANCE_MS).toBeLessThan(300 * SECOND);
  });
});

describe("a signed document from a peer whose clock runs fast", () => {
  const BODY = '{"v":1,"kind":"manifest"}';

  /** A cleartext-signed manifest, stamped at `date`. */
  const manifestSignedAt = async (date) =>
    sign({
      message: await createCleartextMessage({ text: BODY }),
      signingKeys: alice.privateKey,
      format: "armored",
      date,
    });

  const bobReads = (signed) =>
    verifySignedBy(signed, { key: alice.publicKey, fpr: aliceFpr, what: "manifest" });

  it("is read, not dropped, when it is a few seconds ahead", async () => {
    // The same exposure one layer up: a manifest, an attestation, a handoff
    // offer and a cell result are all signed by a peer and sent in the same
    // breath, so they meet the same clock. Fixed together for that reason.
    expect(await bobReads(await manifestSignedAt(new Date(Date.now() + 5 * SECOND)))).toBe(
      BODY
    );
  });

  it("is still refused when it is stamped an hour ahead", async () => {
    const far = new Date(Date.now() + 3600 * SECOND);
    // The refusal here is "not signed by that peer" rather than a clock
    // message: `verifySignedBy` deliberately does not tell a remote peer which
    // way their signature failed. What matters is that it still fails.
    await expect(bobReads(await manifestSignedAt(far))).rejects.toThrow();
  });
});
