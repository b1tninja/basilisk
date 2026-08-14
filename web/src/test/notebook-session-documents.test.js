/**
 * Two live sessions carrying a signed attestation between them.
 *
 * Nothing is stubbed: real OpenPGP keys, real signed and encrypted signalling,
 * real ECDH, real key confirmation, real pairwise AES frames. What is under
 * test is the courier — that a document the user chose to sign reaches the
 * other end intact, and that everything else is refused at the door.
 *
 * **The run manifest used to cross here too, and does not.** Both ends derive
 * it from the notebook text, the title and the roster, deterministically, so a
 * delivered one is a document the receiver could already compute; the signature
 * over its digest is the part that cannot be derived, and that document is the
 * attestation. See `session.js`'s header for the argument and `documents.js`'s
 * for what went with it.
 *
 * The refusals are the point, and each one is written so it *fires*:
 *
 * - a document from a peer whose key is not confirmed is dropped, silently and
 *   without being queued;
 * - a document signed by a key that is not the sender's is refused loudly, even
 *   though the signature itself is perfectly good — that is the replay a
 *   `verify against everyone` check accepts;
 * - a malformed document is one frame going nowhere, not a dead session;
 * - a document over the ceiling is refused whole, on both ends.
 *
 * Every case ends by putting a chat message through the same channel, because
 * `kc` and `chat` are the transport this whole feature stands on and a
 * regression there is worse than not shipping.
 */
import { generateKey } from "openpgp";
import { afterEach, describe, expect, it } from "vitest";
import {
  MAX_DOCUMENT_BYTES,
  looksCleartextSigned,
} from "../lib/notebook/documents.js";
import { encryptSessionPayload } from "../lib/notebook/crypto.js";
import { signOpenPgp } from "../lib/pgp/sign.js";
import { attestationToJson, buildAttestation } from "../lib/toolkit/attest.js";
import { buildRunManifest, manifestDigest } from "../lib/toolkit/manifest.js";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;

afterEach(async () => {
  await pair?.stop();
  pair = null;
});

const SOURCE = "bytes deadbeef | encode hex | out $a";

/** @returns {Promise<import("../lib/toolkit/manifest.js").RunManifest>} */
function aManifest(title = "Thursday key ceremony") {
  return buildRunManifest({
    title,
    recipeSource: SOURCE,
    cells: [{ index: 0, recipe: SOURCE }],
    peers: { mara: "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9" },
  });
}

/**
 * @param {string} text
 * @param {import("openpgp").PrivateKey} privateKey
 */
async function cleartext(text, privateKey) {
  const { armored } = await signOpenPgp(text, [privateKey], "cleartext");
  return armored;
}

/**
 * A signed attestation over a digest, the way a person's recipe would make one.
 * @param {string} sha
 * @param {import("openpgp").PrivateKey} privateKey
 */
async function signedAttestation(sha, privateKey) {
  return cleartext(
    attestationToJson(await buildAttestation({ manifestSha: sha })),
    privateKey
  );
}

/** How many attestations one side has recorded against the other. */
function attestedBy(/** @type {any} */ side, /** @type {any} */ other) {
  return side.session.peers.get(other.fpr)?.attested ?? new Map();
}

/** A meshed pair, with both ends key-confirmed. */
async function meshed() {
  pair = await makeQuorumPair();
  await pair.start();
  const { creator, joiner } = pair;
  const ready = await until(
    () =>
      creator.session.peers.get(joiner.fpr)?.kcVerified === true &&
      joiner.session.peers.get(creator.fpr)?.kcVerified === true
  );
  expect(
    ready,
    `errors: ${[...creator.errors, ...joiner.errors].map((e) => e.message)}`
  ).toBe(true);
  return { creator, joiner };
}

/**
 * The channel still carries chat, both ways. Every case ends here.
 * @param {any} a
 * @param {any} b
 * @param {string} tag
 */
async function chatStillWorks(a, b, tag) {
  const before = b.chats.length;
  expect(await a.session.sendChatTo(b.fpr, tag)).toBe(1);
  await until(() => b.chats.length > before);
  expect(b.chats.at(-1).text).toBe(tag);
}

/* ─────────────────────────────── the happy path ─────────────────────────── */

describe("a signed attestation crosses the room", () => {
  it("arrives verified, and lands on the peer that signed it", async () => {
    const { creator, joiner } = await meshed();
    const sha = await manifestDigest(await aManifest());

    expect(await joiner.session.publishAttestation(
      await signedAttestation(sha, joiner.privateKey)
    )).toBe(1);
    await until(() => attestedBy(creator, joiner).size > 0);

    // The document, not just its digest: what the reader's coverage check
    // measures is the bytes the peer signed.
    const held = attestedBy(creator, joiner);
    expect([...held.keys()]).toEqual([sha]);
    expect(held.get(sha).kind).toBe("basilisk.manifest-attestation");
    expect(held.get(sha).manifest).toBe(sha);

    // Arriving changed nothing else. The creator did not answer with an
    // attestation of its own, and holds the key that could have.
    expect(attestedBy(joiner, creator).size).toBe(0);

    expect([...creator.errors, ...joiner.errors]).toEqual([]);
    await chatStillWorks(creator, joiner, "still talking");
  });

  it("announces it through the roster and no other path", async () => {
    const { creator, joiner } = await meshed();
    // The roster is the only notification the session offers for this, and it
    // has to carry the fact rather than announce that one is coming — the
    // projection the panel reads is built from the map handed to this callback.
    /** @type {number[]} */
    const attestedCounts = [];
    creator.session.onRoster = (/** @type {any} */ peers) => {
      attestedCounts.push(peers.get(joiner.fpr)?.attested.size ?? -1);
    };

    const sha = await manifestDigest(await aManifest());
    await joiner.session.publishAttestation(
      await signedAttestation(sha, joiner.privateKey)
    );
    await until(() => attestedCounts.includes(1));

    expect(attestedCounts).toContain(1);
    // Nothing on the session hands the document out beside the roster.
    expect("onAttestation" in creator.session).toBe(false);
    expect(typeof (/** @type {any} */ (creator.session).attestersOf)).toBe(
      "undefined"
    );
  });

  it("keeps the first document for a digest a peer attests to twice", async () => {
    const { creator, joiner } = await meshed();
    const sha = await manifestDigest(await aManifest());

    const first = await buildAttestation({
      manifestSha: sha,
      claimedAt: "2020-01-01T00:00:00.000Z",
    });
    await joiner.session.publishAttestation(
      await cleartext(attestationToJson(first), joiner.privateKey)
    );
    await until(() => attestedBy(creator, joiner).size > 0);

    const later = await buildAttestation({
      manifestSha: sha,
      claimedAt: "2030-01-01T00:00:00.000Z",
    });
    await joiner.session.publishAttestation(
      await cleartext(attestationToJson(later), joiner.privateKey)
    );
    await pair.settle();

    // One entry, and the one first seen. A peer re-attesting to the same digest
    // says nothing new, and letting the second replace the first would let them
    // walk their own claimed time forward under a reader's nose.
    const held = attestedBy(creator, joiner);
    expect(held.size).toBe(1);
    expect(held.get(sha).claimedAt).toBe("2020-01-01T00:00:00.000Z");
  });
});

/* ───────────────────── signed by *this* peer, over the wire ─────────────── */

describe("a document is believed only from the peer that signed it", () => {
  it("refuses one peer passing on another peer's signed attestation", async () => {
    const { creator, joiner } = await meshed();
    // The creator signs an attestation and the joiner hands that exact document
    // back to the creator as its own. Every signature involved is valid; the
    // only thing wrong is who is holding it out. This is the replay a
    // `verify against every key in the room` check accepts.
    const sha = await manifestDigest(await aManifest());
    const signed = await signedAttestation(sha, creator.privateKey);
    expect(await joiner.session.publishAttestation(signed)).toBe(1);
    await until(() => creator.errors.length > 0);
    await pair.settle();

    expect(creator.errors.map((e) => e.message).join("\n")).toMatch(
      /attestation from .+ refused — .*not signed by that peer/
    );
    expect(attestedBy(creator, joiner).size).toBe(0);
    await chatStillWorks(joiner, creator, "after the replay");
  });

  it("refuses an attestation signed by a key that is not in the room at all", async () => {
    const { creator, joiner } = await meshed();
    const outsider = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "outsider@quorum.test" }],
      format: "object",
    });
    const sha = await manifestDigest(await aManifest());
    await creator.session.publishAttestation(
      await signedAttestation(sha, outsider.privateKey)
    );
    await until(() => joiner.errors.length > 0);

    expect(attestedBy(joiner, creator).size).toBe(0);
    expect(joiner.errors.at(-1).message).toMatch(/not signed by that peer/);
    await chatStillWorks(creator, joiner, "after the outsider");
  });
});

/* ─────────────────────── before key confirmation: dropped ───────────────── */

describe("a document from an unconfirmed peer is dropped, not queued", () => {
  it("records nothing, reports nothing, and does not deliver it later either", async () => {
    const { creator, joiner } = await meshed();
    // The pairwise key still opens the frame — that is what makes this the
    // interesting case rather than an undecryptable one. What is missing is the
    // confirmation that says the far end is anyone in particular, which is
    // exactly the state `chat` refuses in.
    const peer = joiner.session.peers.get(creator.fpr);
    peer.kcVerified = false;
    expect(peer.sessionKey).toBeTruthy();

    const sha = await manifestDigest(await aManifest());
    const signed = await signedAttestation(sha, creator.privateKey);
    await creator.session.publishAttestation(signed);
    await pair.settle();

    expect(attestedBy(joiner, creator).size).toBe(0);
    expect(joiner.errors).toEqual([]);

    // Confirming afterwards does not flush a queue, because there is none. The
    // sender must say it again, which is the same rule chat lives under.
    peer.kcVerified = true;
    await pair.settle();
    expect(attestedBy(joiner, creator).size).toBe(0);

    expect(await creator.session.publishAttestation(signed)).toBe(1);
    await until(() => attestedBy(joiner, creator).size > 0);
    expect(attestedBy(joiner, creator).size).toBe(1);
  });

  it("writes to nobody when the sender has confirmed nobody", async () => {
    const { creator, joiner } = await meshed();
    creator.session.peers.get(joiner.fpr).kcVerified = false;
    const sha = await manifestDigest(await aManifest());
    const signed = await signedAttestation(sha, creator.privateKey);
    // A count, not a promise: the caller is told nobody heard it.
    expect(await creator.session.publishAttestation(signed)).toBe(0);
    await pair.settle();
    expect(attestedBy(joiner, creator).size).toBe(0);
  });
});

/* ──────────────────────────── malformed, not fatal ──────────────────────── */

describe("a malformed document does not take the session down", () => {
  it.each([
    ["signed nonsense", async (/** @type {any} */ k) => cleartext("{{{", k)],
    [
      "a signed document of the wrong kind",
      async (/** @type {any} */ k) =>
        cleartext(JSON.stringify(await aManifest()), k),
    ],
    [
      "an attestation with a field it may not carry",
      async (/** @type {any} */ k) =>
        cleartext(
          JSON.stringify({
            v: 1,
            kind: "basilisk.manifest-attestation",
            manifest: "a".repeat(64),
            claimedAt: new Date(0).toISOString(),
            fpr: "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9",
          }),
          k
        ),
    ],
  ])("survives %s", async (_name, make) => {
    const { creator, joiner } = await meshed();
    await creator.session.publishAttestation(await make(creator.privateKey));
    await until(() => joiner.errors.length > 0);

    expect(attestedBy(joiner, creator).size).toBe(0);
    expect(joiner.errors.at(-1)).toBeInstanceOf(Error);
    expect(joiner.session.peers.get(creator.fpr).kcVerified).toBe(true);
    await chatStillWorks(creator, joiner, "after the malformed one");
  });

  it("survives a payload whose document is not a string at all", async () => {
    const { creator, joiner } = await meshed();
    const peer = creator.session.peers.get(joiner.fpr);
    const body = JSON.stringify({
      kind: "attestation",
      doc: { nope: 1 },
      ts: Date.now(),
    });
    peer.channel.send(
      JSON.stringify({ v: 1, blob: await encryptSessionPayload(peer.sessionKey, body) })
    );
    await until(() => joiner.errors.length > 0);
    expect(attestedBy(joiner, creator).size).toBe(0);
    await chatStillWorks(creator, joiner, "after the object");
  });

  it("drops a manifest frame from a peer that still sends one", async () => {
    const { creator, joiner } = await meshed();
    // A peer running the build where the manifest still travelled. There is no
    // `manifest` kind here now, so the frame takes the same route every unknown
    // kind takes: nothing. Not an error — an unrecognised kind is a peer this
    // build does not speak to, and reporting one per frame would hand a remote
    // peer the error log.
    const peer = creator.session.peers.get(joiner.fpr);
    const body = JSON.stringify({
      kind: "manifest",
      doc: await cleartext(JSON.stringify(await aManifest()), creator.privateKey),
      ts: Date.now(),
    });
    peer.channel.send(
      JSON.stringify({ v: 1, blob: await encryptSessionPayload(peer.sessionKey, body) })
    );
    await pair.settle();

    expect(joiner.errors).toEqual([]);
    expect(attestedBy(joiner, creator).size).toBe(0);
    // Nothing on the peer record grew a slot for it either.
    expect("publishedManifest" in joiner.session.peers.get(creator.fpr)).toBe(false);
    await chatStillWorks(creator, joiner, "after the old kind");
  });
});

/* ──────────────────────────────── the ceiling ───────────────────────────── */

describe("an oversized document is refused rather than truncated", () => {
  it("fails in the author's hands, before anything is encrypted", async () => {
    const { creator, joiner } = await meshed();
    const huge = await cleartext("x".repeat(MAX_DOCUMENT_BYTES), creator.privateKey);
    await expect(creator.session.publishAttestation(huge)).rejects.toThrow(
      /refused whole/
    );
    await pair.settle();
    expect(attestedBy(joiner, creator).size).toBe(0);
    expect(joiner.errors).toEqual([]);
    await chatStillWorks(creator, joiner, "after the oversized send");
  });

  it("is refused on arrival too, whole, when a sender skips its own check", async () => {
    const { creator, joiner } = await meshed();
    // Straight onto the channel, past `publishAttestation` — a peer that does
    // not run this build is not bound by its send-side ceiling.
    const peer = creator.session.peers.get(joiner.fpr);
    const body = JSON.stringify({
      kind: "attestation",
      doc: "a".repeat(MAX_DOCUMENT_BYTES + 1),
      ts: Date.now(),
    });
    peer.channel.send(
      JSON.stringify({ v: 1, blob: await encryptSessionPayload(peer.sessionKey, body) })
    );
    await until(() => joiner.errors.length > 0);

    expect(joiner.errors.at(-1).message).toMatch(/refused whole/);
    // Nothing partial was kept.
    expect(attestedBy(joiner, creator).size).toBe(0);
    await chatStillWorks(creator, joiner, "after the oversized arrival");
  });
});

/* ─────────────────────────────── the courier rule ───────────────────────── */

describe("the session carries documents and does not sign them", () => {
  it("refuses to publish anything that is not already signed", async () => {
    const { creator, joiner } = await meshed();
    const sha = await manifestDigest(await aManifest());
    const raw = attestationToJson(await buildAttestation({ manifestSha: sha }));
    expect(looksCleartextSigned(raw)).toBe(false);
    await expect(creator.session.publishAttestation(raw)).rejects.toThrow(
      /does not sign on anyone's behalf/
    );
    await pair.settle();
    expect(attestedBy(joiner, creator).size).toBe(0);
  });

  it("does not answer an attestation it received with one of its own", async () => {
    const { creator, joiner } = await meshed();
    const sha = await manifestDigest(await aManifest());
    await creator.session.publishAttestation(
      await signedAttestation(sha, creator.privateKey)
    );
    await until(() => attestedBy(joiner, creator).size > 0);
    await pair.settle();

    // Receiving a claim is not making one. The joiner holds the private key
    // that could answer it, and nothing here reaches for it — attesting is a
    // press, one layer up.
    expect(attestedBy(creator, joiner).size).toBe(0);
  });
});
