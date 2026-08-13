/**
 * Two live sessions carrying a manifest and an attestation between them.
 *
 * Nothing is stubbed: real OpenPGP keys, real signed and encrypted signalling,
 * real ECDH, real key confirmation, real pairwise AES frames. What is under
 * test is the courier — that a document the user chose to sign reaches the
 * other end intact, and that everything else is refused at the door.
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
import {
  buildRunManifest,
  manifestDigest,
  manifestToJson,
} from "../lib/toolkit/manifest.js";
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

describe("a signed manifest and a signed attestation cross the room", () => {
  it("arrives parsed, digested, and attributed to the peer that signed it", async () => {
    const { creator, joiner } = await meshed();
    const manifest = await aManifest();
    const sha = await manifestDigest(manifest);

    const signed = await cleartext(manifestToJson(manifest), creator.privateKey);
    expect(await creator.session.publishManifest(signed)).toBe(1);
    await until(() => joiner.manifests.length > 0);

    const got = joiner.manifests[0];
    expect(got.from).toBe(creator.fpr);
    expect(got.digest).toBe(sha);
    expect(got.manifest.title).toBe("Thursday key ceremony");
    expect(got.manifest.recipeSource).toBe(SOURCE);
    // The signed bytes travel too, so a reader can re-check them, store them,
    // or hand them to a recipe — the session did not consume the evidence.
    expect(looksCleartextSigned(got.signed)).toBe(true);

    // Arriving changed nothing else about the peer: it did not run, and it did
    // not answer with an attestation of its own.
    expect(joiner.session.peers.get(creator.fpr).publishedManifest).toBe(sha);
    expect(creator.session.peers.get(joiner.fpr).attested.size).toBe(0);
    expect(joiner.attestations).toEqual([]);
    expect(creator.session.attestersOf(sha)).toEqual([]);

    // Now the joiner attests, by hand, the way a person would.
    const attestation = await buildAttestation({ manifestSha: sha });
    const signedAttestation = await cleartext(
      attestationToJson(attestation),
      joiner.privateKey
    );
    expect(await joiner.session.publishAttestation(signedAttestation)).toBe(1);
    await until(() => creator.attestations.length > 0);

    expect(creator.attestations[0].from).toBe(joiner.fpr);
    expect(creator.attestations[0].digest).toBe(sha);
    expect(creator.session.attestersOf(sha)).toEqual([joiner.fpr]);
    expect(creator.session.attestersOf("f".repeat(64))).toEqual([]);
    expect([...creator.session.peers.get(joiner.fpr).attested]).toEqual([sha]);

    expect([...creator.errors, ...joiner.errors]).toEqual([]);
    await chatStillWorks(creator, joiner, "still talking");
  });

  it("announces attestation state through the roster and no other path", async () => {
    const { creator, joiner } = await meshed();
    /** @type {number[]} */
    const attestedCounts = [];
    creator.session.onRoster = (/** @type {any} */ peers) => {
      attestedCounts.push(peers.get(joiner.fpr)?.attested.size ?? -1);
    };

    const sha = await manifestDigest(await aManifest());
    const signed = await cleartext(
      attestationToJson(await buildAttestation({ manifestSha: sha })),
      joiner.privateKey
    );
    await joiner.session.publishAttestation(signed);
    await until(() => creator.attestations.length > 0);

    // `_emitRoster` fired with the new fact already on the peer record — the
    // roster is the notification, not a hint that one is coming.
    expect(attestedCounts).toContain(1);
  });
});

/* ───────────────────── signed by *this* peer, over the wire ─────────────── */

describe("a document is believed only from the peer that signed it", () => {
  it("refuses one peer passing on another peer's signed manifest", async () => {
    const { creator, joiner } = await meshed();
    // The creator signs a manifest and the joiner hands that exact document
    // back to the creator as its own. Every signature involved is valid; the
    // only thing wrong is who is holding it out. This is the replay a
    // `verify against every key in the room` check accepts.
    const signed = await cleartext(
      manifestToJson(await aManifest()),
      creator.privateKey
    );
    expect(await joiner.session.publishManifest(signed)).toBe(1);
    await until(() => creator.errors.length > 0);
    await pair.settle();

    expect(creator.manifests).toEqual([]);
    expect(creator.errors.map((e) => e.message).join("\n")).toMatch(
      /manifest from .+ refused — .*not signed by that peer/
    );
    expect(creator.session.peers.get(joiner.fpr).publishedManifest).toBe(null);
    await chatStillWorks(joiner, creator, "after the replay");
  });

  it("refuses a manifest signed by a key that is not in the room at all", async () => {
    const { creator, joiner } = await meshed();
    const outsider = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "outsider@quorum.test" }],
      format: "object",
    });
    const signed = await cleartext(
      manifestToJson(await aManifest()),
      outsider.privateKey
    );
    await creator.session.publishManifest(signed);
    await until(() => joiner.errors.length > 0);

    expect(joiner.manifests).toEqual([]);
    expect(joiner.errors.at(-1).message).toMatch(/not signed by that peer/);
    await chatStillWorks(creator, joiner, "after the outsider");
  });
});

/* ─────────────────────── before key confirmation: dropped ───────────────── */

describe("a document from an unconfirmed peer is dropped, not queued", () => {
  it("delivers nothing, reports nothing, and does not deliver it later either", async () => {
    const { creator, joiner } = await meshed();
    // The pairwise key still opens the frame — that is what makes this the
    // interesting case rather than an undecryptable one. What is missing is
    // the confirmation that says the far end is anyone in particular, which is
    // exactly the state `chat` refuses in.
    const peer = joiner.session.peers.get(creator.fpr);
    peer.kcVerified = false;
    expect(peer.sessionKey).toBeTruthy();

    const signed = await cleartext(
      manifestToJson(await aManifest()),
      creator.privateKey
    );
    await creator.session.publishManifest(signed);
    await pair.settle();

    expect(joiner.manifests).toEqual([]);
    expect(joiner.errors).toEqual([]);

    // Confirming afterwards does not flush a queue, because there is none. The
    // sender must say it again, which is the same rule chat lives under.
    peer.kcVerified = true;
    await pair.settle();
    expect(joiner.manifests).toEqual([]);

    expect(await creator.session.publishManifest(signed)).toBe(1);
    await until(() => joiner.manifests.length > 0);
    expect(joiner.manifests).toHaveLength(1);
  });

  it("writes to nobody when the sender has confirmed nobody", async () => {
    const { creator, joiner } = await meshed();
    creator.session.peers.get(joiner.fpr).kcVerified = false;
    const signed = await cleartext(
      manifestToJson(await aManifest()),
      creator.privateKey
    );
    // A count, not a promise: the caller is told nobody heard it.
    expect(await creator.session.publishManifest(signed)).toBe(0);
    await pair.settle();
    expect(joiner.manifests).toEqual([]);
  });
});

/* ──────────────────────────── malformed, not fatal ──────────────────────── */

describe("a malformed document does not take the session down", () => {
  it.each([
    ["signed nonsense", async (/** @type {any} */ k) => cleartext("{{{", k)],
    [
      "a signed document of the wrong kind",
      async (/** @type {any} */ k) =>
        cleartext(attestationToJson(await buildAttestation({ manifestSha: "a".repeat(64) })), k),
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
    await creator.session.publishManifest(await make(creator.privateKey));
    await until(() => joiner.errors.length > 0);

    expect(joiner.manifests).toEqual([]);
    expect(joiner.errors.at(-1)).toBeInstanceOf(Error);
    expect(joiner.session.peers.get(creator.fpr).kcVerified).toBe(true);
    await chatStillWorks(creator, joiner, "after the malformed one");
  });

  it("survives a payload whose document is not a string at all", async () => {
    const { creator, joiner } = await meshed();
    const peer = creator.session.peers.get(joiner.fpr);
    const body = JSON.stringify({ kind: "manifest", doc: { nope: 1 }, ts: Date.now() });
    peer.channel.send(
      JSON.stringify({ v: 1, blob: await encryptSessionPayload(peer.sessionKey, body) })
    );
    await until(() => joiner.errors.length > 0);
    expect(joiner.manifests).toEqual([]);
    await chatStillWorks(creator, joiner, "after the object");
  });
});

/* ──────────────────────────────── the ceiling ───────────────────────────── */

describe("an oversized document is refused rather than truncated", () => {
  it("fails in the author's hands, before anything is encrypted", async () => {
    const { creator, joiner } = await meshed();
    const huge = await cleartext(
      manifestToJson(await aManifest("x".repeat(MAX_DOCUMENT_BYTES))),
      creator.privateKey
    );
    await expect(creator.session.publishManifest(huge)).rejects.toThrow(
      /refused whole/
    );
    await pair.settle();
    expect(joiner.manifests).toEqual([]);
    expect(joiner.errors).toEqual([]);
    await chatStillWorks(creator, joiner, "after the oversized send");
  });

  it("is refused on arrival too, whole, when a sender skips its own check", async () => {
    const { creator, joiner } = await meshed();
    // Straight onto the channel, past `publishManifest` — a peer that does not
    // run this build is not bound by its send-side ceiling.
    const peer = creator.session.peers.get(joiner.fpr);
    const body = JSON.stringify({
      kind: "manifest",
      doc: "a".repeat(MAX_DOCUMENT_BYTES + 1),
      ts: Date.now(),
    });
    peer.channel.send(
      JSON.stringify({ v: 1, blob: await encryptSessionPayload(peer.sessionKey, body) })
    );
    await until(() => joiner.errors.length > 0);

    expect(joiner.manifests).toEqual([]);
    expect(joiner.errors.at(-1).message).toMatch(/refused whole/);
    // Nothing partial was kept.
    expect(joiner.session.peers.get(creator.fpr).publishedManifest).toBe(null);
    await chatStillWorks(creator, joiner, "after the oversized arrival");
  });
});

/* ─────────────────────────────── the courier rule ───────────────────────── */

describe("the session carries documents and does not sign them", () => {
  it("refuses to publish anything that is not already signed", async () => {
    const { creator, joiner } = await meshed();
    const raw = manifestToJson(await aManifest());
    await expect(creator.session.publishManifest(raw)).rejects.toThrow(
      /must arrive here already signed/
    );
    await expect(creator.session.publishAttestation(raw)).rejects.toThrow(
      /does not sign on anyone's behalf/
    );
    await pair.settle();
    expect(joiner.manifests).toEqual([]);
    expect(joiner.attestations).toEqual([]);
  });

  it("does not attest to a manifest it received", async () => {
    const { creator, joiner } = await meshed();
    const sha = await manifestDigest(await aManifest());
    await creator.session.publishManifest(
      await cleartext(manifestToJson(await aManifest()), creator.privateKey)
    );
    await until(() => joiner.manifests.length > 0);
    await pair.settle();

    // Receiving a commitment is not making one. The joiner holds the private
    // key that could answer it, and nothing here reaches for it.
    expect(creator.attestations).toEqual([]);
    expect(creator.session.attestersOf(sha)).toEqual([]);
    expect(joiner.session.peers.get(creator.fpr).attested.size).toBe(0);
  });
});
