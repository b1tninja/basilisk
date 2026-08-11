/**
 * Two live sessions carrying a cell handoff offer between them.
 *
 * Nothing is stubbed: real OpenPGP keys, real signed and encrypted signalling,
 * real ECDH, real key confirmation, real pairwise AES frames — the same mesh
 * `notebook-session-documents.test.js` runs the manifest and the attestation
 * over, because an offer rides the same `session` frame beside them.
 *
 * The properties this file exists for:
 *
 * - an offer reaches **one** peer, because the document names no assignee and
 *   the wire is the only addressing there is;
 * - it arrives **pending**: parsed, handed up, and nothing else. No slot was
 *   registered, no cell ran, and there is no method on the session that could
 *   do either — accepting is a person, in the shell, holding a plan;
 * - an offer from a peer whose key is not confirmed is dropped, not queued,
 *   exactly as a document is;
 * - a malformed offer is one frame going nowhere.
 *
 * Every case ends by putting a chat message through the same channel: `kc` and
 * `chat` are the transport all of this stands on.
 */
import { afterEach, describe, expect, it } from "vitest";
import { encryptSessionPayload } from "../lib/notebook/crypto.js";
import { MAX_DOCUMENT_BYTES } from "../lib/notebook/documents.js";
import {
  HANDOFF_KIND,
  HANDOFF_VERSION,
  acceptHandoffOffer,
  offerToJson,
} from "../lib/toolkit/handoff.js";
import { buildRunManifest, manifestDigest } from "../lib/toolkit/manifest.js";
import { planChains, planRun } from "../lib/toolkit/plan.js";
import { compileRecipe, migrateRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;

afterEach(() => {
  pair?.stop();
  pair = null;
});

const HANDED = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor
in $seed | decode hex | encode base64 | out $b64
`;

const compiled = compileRecipe(migrateRecipe(HANDED).recipe);

/**
 * The room's roster, bound to the fingerprints these two sessions actually
 * carry — `mara` is the creator, `okafor` the joiner.
 * @param {any} creator @param {any} joiner
 */
const rosterOf = (creator, joiner) => ({ mara: creator.fpr, okafor: joiner.fpr });

/** @param {Record<string, string>} peers */
function manifestFor(peers) {
  return buildRunManifest({
    title: "handoff",
    recipeSource: migrateRecipe(HANDED).recipe,
    peers,
    cells: planChains(compiled).map((chain, i) => ({
      index: i,
      peer: String(chain.peer || ""),
      publish: !!chain.publish,
      recipe: serializeRecipe({ chains: [chain] }),
    })),
  });
}

/**
 * An offer for cell 1, as mara's stopped run would have produced it.
 * @param {import("../lib/toolkit/manifest.js").RunManifest} manifest
 */
async function anOffer(manifest) {
  return {
    v: HANDOFF_VERSION,
    kind: /** @type {*} */ (HANDOFF_KIND),
    manifest: await manifestDigest(manifest),
    cell: 1,
    cellDigest: manifest.cells[1].recipeDigest,
    needs: [{ label: "seed", type: /** @type {*} */ ("text"), data: "deadbeef" }],
    offeredAt: new Date(0).toISOString(),
  };
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
 * @param {any} a @param {any} b @param {string} tag
 */
async function chatStillWorks(a, b, tag) {
  const before = b.chats.length;
  expect(await a.session.sendChatTo(b.fpr, tag)).toBe(1);
  await until(() => b.chats.length > before);
  expect(b.chats.at(-1).text).toBe(tag);
}

describe("a cell handoff offer crosses the room", () => {
  it("reaches one peer, arrives pending, and is only then accepted by hand", async () => {
    const { creator, joiner } = await meshed();
    const roster = rosterOf(creator, joiner);
    const manifest = await manifestFor(roster);
    const sha = await manifestDigest(manifest);
    const offer = await anOffer(manifest);

    expect(await creator.session.sendOffer(joiner.fpr, offerToJson(offer))).toBe(1);
    await until(() => joiner.offers.length > 0);

    const got = joiner.offers[0];
    expect(got.from).toBe(creator.fpr);
    expect(got.cell).toBe(1);
    expect(got.manifest).toBe(sha);
    expect(got.offer.needs).toEqual([{ label: "seed", type: "text", data: "deadbeef" }]);
    // The session recorded that an offer arrived and nothing more. There is no
    // `accept` here to have been called and no registry for it to write to.
    expect([...joiner.session.peers.get(creator.fpr).offered]).toEqual([`${sha}:1`]);
    expect(joiner.session.acceptOffer).toBeUndefined();

    // Now the person: check the offer against this peer's own plan, then put
    // the bindings in. Two separate acts, and the second is the only one that
    // changes anything.
    const plan = planRun(compiled, { me: joiner.fpr, roster });
    const registry = createSlotRegistry();
    const verdict = await acceptHandoffOffer(got.offer, {
      plan,
      compiled,
      manifest,
      hasSlot: (l) => registry.has(l),
    });
    expect(verdict.ok, verdict.refusals.map((r) => r.message).join(" · ")).toBe(true);
    expect(registry.has("seed")).toBe(false);
    for (const b of verdict.bindings) registry.register(`$${b.label}`, b.value);

    const arts = await runRecipe(compiled.ast, {}, { slotRegistry: registry, placement: { plan } });
    expect(arts.some((a) => String(a.content).includes("3q2+7w=="))).toBe(true);

    expect([...creator.errors, ...joiner.errors]).toEqual([]);
    await chatStillWorks(creator, joiner, "still talking");
  });

  it("refuses to hand a cell to nobody", async () => {
    const { creator, joiner } = await meshed();
    const json = offerToJson(await anOffer(await manifestFor(rosterOf(creator, joiner))));
    // An offer says nothing about who runs the cell, so there is nobody for an
    // unaddressed one to reach — silence would be the dangerous answer.
    await expect(creator.session.sendOffer("", json)).rejects.toThrow(/goes to one peer/);
    await expect(creator.session.sendOffer("BADF00D", json)).rejects.toThrow(
      /handed to nobody/
    );
    expect(joiner.offers).toEqual([]);
  });
});

describe("an offer from an unconfirmed peer is dropped, not queued", () => {
  it("delivers nothing, and confirming afterwards flushes no queue", async () => {
    const { creator, joiner } = await meshed();
    // The pairwise key still opens the frame; what is missing is the
    // confirmation that says the far end is anyone in particular — which is
    // exactly the state a peer proposing to write into our slots must not be in.
    const peer = joiner.session.peers.get(creator.fpr);
    peer.kcVerified = false;
    expect(peer.sessionKey).toBeTruthy();

    const json = offerToJson(await anOffer(await manifestFor(rosterOf(creator, joiner))));
    await creator.session.sendOffer(joiner.fpr, json);
    await pair.settle();

    expect(joiner.offers).toEqual([]);
    expect(joiner.errors).toEqual([]);

    peer.kcVerified = true;
    await pair.settle();
    expect(joiner.offers).toEqual([]);

    expect(await creator.session.sendOffer(joiner.fpr, json)).toBe(1);
    await until(() => joiner.offers.length > 0);
    expect(joiner.offers).toHaveLength(1);
    await chatStillWorks(creator, joiner, "after the drop");
  });
});

describe("a malformed offer does not take the session down", () => {
  it.each([
    ["not JSON at all", "{{{"],
    [
      "a document of another kind",
      JSON.stringify({ v: 1, kind: "basilisk.run-manifest", cells: [] }),
    ],
    [
      "an offer naming who should run the cell",
      JSON.stringify({
        v: HANDOFF_VERSION,
        kind: HANDOFF_KIND,
        manifest: "a".repeat(64),
        cell: 1,
        cellDigest: "b".repeat(64),
        needs: [],
        offeredAt: new Date(0).toISOString(),
        assignee: "okafor",
      }),
    ],
    [
      "an offer carrying key material",
      JSON.stringify({
        v: HANDOFF_VERSION,
        kind: HANDOFF_KIND,
        manifest: "a".repeat(64),
        cell: 1,
        cellDigest: "b".repeat(64),
        needs: [{ label: "kp", type: "keypair", data: {} }],
        offeredAt: new Date(0).toISOString(),
      }),
    ],
  ])("survives %s", async (_what, json) => {
    const { creator, joiner } = await meshed();
    await creator.session.sendOffer(joiner.fpr, json);
    await until(() => joiner.errors.length > 0);

    expect(joiner.offers).toEqual([]);
    expect(joiner.errors[0].message).toMatch(/handoff offer from .+ refused/);
    expect([...joiner.session.peers.get(creator.fpr).offered]).toEqual([]);
    await chatStillWorks(creator, joiner, "unharmed");
  });

  it("is refused whole on arrival when a sender skips its own size check", async () => {
    const { creator, joiner } = await meshed();
    // Straight onto the wire, bypassing `sendOffer` — the receiver must refuse
    // before anything is asked to parse an attacker-sized blob.
    const peer = creator.session.peers.get(joiner.fpr);
    const json = JSON.stringify({
      v: HANDOFF_VERSION,
      kind: HANDOFF_KIND,
      manifest: "a".repeat(64),
      cell: 1,
      cellDigest: "b".repeat(64),
      needs: [{ label: "seed", type: "text", data: "x".repeat(MAX_DOCUMENT_BYTES) }],
      offeredAt: new Date(0).toISOString(),
    });
    const body = JSON.stringify({ kind: "handoff", doc: json, ts: Date.now() });
    const blob = await encryptSessionPayload(peer.sessionKey, body);
    peer.channel.send(JSON.stringify({ v: 1, blob }));
    await until(() => joiner.errors.length > 0);

    expect(joiner.offers).toEqual([]);
    expect(joiner.errors[0].message).toContain("refused whole");
    await chatStillWorks(creator, joiner, "still standing");
  });
});
