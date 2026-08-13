/**
 * Two live sessions carrying a cell handoff between them, both ways.
 *
 * Nothing is stubbed: real OpenPGP keys, real signed and encrypted signalling,
 * real ECDH, real key confirmation, real pairwise AES frames — the same mesh
 * `notebook-session-documents.test.js` runs the manifest and the attestation
 * over, because a handoff rides the same `session` frame beside them.
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
 * And the way back, where one thing changes and one does not. A result is
 * **signed**, so the session checks it against that peer's key and no other,
 * the way it checks a manifest — a peer passing on somebody else's signed result
 * as their own answer is refused. What does not change is that it arrives just
 * as pending: the signature says who made the claim, and whether the claim is
 * about a cell this peer offered them, and whether the values may be registered,
 * are questions for a plan this layer does not hold. **Nothing here restarts a
 * run.**
 *
 * Every case ends by putting a chat message through the same channel: `kc` and
 * `chat` are the transport all of this stands on.
 */
import { afterEach, describe, expect, it } from "vitest";
import { encryptSessionPayload } from "../lib/notebook/crypto.js";
import { MAX_DOCUMENT_BYTES, looksCleartextSigned } from "../lib/notebook/documents.js";
import {
  HANDOFF_KIND,
  HANDOFF_VERSION,
  RESULT_KIND,
  RESULT_VERSION,
  acceptCellResult,
  acceptHandoffOffer,
  buildResultFor,
  offerToJson,
  resultToJson,
} from "../lib/toolkit/handoff.js";
import { signOpenPgp } from "../lib/pgp/sign.js";
import { buildRunManifest, manifestDigest } from "../lib/toolkit/manifest.js";
import { planChains, planRun } from "../lib/toolkit/plan.js";
import { compileRecipe, migrateRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;

afterEach(async () => {
  await pair?.stop();
  pair = null;
});

/**
 * Three cells and two machines. mara publishes a seed, okafor's cell turns it
 * into `$b64`, and **mara's last cell reads `$b64`** — so mara's run does not
 * merely skip a cell, it stops, and stays stopped until okafor's result comes
 * back. One notebook for both legs, because it is one handoff.
 */
const HANDED = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor publish
in $seed | decode hex | encode base64 | out $b64

@mara
in $b64 | out $done
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

/**
 * A result for cell 1, as okafor's run would have produced it.
 * @param {import("../lib/toolkit/manifest.js").RunManifest} manifest
 */
async function aResult(manifest) {
  return {
    v: RESULT_VERSION,
    kind: /** @type {*} */ (RESULT_KIND),
    manifest: await manifestDigest(manifest),
    cell: 1,
    cellDigest: manifest.cells[1].recipeDigest,
    produced: [{ label: "b64", type: /** @type {*} */ ("text"), data: "3q2+7w==" }],
    ranAt: new Date(0).toISOString(),
  };
}

/**
 * A document the way a recipe would hand it over — `gpg.sign`'s output, chosen
 * by somebody who read the pipeline. Nothing in the session can produce this.
 * @param {string} text @param {import("openpgp").PrivateKey} privateKey
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

/* ─────────────────────────────── the way back ───────────────────────────── */

describe("a signed cell result crosses the room the other way", () => {
  /**
   * The whole exchange over two live sessions: mara stops, offers, okafor
   * accepts and runs, signs what came out, sends it back, and mara's stopped run
   * finishes. Every hop is the real thing; the only hand-written lines are the
   * two a person would click.
   */
  it("closes the run that stopped, and registering is still somebody's act", async () => {
    const { creator, joiner } = await meshed();
    const roster = rosterOf(creator, joiner);
    const manifest = await manifestFor(roster);
    const sha = await manifestDigest(manifest);
    const maraPlan = planRun(compiled, { me: creator.fpr, roster });
    const okaforPlan = planRun(compiled, { me: joiner.fpr, roster });

    // mara's run stops at cell 2, which reads what cell 1 writes on okafor.
    const stopped = await runRecipe(
      compiled.ast,
      {},
      { slotRegistry: createSlotRegistry(), placement: { plan: maraPlan } }
    ).then(
      () => null,
      (e) => e
    );
    expect(stopped?.basiliskWithheld).toEqual({ cell: 2, slot: "b64", from: 1, peer: "okafor" });

    // The offer out, and okafor running his cell.
    expect(await creator.session.sendOffer(joiner.fpr, offerToJson(await anOffer(manifest)))).toBe(1);
    await until(() => joiner.offers.length > 0);
    const okaforSlots = createSlotRegistry();
    const taken = await acceptHandoffOffer(joiner.offers[0].offer, {
      plan: okaforPlan,
      compiled,
      manifest,
      hasSlot: (l) => okaforSlots.has(l),
    });
    expect(taken.ok, taken.refusals.map((r) => r.message).join(" · ")).toBe(true);
    for (const b of taken.bindings) okaforSlots.register(`$${b.label}`, b.value);
    await runRecipe(compiled.ast, {}, { slotRegistry: okaforSlots, placement: { plan: okaforPlan } });
    expect(okaforSlots.has("b64")).toBe(true);

    // The result back, signed by the peer that ran it. The session takes the
    // signed bytes and never the object — there is no path from here to a key.
    const built = await buildResultFor({
      plan: okaforPlan,
      compiled,
      manifest,
      cell: 1,
      readSlot: (l) => (okaforSlots.has(l) ? okaforSlots.resolve(l) : null),
    });
    expect(built.ok, built.refusals.map((r) => r.message).join(" · ")).toBe(true);
    const signed = await cleartext(resultToJson(built.result), joiner.privateKey);
    expect(await joiner.session.sendResult(creator.fpr, signed)).toBe(1);
    await until(() => creator.results.length > 0);

    const got = creator.results[0];
    expect(got.from).toBe(joiner.fpr);
    expect(got.cell).toBe(1);
    expect(got.manifest).toBe(sha);
    expect(got.result.produced).toEqual([{ label: "b64", type: "text", data: "3q2+7w==" }]);
    // The signed bytes travel too, so mara can keep the evidence of who said so
    // long after this channel is gone. That is what the signature is for.
    expect(looksCleartextSigned(got.signed)).toBe(true);
    // The session recorded that a claim arrived and nothing more. There is no
    // `acceptResult` here, and no registry for one to have written to.
    expect([...creator.session.peers.get(joiner.fpr).returned]).toEqual([`${sha}:1`]);
    expect(creator.session.acceptResult).toBeUndefined();

    // Now the person. Checking is one act; registering is another; running is a
    // third, and only the last of them makes the notebook move.
    const maraSlots = createSlotRegistry();
    const verdict = await acceptCellResult(got.result, {
      plan: maraPlan,
      compiled,
      manifest,
      by: "okafor",
      offered: [{ manifest: sha, cell: 1, to: "okafor" }],
      hasSlot: (l) => maraSlots.has(l),
    });
    expect(verdict.ok, verdict.refusals.map((r) => r.message).join(" · ")).toBe(true);
    expect(maraSlots.has("b64")).toBe(false);
    for (const b of verdict.bindings) maraSlots.register(`$${b.label}`, b.value);

    const arts = await runRecipe(
      compiled.ast,
      {},
      { slotRegistry: maraSlots, placement: { plan: maraPlan } }
    );
    expect(maraSlots.has("done")).toBe(true);
    expect(arts.some((a) => String(a.content).includes("3q2+7w="))).toBe(true);

    expect([...creator.errors, ...joiner.errors]).toEqual([]);
    await chatStillWorks(creator, joiner, "and the loop is closed");
  });

  it("refuses a result signed by anyone but the peer it arrived from", async () => {
    // The replay a `verify against every key in the room` check waves through:
    // one peer holding out another peer's signed result as their own answer to
    // an offer. The signature is perfectly good — it is not theirs, and the
    // origin is about to fold the value into its own run.
    const { creator, joiner } = await meshed();
    const manifest = await manifestFor(rosterOf(creator, joiner));
    const result = await aResult(manifest);
    const signedByMara = await cleartext(resultToJson(result), creator.privateKey);

    // mara's own signature, sent back to mara on okafor's channel.
    await joiner.session.sendResult(creator.fpr, signedByMara);
    await until(() => creator.errors.length > 0);

    expect(creator.results).toEqual([]);
    expect(creator.errors[0].message).toMatch(/cell result from .+ refused/);
    expect(creator.errors[0].message).toContain("not signed by that peer");
    expect([...creator.session.peers.get(joiner.fpr).returned]).toEqual([]);
    await chatStillWorks(creator, joiner, "after the replay");
  });

  it("refuses to send a result that nobody signed, or to send it to nobody", async () => {
    const { creator, joiner } = await meshed();
    const json = resultToJson(await aResult(await manifestFor(rosterOf(creator, joiner))));
    // The temptation this refuses is the session reaching for a private key it
    // holds for another purpose entirely.
    await expect(joiner.session.sendResult(creator.fpr, json)).rejects.toThrow(
      /already signed/
    );
    const signed = await cleartext(json, joiner.privateKey);
    await expect(joiner.session.sendResult("", signed)).rejects.toThrow(/goes back to one peer/);
    await expect(joiner.session.sendResult("BADF00D", signed)).rejects.toThrow(/went nowhere/);
    expect(creator.results).toEqual([]);
  });

  it("drops a result from a peer whose key is not confirmed", async () => {
    const { creator, joiner } = await meshed();
    const peer = creator.session.peers.get(joiner.fpr);
    peer.kcVerified = false;
    const signed = await cleartext(
      resultToJson(await aResult(await manifestFor(rosterOf(creator, joiner)))),
      joiner.privateKey
    );
    await joiner.session.sendResult(creator.fpr, signed);
    await pair.settle();
    expect(creator.results).toEqual([]);
    expect(creator.errors).toEqual([]);

    // And confirming afterwards flushes no queue: there was never one.
    peer.kcVerified = true;
    await pair.settle();
    expect(creator.results).toEqual([]);
    expect(await joiner.session.sendResult(creator.fpr, signed)).toBe(1);
    await until(() => creator.results.length > 0);
    await chatStillWorks(creator, joiner, "after the drop");
  });

  it("is refused whole on arrival when a sender skips its own size check", async () => {
    const { creator, joiner } = await meshed();
    // Straight onto the wire, bypassing `sendResult` — the receiver refuses on
    // size before OpenPGP is asked to parse an attacker-sized blob, so the
    // ceiling holds even when the sender's own check was never run.
    const peer = joiner.session.peers.get(creator.fpr);
    const body = JSON.stringify({
      kind: "result",
      doc: "x".repeat(MAX_DOCUMENT_BYTES + 1),
      ts: Date.now(),
    });
    const blob = await encryptSessionPayload(peer.sessionKey, body);
    peer.channel.send(JSON.stringify({ v: 1, blob }));
    await until(() => creator.errors.length > 0);

    expect(creator.results).toEqual([]);
    expect(creator.errors[0].message).toContain("refused whole");
    await chatStillWorks(creator, joiner, "still standing");
  });

  it("survives a signed document that is not a result at all", async () => {
    const { creator, joiner } = await meshed();
    const signed = await cleartext(
      JSON.stringify({ v: 1, kind: "basilisk.cell-handoff", needs: [] }),
      joiner.privateKey
    );
    await joiner.session.sendResult(creator.fpr, signed);
    await until(() => creator.errors.length > 0);
    expect(creator.results).toEqual([]);
    expect(creator.errors[0].message).toContain("not a Basilisk cell result");
    await chatStillWorks(creator, joiner, "unharmed");
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
