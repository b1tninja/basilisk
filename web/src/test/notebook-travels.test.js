/**
 * The notebook itself crossing between two machines.
 *
 * ## What was broken, stated as the thing this file first proves
 *
 * `acceptHandoffOffer` checks an arriving offer against the **recipient's own**
 * plan, their own cell text and a manifest they already hold. That is the good
 * part: it is what makes the value you register proof that the cell you ran is
 * the cell they offered, and it is why a shared run is a reproducible build
 * rather than a screen share.
 *
 * The doctrine had no mechanism. An invite (`#j=`) carries an audience and
 * deliberately no recipe; the session carried a manifest, an attestation, an
 * offer and a result and no notebook. So a joiner arrived with an empty
 * notebook, derived a manifest from *that*, and refused every offer with
 * `unknown-manifest` — a refusal whose own sentence tells the reader to "ask for
 * the signed manifest, check it, and offer again", naming a step no code
 * performed. `placed-run-arc.e2e.js` never caught it because it hands both sides
 * the same `S.src` variable: it proves the arc works when the notebooks already
 * match, and says nothing about how a joiner obtains the text.
 *
 * The first test here is that refusal, reproduced. Everything after it is the
 * transport that makes it stop happening — **without relaxing the gate**. Both
 * ends still hold the same text and still prove it by digest; one of them may
 * now receive it, signed, instead of being required to retype it.
 *
 * ## The manifest does not have to travel, and this file shows why
 *
 * `handoffContext` *derives* the manifest from `{source, roster, title}` and
 * `buildRunManifest` is deterministic — no timestamp, no nonce. The roster is
 * `roomRoster` over the audience, which is fixed for the session and identical
 * in every browser. So `source` and `title` are the whole of what can differ
 * between two peers of one room, and `carries the title too` below is the test
 * that says why the title is on the document: identical recipe text under two
 * titles still digests to two manifests, and the offer is still refused.
 */
import { afterEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { generateKey } from "openpgp";
import { signOpenPgp } from "../lib/pgp/sign.js";
import { encryptSessionPayload } from "../lib/notebook/crypto.js";
import { handoffContext, offerForSkipped, reviewOffer } from "../lib/toolkit/handoff-shell.js";
import { summarizeHandoff } from "../lib/toolkit/handoff.js";
import { manifestDigest } from "../lib/toolkit/manifest.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { compileRecipe, migrateRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import {
  MAX_PROPOSAL_SOURCE,
  NOTEBOOK_PROPOSAL_FIELDS,
  buildNotebookProposal,
  decideProposal,
  parseNotebookProposal,
  proposalToJson,
  sameNotebook,
} from "../lib/toolkit/notebook-share.js";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;

afterEach(async () => {
  await pair?.stop();
  pair = null;
});

const TITLE = "Thursday key ceremony";

/**
 * peer1 seeds, peer2 transforms, peer1 reads the answer.
 *
 * The labels are `roomRoster`'s, because that is what the product derives them
 * as — position in the canonical audience — and a notebook that travels between
 * two browsers has to be written in the names both of them compute.
 */
const HANDED = `@peer1
bytes deadbeef | encode hex | out $seed | publish

@peer2
$seed | decode hex | encode base64 | out $b64 | publish

@peer1
$b64 | decode base64 | encode hex | out $final`;

const FPR_1 = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_2 = "91C7E6D5C4B3A29180716253443526170819AABB";
const ROSTER = { peer1: FPR_1, peer2: FPR_2 };

/** Run a placed notebook, collecting what the gate declined. */
async function runPlaced(ctx, source, registry) {
  /** @type {any[]} */
  const skipped = [];
  await runRecipe(compileRecipe(migrateRecipe(source).recipe).ast, {}, {
    slotRegistry: registry,
    allowReplaceSlots: true,
    placement: { plan: ctx.plan, onSkip: (s) => skipped.push(s) },
  }).catch(() => {});
  return skipped;
}

/** The offer peer1's stopped run produces for the cell that is peer2's. */
async function offerFromPeer1(title = TITLE) {
  const ctx = await handoffContext({ source: HANDED, me: "peer1", roster: ROSTER, title });
  const slots = createSlotRegistry();
  const skipped = await runPlaced(ctx, HANDED, slots);
  expect(skipped.map((s) => s.cell)).toEqual([1]);
  const built = await offerForSkipped(ctx, skipped[0], (l) =>
    slots.has(l) ? slots.resolve(l) : null
  );
  expect(built.ok, JSON.stringify(built)).toBe(true);
  return { ctx, offer: built };
}

/* ───────────────────────────── the defect itself ─────────────────────────── */

describe("a joiner who was never given the notebook", () => {
  it("refuses every offer, naming a manifest it could not have", async () => {
    const { offer } = await offerFromPeer1();

    // The joiner's notebook on arrival. `#j=` carries an audience and no recipe,
    // and nothing else ever handed them one.
    const empty = await handoffContext({
      source: "",
      me: "peer2",
      roster: ROSTER,
      title: "Untitled notebook",
    });
    const verdict = await reviewOffer(empty, offer.json, () => false);

    expect(verdict.ok).toBe(false);
    expect(verdict.refusals).toHaveLength(1);
    expect(verdict.refusals[0].reason).toBe("unknown-manifest");
    // The sentence, as it actually reads.
    expect(verdict.refusals[0].message).toContain(
      "This offer is against a run manifest this peer has not seen"
    );
    // It used to end "ask for the signed manifest, check it, and offer again
    // against the digest it actually has" — naming a step no code in this
    // product performed, since nothing published a manifest and nothing here
    // reads one anyway: `handoffContext` *derives* it from the notebook. The
    // refusal now names the state that is actually true and the press that ends
    // it, which is the rule this repo keeps breaking.
    expect(verdict.refusals[0].message).toContain(
      "A manifest is derived from the notebook on this machine"
    );
    expect(verdict.refusals[0].message).toContain("The notebook itself");
    expect(verdict.refusals[0].message).not.toContain("Ask for the signed manifest");
  });

  it("is refused for the notebook and not for the cell, which is why the cell gate never fired", async () => {
    // The order matters to anybody reading a refusal: the manifest is checked
    // first, so the cell-text digest — the check people think of as *the* gate —
    // is never reached at all. An empty joiner never learns that cell 1 is
    // theirs; they learn nothing.
    const { offer } = await offerFromPeer1();
    const empty = await handoffContext({ source: "", me: "peer2", roster: ROSTER });
    const verdict = await reviewOffer(empty, offer.json, () => false);
    expect(verdict.refusals.map((r) => r.reason)).not.toContain("cell-mismatch");
    expect(verdict.refusals.map((r) => r.reason)).not.toContain("not-mine");
    expect(summarizeHandoff(verdict)).toContain("cell 1 (manifest)");
  });
});

/* ─────────────────────── what adopting the text fixes ────────────────────── */

describe("once both ends hold the same notebook", () => {
  it("the manifests agree by construction, with nothing published", async () => {
    // No manifest crossed the room in this test, and none needed to:
    // `handoffContext` derives it from the text, the roster and the title, and
    // `buildRunManifest` carries no clock and no nonce.
    const a = await handoffContext({ source: HANDED, me: "peer1", roster: ROSTER, title: TITLE });
    const b = await handoffContext({ source: HANDED, me: "peer2", roster: ROSTER, title: TITLE });
    expect(await manifestDigest(a.manifest)).toBe(await manifestDigest(b.manifest));
  });

  it("the offer that was refused is accepted", async () => {
    const { offer } = await offerFromPeer1();
    const adopted = await handoffContext({
      source: HANDED,
      me: "peer2",
      roster: ROSTER,
      title: TITLE,
    });
    const verdict = await reviewOffer(adopted, offer.json, () => false);
    expect(verdict.ok, summarizeHandoff(verdict)).toBe(true);
    expect(verdict.bindings.map((b) => b.label)).toEqual(["seed"]);
  });

  it("carries the title too, because half the digest is made of it", async () => {
    // The reason `title` is a field on the proposal rather than an ornament.
    // Character-identical recipe text under a different title is a different
    // manifest, and the offer is refused with the same sentence as an empty
    // notebook — which would have been a maddening second bug behind the first.
    const { offer } = await offerFromPeer1();
    const wrongTitle = await handoffContext({
      source: HANDED,
      me: "peer2",
      roster: ROSTER,
      title: "Shared notebook",
    });
    const verdict = await reviewOffer(wrongTitle, offer.json, () => false);
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals[0].reason).toBe("unknown-manifest");
  });

  it("survives the editor's round trip, which is what adoption actually does", async () => {
    // Adopting compiles the proposal and the editor's `source` is the
    // re-serialisation of what it compiled. If that were not a fixed point, an
    // adopted notebook would digest to something the sender never had and the
    // offer would still be refused — for a reason nobody could see.
    const settled = serializeRecipe(compileRecipe(HANDED).ast);
    expect(serializeRecipe(compileRecipe(settled).ast)).toBe(settled);
    const { offer } = await offerFromPeer1();
    const viaEditor = await handoffContext({
      source: settled,
      me: "peer2",
      roster: ROSTER,
      title: TITLE,
    });
    expect((await reviewOffer(viaEditor, offer.json, () => false)).ok).toBe(true);
  });
});

/* ──────────────────────────── the document itself ────────────────────────── */

describe("a notebook proposal", () => {
  it("carries a title and the text, and has nowhere to put a claim", () => {
    expect([...NOTEBOOK_PROPOSAL_FIELDS].sort()).toEqual([
      "kind",
      "proposedAt",
      "source",
      "title",
      "v",
    ]);
    const p = buildNotebookProposal({ title: TITLE, source: HANDED });
    const smuggled = { ...p, from: FPR_1, runNow: true };
    expect(() => parseNotebookProposal(JSON.stringify(smuggled))).toThrow(
      /unexpected fields from, runNow/
    );
  });

  it("refuses to carry a private key, in both directions", () => {
    const armored = `bytes cafe | out $x\n\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nxxxx\n-----END PGP PRIVATE KEY BLOCK-----`;
    expect(() => buildNotebookProposal({ title: TITLE, source: armored })).toThrow(
      /looks like it holds secret material/
    );
    // And on the way in, because the sender's refusal is an argument about a
    // document *this* build produced. A proposal built by something else reaches
    // the parse and is refused there.
    const forged = JSON.stringify({
      ...buildNotebookProposal({ title: TITLE, source: HANDED }),
      source: armored,
    });
    // Phrasing, not property: the arriving refusal now names passphrases too,
    // since a literal `passphrase=` is material this predicate catches. What is
    // pinned is that a proposal carrying private armor is refused on the way in
    // as well as on the way out.
    expect(() => parseNotebookProposal(forged)).toThrow(/secret material/);
  });

  it("refuses a passphrase written into a step, which is not armor and travels the same way", () => {
    // The class the armor checks could not see. `sss.split passphrase=hunter2`
    // does not parse — a `secret` param takes a `$ref` — but nothing on this
    // path parses, so until the predicate learned the form, a notebook nobody
    // could run still carried the mask for shares somebody could.
    const literal = `random 32 | sss.split threshold=2 shares=3 passphrase=hunter2 | out $s`;
    expect(() => buildNotebookProposal({ title: TITLE, source: literal })).toThrow(
      /looks like it holds secret material/
    );
    // The same notebook, spelled the way the language asks for: the mask is
    // named, and the name is all that travels.
    const named = `input | out $pw\n\nrandom 32 | sss.split threshold=2 shares=3 passphrase=$pw | out $s`;
    expect(() => buildNotebookProposal({ title: TITLE, source: named })).not.toThrow();
  });

  it("proposes a placed notebook, fingerprints and all", () => {
    // This used to throw. `recipeLooksSecret` counted a fingerprint written as
    // a peer among the material it refuses to let across a boundary, and a
    // placed notebook is now exactly that on purpose — so refusing it here
    // would mean the one kind of notebook worth sharing over a session is the
    // one kind that cannot be.
    //
    // The other three arms of the predicate are untouched and are asserted
    // elsewhere in this file: this boundary still refuses private armor.
    const doc = buildNotebookProposal({
      title: TITLE,
      source: `@${FPR_1} publish
bytes ca | out $x`,
    });
    expect(doc.source).toContain(FPR_1);
  });

  it("refuses armor, so there is one answer to which bytes were signed", () => {
    expect(() =>
      parseNotebookProposal("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{}")
    ).toThrow(/check the signature against the key of the peer proposing it/);
  });

  it("refuses an empty notebook and an oversized one, before signing either", () => {
    expect(() => buildNotebookProposal({ title: TITLE, source: "   " })).toThrow(
      /nothing in this notebook to propose/
    );
    const huge = `bytes ${"ab".repeat(MAX_PROPOSAL_SOURCE)} | out $x`;
    expect(() => buildNotebookProposal({ title: TITLE, source: huge })).toThrow(
      /refused whole/
    );
  });

  it("is exact about what counts as the same notebook", () => {
    // Whitespace is not noise here: `handoffContext` takes `source` and never a
    // re-serialisation, so two texts that differ by a space digest differently
    // and calling them the same would leave the offer refused while the panel
    // said everything matched.
    expect(sameNotebook({ title: TITLE, source: HANDED }, { title: TITLE, source: HANDED })).toBe(
      true
    );
    expect(
      sameNotebook({ title: TITLE, source: HANDED }, { title: TITLE, source: `${HANDED} ` })
    ).toBe(false);
    expect(
      sameNotebook({ title: TITLE, source: HANDED }, { title: "Other", source: HANDED })
    ).toBe(false);
  });
});

/* ─────────────────────────── the adoption rule ───────────────────────────── */

describe("whose notebook wins", () => {
  const theirs = { from: FPR_1, title: TITLE, source: HANDED };

  it("adopts into an empty notebook without asking", () => {
    // The joiner's case, and the whole reason the document exists. A press to
    // *receive* the first notebook would be the same uselessness with a button.
    const d = decideProposal({ proposal: theirs, here: { title: "Untitled notebook", source: "" } });
    expect(d.action).toBe("adopt");
    expect(d.why).toContain("There was no notebook open here");
  });

  it("does not clobber work that is here", () => {
    const d = decideProposal({
      proposal: theirs,
      here: { title: "Mine", source: "bytes ca | encode hex | out $x" },
    });
    expect(d.action).toBe("ask");
    expect(d.why).toContain("nothing was replaced");
  });

  it("says nothing when the text is already the one they sent", () => {
    expect(
      decideProposal({ proposal: theirs, here: { title: TITLE, source: HANDED } }).action
    ).toBe("same");
  });

  it("flows again from the peer whose notebook this is, until somebody edits", () => {
    const adopted = { from: FPR_1, title: TITLE, source: HANDED };
    const revised = { from: FPR_1, title: TITLE, source: `${HANDED}\n\n@peer2\n$b64 | out $copy` };
    // Unedited since the adopt: their revision lands without a press.
    expect(
      decideProposal({ proposal: revised, here: { title: TITLE, source: HANDED }, adopted }).action
    ).toBe("adopt");
    // One character typed here, and it stops.
    expect(
      decideProposal({
        proposal: revised,
        here: { title: TITLE, source: `${HANDED}\n` },
        adopted,
      }).action
    ).toBe("ask");
  });

  it("does not let a second peer inherit the first peer's welcome", () => {
    // Two people sharing notebooks are two people disagreeing. If this returned
    // `adopt`, whose notebook you are running would depend on packet order.
    const adopted = { from: FPR_1, title: TITLE, source: HANDED };
    const other = { from: FPR_2, title: "Theirs", source: "bytes ff | out $z" };
    expect(
      decideProposal({ proposal: other, here: { title: TITLE, source: HANDED }, adopted }).action
    ).toBe("ask");
  });
});

/* ──────────────────────── two live sessions, end to end ──────────────────── */

/** A meshed pair with both ends key-confirmed. */
async function meshed() {
  pair = await makeQuorumPair();
  await pair.start();
  const { creator, joiner } = pair;
  const ready = await until(
    () =>
      creator.session.peers.get(joiner.fpr)?.kcVerified === true &&
      joiner.session.peers.get(creator.fpr)?.kcVerified === true
  );
  expect(ready, `errors: ${[...creator.errors, ...joiner.errors].map((e) => e.message)}`).toBe(
    true
  );
  return { creator, joiner };
}

/** @param {string} text @param {import("openpgp").PrivateKey} key */
async function cleartext(text, key) {
  const { armored } = await signOpenPgp(text, [key], "cleartext");
  return armored;
}

describe("the notebook on the wire", () => {
  it("crosses signed, and arrives adopted by nobody", async () => {
    const { creator, joiner } = await meshed();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      creator.privateKey
    );

    expect(await creator.session.shareNotebook(signed)).toBe(1);
    expect(
      await until(() => joiner.notebooks.length > 0, 3000),
      "the notebook was never given to the peer who joined after the press"
    ).toBe(true);

    const got = joiner.notebooks[0];
    // Who sent it is the channel's answer, not a field the sender chose — the
    // document has nowhere to put a `from`.
    expect(got.from).toBe(creator.fpr);
    expect(got.proposal.source).toBe(HANDED);
    expect(got.proposal.title).toBe(TITLE);
    expect(joiner.errors).toEqual([]);

    // And the whole point: what arrived, adopted, closes the gate that refused
    // every offer. Both ends derive the same manifest from the same text.
    const mine = await handoffContext({
      source: got.proposal.source,
      me: "peer2",
      roster: ROSTER,
      title: got.proposal.title,
    });
    const { ctx } = await offerFromPeer1();
    expect(await manifestDigest(mine.manifest)).toBe(await manifestDigest(ctx.manifest));
  });

  it("refuses one signed by anybody but the peer that sent it", async () => {
    const { creator, joiner } = await meshed();
    // A perfectly good signature by a key that is not the sender's. This is the
    // replay a `verify against everyone` check waves through, and on this
    // document it would be a peer choosing the text every later digest covers.
    const stranger = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "stranger@quorum.test" }],
      format: "object",
    });
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      stranger.privateKey
    );
    await creator.session.shareNotebook(signed);
    await pair.settle();

    expect(joiner.notebooks).toHaveLength(0);
    expect(joiner.errors.map((e) => e.message).join("\n")).toMatch(
      /notebook proposal from .* refused/
    );
  });

  it("refuses an unsigned one before it is encrypted", async () => {
    const { creator } = await meshed();
    const raw = proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED }));
    await expect(creator.session.shareNotebook(raw)).rejects.toThrow(
      /notebook proposal must arrive here already signed/
    );
  });

  it("drops one from a peer whose key is not confirmed", async () => {
    const { creator, joiner } = await meshed();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      creator.privateKey
    );
    // Straight onto the wire, past `shareNotebook`, with the receiving end's
    // record of this peer un-confirmed. `chat`'s refusal, inherited: an
    // unconfirmed peer is not anyone in particular, and this is the document
    // whose entire content is whose text it is.
    const peer = joiner.session.peers.get(creator.fpr);
    peer.kcVerified = false;
    const target = creator.session.peers.get(joiner.fpr);
    const blob = await encryptSessionPayload(
      target.sessionKey,
      JSON.stringify({ kind: "notebook", doc: signed, ts: Date.now() })
    );
    target.channel.send(JSON.stringify({ v: 1, blob }));
    await pair.settle();

    expect(joiner.notebooks).toHaveLength(0);
    expect(joiner.errors).toEqual([]);
  });
});

/* ───────────────── shared before the other end had arrived ───────────────── */

/**
 * A creator alone in an open room, with every introduction already spent.
 *
 * `settle()` between the two starts is the point rather than a precaution — it
 * is `startCreatorFirst`'s own argument, and here it buys the specific state the
 * owner reported: a session that is up, has published everything it has to
 * publish, and has nobody confirmed. Share pressed here reaches zero peers, and
 * that count was the last word on who would ever receive the notebook.
 */
async function creatorAlone() {
  pair = await makeQuorumPair();
  await pair.creator.session.start();
  await pair.settle();
  return pair;
}

/** Bring the joiner in and wait until both ends have confirmed each other. */
async function joinerArrives() {
  await pair.joiner.session.start();
  const ok = await until(
    () =>
      pair.creator.session.peers.get(pair.joiner.fpr)?.kcVerified === true &&
      pair.joiner.session.peers.get(pair.creator.fpr)?.kcVerified === true
  );
  expect(
    ok,
    `errors: ${[...pair.creator.errors, ...pair.joiner.errors].map((e) => e.message)}`
  ).toBe(true);
  await pair.settle();
}

describe("a notebook shared before anybody had meshed", () => {
  it("reaches nobody at the press, and says so with a count of zero", async () => {
    const { creator } = await creatorAlone();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      creator.privateKey
    );
    // The reported failure's first half, and it was never the wrong answer:
    // there is genuinely nobody to write to. What was wrong is what happened
    // next, which was nothing.
    expect(await creator.session.shareNotebook(signed)).toBe(0);
  });

  it("reaches the peer who arrives afterwards, with no second press", async () => {
    const { creator, joiner } = await creatorAlone();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      creator.privateKey
    );
    await creator.session.shareNotebook(signed);
    expect(joiner.notebooks).toHaveLength(0);

    await joinerArrives();

    // The whole defect, inverted. Nothing was pressed between the share above
    // and this line; the joiner simply turned up.
    expect(
      await until(() => joiner.notebooks.length > 0, 3000),
      "the notebook was never given to the peer who joined after the press"
    ).toBe(true);
    expect(joiner.notebooks[0].proposal.source).toBe(HANDED);
    expect(joiner.notebooks[0].proposal.title).toBe(TITLE);
    expect(joiner.notebooks[0].from).toBe(creator.fpr);
    expect(joiner.errors).toEqual([]);
  });

  it("replays the very bytes that were signed, rather than signing again", async () => {
    const { creator, joiner } = await creatorAlone();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      creator.privateKey
    );
    await creator.session.shareNotebook(signed);
    await joinerArrives();
    expect(
      await until(() => joiner.notebooks.length > 0, 3000),
      "the notebook was never given to the peer who joined after the press"
    ).toBe(true);

    // **This is the consent argument, as an assertion.** What arrives is
    // byte-for-byte the document a person pressed Share on — same signature,
    // same signing moment, same bytes — so the recipient's check is exactly the
    // check they would have made had they been in the room at the press. A
    // delivery that re-signed would produce a different armor here (two
    // signatures over identical text never match), and would mean this session
    // putting somebody's name on a document at a moment they pressed nothing.
    expect(joiner.notebooks[0].signed).toBe(signed);
  });

  it("hands it over once per member, so a reconnect cannot pull it again", async () => {
    const { creator, joiner } = await creatorAlone();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      creator.privateKey
    );
    await creator.session.shareNotebook(signed);
    await joinerArrives();
    expect(
      await until(() => joiner.notebooks.length > 0, 3000),
      "the notebook was never given to the peer who joined after the press"
    ).toBe(true);

    // The bound `_invited` and `_knocked` put on the two invite halves, on this
    // half: a peer flapping on the relay re-verifies, and must not draw the
    // proposal out of the room on every pass. Driven by calling the delivery
    // again rather than by tearing a transport down, because the guard is what
    // is being asked about and a rebuilt transport would also be asking whether
    // the mesh heals.
    const peer = creator.session.peers.get(joiner.fpr);
    expect(peer.notebookSent).toBe(true);
    await creator.session._deliverSharedNotebook(joiner.fpr, peer);
    await pair.settle();
    expect(joiner.notebooks).toHaveLength(1);
  });

  it("is re-armed by a fresh press, which is a person deciding again", async () => {
    const { creator, joiner } = await creatorAlone();
    await creator.session.shareNotebook(
      await cleartext(
        proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
        creator.privateKey
      )
    );
    await joinerArrives();
    expect(
      await until(() => joiner.notebooks.length > 0, 3000),
      "the notebook was never given to the peer who joined after the press"
    ).toBe(true);

    // The once-per-member bound is scoped to a document, not to a session — the
    // remedy the panel names has to work. A second press is a second act of
    // consent over different text and clears what the first one recorded.
    const revised = "bytes c0ffee | encode hex | out $seed";
    await creator.session.shareNotebook(
      await cleartext(
        proposalToJson(buildNotebookProposal({ title: TITLE, source: revised })),
        creator.privateKey
      )
    );
    expect(
      await until(() => joiner.notebooks.length > 1, 3000),
      "a second press did not re-arm the retention"
    ).toBe(true);
    expect(joiner.notebooks[1].proposal.source).toBe(revised);
  });

  it("delivers nothing once the dealer has typed past what they signed", async () => {
    const { creator, joiner } = await creatorAlone();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      creator.privateKey
    );
    await creator.session.shareNotebook(signed);
    // What the editor says when the text on screen moves. Delivering the older
    // document here is the failure that would be worse than the one being
    // fixed: the joiner's notebook is empty, so `decideProposal` adopts it
    // *without asking*, and both ends then believe they agreed on a notebook
    // only one of them is holding.
    expect(creator.session.retireSharedNotebook()).toBe(true);

    await joinerArrives();
    await pair.settle();

    expect(joiner.notebooks).toHaveLength(0);
    expect(joiner.errors).toEqual([]);
    // And the peer is reported as one this browser has not written to, which is
    // the fact the panel turns into a sentence with a remedy on it.
    expect(creator.session.peers.get(joiner.fpr).notebookSent).toBe(false);
  });

  it("tells the roster when a press changes who is holding it", async () => {
    const { creator, joiner } = await creatorAlone();
    await joinerArrives();
    const before = creator.rosters.length;
    await creator.session.shareNotebook(
      await cleartext(
        proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
        creator.privateKey
      )
    );
    // **The panel is drawn from the roster, and `notebookSent` moves inside the
    // press.** Without an emit here the line naming who is holding nothing went
    // on naming a peer the press had just written to, until some unrelated
    // event refreshed it — a warning that outlives its own condition, which
    // teaches the reader that pressing the button does nothing. Caught by the
    // browser suite pressing Share a second time, not by anything below it.
    //
    // The *count* and not the contents: `onRoster` hands out the live peer map,
    // so every entry is the same object and only the fact that an emit happened
    // is observable from here.
    expect(creator.rosters.length).toBeGreaterThan(before);
    expect(creator.session.peers.get(joiner.fpr).notebookSent).toBe(true);
  });

  it("retains nothing it would have refused to send", async () => {
    const { creator } = await creatorAlone();
    const raw = proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED }));
    await expect(creator.session.shareNotebook(raw)).rejects.toThrow(
      /notebook proposal must arrive here already signed/
    );
    // A document this session refuses to put on the wire is not one it may hold
    // and hand somebody later — so the refusal happens before anything is kept.
    expect(creator.session._sharedNotebook).toBe("");
  });

  it("does not outlive the session that held it", async () => {
    const { creator } = await creatorAlone();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: HANDED })),
      creator.privateKey
    );
    await creator.session.shareNotebook(signed);
    expect(creator.session._sharedNotebook).toBe(signed);
    // Recipe text, session-scoped, dropped with the room key and the invite
    // material — `memory-safety.js`'s rule 5 on the one notebook string this
    // class holds.
    creator.session.stop();
    expect(creator.session._sharedNotebook).toBe("");
  });
});

/* ────────────────────────── the product reaches it ───────────────────────── */

const read = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
const HOOK = read("../toolkit/useNotebook.ts");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const PANEL = read("../toolkit/widgets/NotebookShare.tsx");
const FRAGMENT = read("../lib/toolkit/fragment.js");

describe("who consumes this", () => {
  it("is reachable by a person, both ways", () => {
    // The recurring defect in this codebase is a finished mechanism with no
    // caller. `shareNotebook` and the adopt press are drawn in the Connections
    // tab, above the queue that presumed the notebook had already arrived.
    expect(SHELL).toContain("<NotebookShare");
    expect(SHELL).toContain("nb.shareNotebook()");
    expect(SHELL).toContain("nb.adoptProposedNotebook()");
    expect(SHELL).toContain("nb.dismissProposedNotebook()");
    expect(PANEL).toContain("data-notebook-proposed");
  });

  it("signs at the press and never in a module", () => {
    // `session.shareNotebook` refuses anything not cleartext-signed and there is
    // no path from a payload to the session's private key. The signing is the
    // shell's, at the moment somebody presses Share.
    expect(HOOK).toMatch(/signSessionDocument\(proposalToJson\(proposal\)\)/);
    expect(HOOK).toMatch(/session\.shareNotebook\(signed\)/);
  });

  it("decides with the rule, rather than with a second copy of it", () => {
    expect(HOOK).toMatch(/decideProposal\(\{/);
    expect(HOOK).not.toMatch(/here\.source\.trim\(\)/);
  });

  it("hands the kernel the notebook it is now holding", () => {
    // `loadRecipeText` replaced `chains` and told the kernel nothing, so every
    // per-cell status, timing, run error and artifact tile stayed attached to
    // its *index* while the cell underneath became somebody else's. A freshly
    // adopted cell read "ran 0s ago · 293ms" with the previous notebook's
    // `$session` tile beneath it. `placed-journey.e2e.js` step 6 is the check
    // that can see the header; this is the line that has to be there for it.
    const loader = /const loadRecipeText = useCallback\([\s\S]*?\n  \}, \[\]\);/.exec(HOOK);
    expect(loader, "loadRecipeText is not where this test thinks it is").toBeTruthy();
    expect(loader[0]).toMatch(/clearCellOutputs/);
    // Not the other two: staleness presumes the tile is still this cell's
    // answer, and a remap presumes a correspondence between old index and new.
    // Opening a different notebook has neither.
    expect(loader[0]).not.toMatch(/markAllWithOutputsStale|remapCells/);
  });

  it("moves the kernel's buckets when a delete renumbers the notebook", () => {
    // The same drift through the other mutation that changes what an index
    // means. `deleteCell` cleared the deleted index and stopped, so every cell
    // below it kept a bucket belonging to the cell above — the notebook drew a
    // cell reading "never run" beside one reading "ran 0s ago · 7ms" with the
    // *previous* cell's tile under a recipe that names a different slot.
    // `notebook-cells.e2e.js` is the check that can see the screen; these are
    // the two lines that have to be there for it, and `remapCells` had no
    // product caller at all before this one.
    const del = /const deleteCell = useCallback\([\s\S]*?\n  \}, \[\]\);/.exec(HOOK);
    expect(del, "deleteCell is not where this test thinks it is").toBeTruthy();
    // Both, in this order: the clear is what *wipes* the bytes the deleted cell
    // owned, and a remap that dropped the bucket instead would release them
    // without zeroizing. See the comment on `deleteCell` for the argument.
    expect(del[0].indexOf("clearCellOutputs")).toBeGreaterThanOrEqual(0);
    expect(del[0].indexOf("remapCells")).toBeGreaterThan(
      del[0].indexOf("clearCellOutputs")
    );
    // The mapping itself, because an off-by-one here is exactly the defect:
    // everything above the hole moves down one, and the hole is dropped.
    expect(del[0]).toMatch(/i === index \? null : i > index \? i - 1 : i/);
    // Nothing is marked stale — a cell that moved up is still holding its own
    // last answer, which is what separates a delete from a reorder.
    expect(del[0]).not.toMatch(/markAllWithOutputsStale/);
  });

  it("bumps the counter the slot tray is memoised on when it registers one", () => {
    // `acceptHandoff` bumped `sessionTick` — the vault's counter — while
    // `slotMetas` is memoised on `kernelEpoch`, so the tray went on saying "No
    // slots yet" about a value the shell had just reported registering.
    const accept = /const acceptHandoff = useCallback\([\s\S]*?\n  \);/.exec(HOOK);
    expect(accept, "acceptHandoff is not where this test thinks it is").toBeTruthy();
    expect(accept[0]).toMatch(/setKernelEpoch/);
    expect(accept[0]).not.toMatch(/setSessionTick/);
    // And the memo really is the one being bumped, so this is not two names for
    // a counter nothing reads.
    expect(HOOK).toMatch(/const slotMetas[\s\S]{0,600}\}, \[kernelEpoch\]\);/);
  });

  it("keeps one secret predicate for the URL and the wire", () => {
    // Moved to `recipe-secrets.js` and re-exported under the name every caller
    // already used. Two copies would agree until the first case only one of them
    // learned about.
    expect(FRAGMENT).toMatch(/from "\.\/recipe-secrets\.js"/);
    expect(FRAGMENT).not.toMatch(/BEGIN PGP PRIVATE KEY BLOCK/);
  });

  it("retires the retained notebook from the editor, on every mutation at once", () => {
    // **The retention is only honest while something invalidates it**, and the
    // session cannot: it holds a signed document and cannot see the editor. If
    // this effect went missing the mechanism would stop being a fix and become
    // a worse bug — a newcomer silently adopting text the dealer had typed past.
    //
    // The dependency list is the assertion, not the call. `source` is the
    // re-serialisation of whatever the notebook compiled to, so every mutator
    // that exists or ever will — typing, adding a cell, deleting one, adopting
    // a peer's — moves it, and none of them has to remember this. A boolean
    // "has been edited" maintained per mutator is the shape whose failure mode
    // is silent and destructive; `decideProposal` refuses one for the same
    // reason and says so at length.
    expect(HOOK).toMatch(
      /useEffect\(\(\) => \{\s*getLiveSession\(\)\?\.retireSharedNotebook\(\);\s*\}, \[source, title\]\);/
    );
    // Half the manifest digest is the title, so a rename is a different
    // notebook to every check on the receiving end.
    expect(HOOK).toMatch(/\}, \[source, title\]\);/);
    // And the editor never hands the session replacement text — that would be
    // a share on every keystroke, which is the ambient broadcast this must not
    // become. `retireSharedNotebook` takes no argument, and this is the line
    // that keeps it that way.
    expect(HOOK).not.toMatch(/retireSharedNotebook\(\s*[^)\s]/);
  });

  it("tells the dealer which peers are holding nothing, and names a remedy", () => {
    // The other half of the design, and the half with no mechanism before this:
    // a newcomer with an empty notebook in a room that has a shared one is a
    // state *nothing surfaced*, and a person cannot act on what nothing tells
    // them. The dealer's own screen is full of the notebook; the joiner has
    // nothing to ask about.
    expect(HOOK).toMatch(/const peersWithoutNotebook = useMemo/);
    // Verified peers only — one still meshing has missed nothing, and naming
    // them would ask the reader to act on a race.
    expect(HOOK).toMatch(/peer\.kcVerified && !peer\.notebookSent/);
    // Reachable by a person: exported from the hook and drawn by the shell.
    expect(HOOK).toMatch(/^\s{4}peersWithoutNotebook,$/m);
    expect(SHELL).toMatch(/nb\.peersWithoutNotebook\.length > 0/);
    expect(SHELL).toMatch(/data-notebook-unshared/);
    // The sentence names the state that is true and a remedy that can be
    // performed — the button is directly above it. "Ask them to share" would
    // name an act the other end has no way to know it should make.
    expect(SHELL).toMatch(/has not been given this notebook/);
    expect(SHELL).toMatch(/Share this notebook to send it/);
    // Whole keys. The row telling somebody which peer to act about is the last
    // place to print part of who they are, so it is the `Fingerprint` placard
    // and never a hand-rolled abbreviation.
    const line = /\{sessionLive &&[\s\S]*?\) : null\}/.exec(SHELL);
    expect(line, "the unshared-peers line is not where this test thinks it is").toBeTruthy();
    expect(line[0]).toMatch(/<Fingerprint fpr=\{fpr\} \/>/);
    expect(line[0]).not.toMatch(/slice\(|substring\(|…/);
    // Not folded into the share note: that is the outcome of the last press,
    // and a standing fact about the room overwriting it would erase the answer
    // to something the reader just did.
    expect(line[0]).not.toMatch(/setNotebookShareNote/);
  });

  it("says in the codec that an invite still carries no recipe, and how one travels now", () => {
    // The doctrine is not abandoned and the prose must not read as though it
    // were. `#j=` still carries an audience and no notebook.
    expect(FRAGMENT).toMatch(/no `r=` is merged into the `j=` form/);
    expect(FRAGMENT).toMatch(/notebook-share\.js/);
  });
});
