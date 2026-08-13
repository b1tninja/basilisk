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

afterEach(() => {
  pair?.stop();
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
const HANDED = `@peer1 publish
bytes deadbeef | encode hex | out $seed

@peer2 publish
$seed | decode hex | encode base64 | out $b64

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
    expect(() => parseNotebookProposal(forged)).toThrow(/private key material/);
  });

  it("refuses a fingerprint written where a peer label belongs", () => {
    // The third arm of `recipeLooksSecret`, and the reason the predicate was
    // moved out of the URL codec rather than copied: one rule, every boundary.
    expect(() =>
      buildNotebookProposal({ title: TITLE, source: `@${FPR_1} publish\nbytes ca | out $x` })
    ).toThrow(/looks like it holds secret material/);
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
    expect(await until(() => joiner.notebooks.length > 0)).toBe(true);

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

  it("keeps one secret predicate for the URL and the wire", () => {
    // Moved to `recipe-secrets.js` and re-exported under the name every caller
    // already used. Two copies would agree until the first case only one of them
    // learned about.
    expect(FRAGMENT).toMatch(/from "\.\/recipe-secrets\.js"/);
    expect(FRAGMENT).not.toMatch(/BEGIN PGP PRIVATE KEY BLOCK/);
  });

  it("says in the codec that an invite still carries no recipe, and how one travels now", () => {
    // The doctrine is not abandoned and the prose must not read as though it
    // were. `#j=` still carries an audience and no notebook.
    expect(FRAGMENT).toMatch(/no `r=` is merged into the `j=` form/);
    expect(FRAGMENT).toMatch(/notebook-share\.js/);
  });
});
