/**
 * Removing somebody from a room that is already running.
 *
 * ## The drift this file was written for, and where it went
 *
 * `peerLabels` numbered the audience in `canonicalAudience` order, so a
 * three-key room [ADA, BEA, CEC] handed out
 *
 *     peer1=AAAA  peer2=BBBB  peer3=CCCC
 *
 * and removing BEA left
 *
 *     peer1=AAAA  peer2=CCCC
 *
 * so a cell placed on CEC still said `@peer3` and named nobody, while a cell
 * placed on the member who had just been removed still said `@peer2` and was now
 * addressed to CEC — the removed member's number, taken over by the member who
 * stayed, with nothing on screen having moved. `4b3305d` closed that by
 * rewriting every header whenever the audience changed.
 *
 * **A peer is the whole fingerprint now, so the renumbering half of that is
 * gone.** Removing BEA renames nobody: CEC is called what CEC was called, and no
 * header anywhere has to move. This file therefore asserts the *absence* of the
 * rewrite on the members who stayed, which is the strongest form of the claim
 * and fails loudly if any positional naming returns.
 *
 * ## What is left, and why it is still here
 *
 * The cells placed on the member who **left**. Those never ran and never will —
 * `planRun` refuses them `unknown-peer` — so they are unassigned and the reader
 * is told. That was always a separate question from renumbering; it simply used
 * to have a second and worse reason behind it (the vacated number was occupied
 * immediately), and that reason is now unavailable rather than merely unused.
 *
 * ## What makes the live case a different decision from the draft
 *
 * On a draft, one browser holds the notebook. Here every member holds one, and
 * `buildRunManifest` digests the roster into `peersSha`: two peers committing to
 * different bindings produce offers neither can accept. So it is not enough for
 * the machine that pressed Remove to do the right thing — the room has to arrive
 * at *one* binding.
 *
 * It does, and now it does so for a stronger reason than the rewrite ever gave:
 * the binding is identity-mapped, so two members holding the same audience agree
 * by construction with nothing derived and nothing carried. The convergence
 * tests below are kept — they are what would fail if a naming layer came back —
 * and they no longer depend on two machines performing the same edit.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { roomRoster } from "../lib/notebook/roster.js";
import { departedPeers, unassignDeparted } from "../lib/toolkit/peer-relabel.js";
import { manifestDigest } from "../lib/toolkit/manifest.js";
import { handoffContext, offerForSkipped, reviewOffer } from "../lib/toolkit/handoff-shell.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";

/** Three keys whose sort order is their name, so the arithmetic is readable. */
const ADA = "AAAA111122223333444455556666777788889999";
const BEA = "BBBB111122223333444455556666777788889999";
const CEC = "CCCC111122223333444455556666777788889999";

/** The room as it was invited, and as it stands after BEA is removed. */
const BEFORE = [ADA, BEA, CEC];
const AFTER = [ADA, CEC];

/**
 * Apply the edits the way `setCellPeer` does — the chain field, never the text.
 *
 * The same helper `relabel-drift.test.js` uses, and copied rather than shared
 * for the reason it gives: it is a restatement of the mutator under test, and a
 * restatement that drifted from the mutator would be the only thing either file
 * was really checking.
 */
function applyEdits(source, edits) {
  const chains = compileRecipe(source).ast.chains.map((chain) => ({ ...chain }));
  for (const edit of edits) {
    const chain = chains[edit.cell];
    delete chain.peer;
    delete chain.publish;
    delete chain.publishSlots;
    if (edit.peer) {
      chain.peer = edit.peer;
      if (edit.publish) chain.publish = true;
      if (edit.publish && edit.publishSlots.length) {
        chain.publishSlots = [...edit.publishSlots];
      }
    }
  }
  return serializeRecipe(chains);
}

/** One member's copy, after `dropDepartedPlacements` has run on it. */
function follow(source, beforeFprs, afterFprs) {
  const gone = departedPeers(beforeFprs, afterFprs);
  const { edits, note } = unassignDeparted(compileRecipe(source).ast.chains, gone);
  return { source: applyEdits(source, edits), edits, note };
}

/* ─────────────────────────── the drift itself ─────────────────────────── */

describe("what removing somebody does to a notebook already written", () => {
  it("does not hand the removed member's name to the member who stayed", () => {
    // The inversion. Under the numbering, BEA was `peer2` and CEC became
    // `peer2` the instant BEA left, so a cell placed on the removed member came
    // to address somebody still in the room who would run it. Nobody inherits a
    // key.
    const before = roomRoster(BEFORE).roster;
    const after = roomRoster(AFTER).roster;
    expect(before[BEA]).toBe(BEA);
    expect(after[BEA]).toBeUndefined();
    // And CEC answers to exactly what CEC answered to before. Under the old
    // rule this was the assertion that CEC's *name* had changed.
    expect(after[CEC]).toBe(before[CEC]);
  });

  it("is a shrink and never a grow, which is why nobody is ever added here", () => {
    // `rotateRoom` filters the audience by a remove list and cannot extend it,
    // so the live half of this hazard is always somebody leaving. The draft
    // half is the one where people arrive — and neither half renames anybody.
    expect([...departedPeers(BEFORE, AFTER)]).toEqual([BEA]);
    expect([...departedPeers(AFTER, BEFORE)]).toEqual([]);
  });
});

/* ──────────────────────── the decision, both sides ─────────────────────── */

describe("a live placement outlasts everybody except its own person", () => {
  const SOURCE = [`@${ADA}`, "random 32 | out $a", "", `@${CEC} publish`, "random 32 | out $b"].join(
    "\n"
  );

  it("leaves the notebook alone when the person stayed", () => {
    const { source, edits, note } = follow(SOURCE, BEFORE, AFTER);

    // Byte for byte. This is the assertion that "leave the numbers alone" could
    // never have passed under the old rule, and it is now the correct one — the
    // room really did move, and no header in it named a position.
    expect(edits).toEqual([]);
    expect(source).toBe(SOURCE);
    expect(note).toBe("");
    // The independent check, from the other end: the peer each cell names still
    // resolves in the room that is left.
    expect(roomRoster(AFTER).roster[CEC]).toBe(CEC);
    expect(roomRoster(AFTER).roster[ADA]).toBe(ADA);
  });

  it("unassigns the removed member's cells", () => {
    // The half that stayed. It is the same rule the draft applies, and its
    // reason is now the simpler of the two the old file gave: a cell addressed
    // to a key that is not in the room will never run.
    const src = `@${BEA} publish\nrandom 32 | out $secret`;
    const { source, edits, note } = follow(src, BEFORE, AFTER);
    expect(edits).toEqual([{ cell: 0, peer: null, publish: false, publishSlots: [] }]);
    expect(source).toBe("random 32 | out $secret");
    expect(note).toContain("no longer in the room");
    // The worse reason, gone: nobody in the room after the rotation answers to
    // the departed key, so leaving the header would have stranded the cell
    // rather than handing it to the member who stayed.
    expect(roomRoster(AFTER).roster[BEA]).toBeUndefined();
  });

  it("writes the header through the recipe layer, so it parses back", () => {
    // `serializeStep`'s quoting has broken this repo before. Nothing in the
    // rewrite touches text — this is the assertion that would notice if it did.
    const src = `${SOURCE}\n\n@${BEA} publish=$c\nrandom 32 | out $c`;
    const { source } = follow(src, BEFORE, AFTER);
    const { ast, validation } = compileRecipe(source);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    expect(ast.chains.map((c) => c.peer || "")).toEqual([ADA, CEC, ""]);
    expect(ast.chains[1].publish).toBe(true);
    // `publish` left with the peer: a modifier attached to nobody is not a
    // claim about anything, and a header that kept it would not compile.
    expect(ast.chains[2].publish).toBeUndefined();
  });
});

/* ───────────────────── two notebooks, one binding ──────────────────────── */

/**
 * The notebook both members hold. Placed on all three so the rotation has
 * something to strand and something to leave alone.
 */
const SHARED = `@${ADA} publish
bytes deadbeef | encode hex | out $seed

@${CEC} publish
in $seed | decode hex | encode base64 | out $b64

@${ADA}
in $b64 | decode base64 | encode hex | out $final
`;

/** What one member derives from its own copy, after its own rewrite. */
async function memberContext(source, audience, selfFpr) {
  const { roster, me } = roomRoster(audience, [], selfFpr);
  return handoffContext({ source, me, roster, title: "rotation" });
}

describe("both members reach the same binding without exchanging one", () => {
  it("holds two identical copies, because neither had anything to change", async () => {
    // ADA ordered the rotation; CEC was told about it. Neither sent the other
    // anything about who is called what, and neither had to derive it: the
    // binding is the key. This used to be the test that two independently
    // computed rewrites agreed.
    const ada = follow(SHARED, BEFORE, AFTER);
    const cec = follow(SHARED, BEFORE, AFTER);
    expect(ada.source).toBe(cec.source);
    // Against the *serialized* original rather than the literal: `applyEdits`
    // re-serializes whatever it is given, so comparing to the source string
    // would be asserting that the serializer is a no-op on it, which is a
    // different claim and not this one.
    expect(ada.source).toBe(applyEdits(SHARED, []));

    // And each header resolves to the key its cell was placed on, checked
    // against the roster rather than against the rewrite.
    const { roster } = roomRoster(AFTER);
    expect(roster[ADA]).toBe(ADA);
    expect(roster[CEC]).toBe(CEC);
  });

  it("digests to one manifest, which is what `peersSha` requires of them", async () => {
    const ctxA = await memberContext(SHARED, AFTER, ADA);
    const ctxC = await memberContext(SHARED, AFTER, CEC);

    expect(ctxA.manifest.peers).toEqual([ADA, CEC].sort());
    expect(await manifestDigest(ctxA.manifest)).toBe(await manifestDigest(ctxC.manifest));
    // Two machines, two answers to "which of these am I" — that part must not
    // converge, or every cell would be somebody else's on both.
    expect([ctxA.plan.me, ctxC.plan.me]).toEqual([ADA, CEC]);
    expect(ctxA.plan.cells.map((c) => c.mine)).toEqual([true, false, true]);
    expect(ctxC.plan.cells.map((c) => c.mine)).toEqual([false, true, false]);
  });

  it("carries a cell across the rotation and has it accepted on the other side", async () => {
    // The whole arc, after the room moved: ADA runs, the gate declines the cell
    // that is CEC's, and CEC accepts an offer for it.
    const ctxA = await memberContext(SHARED, AFTER, ADA);
    const ctxC = await memberContext(SHARED, AFTER, CEC);

    const registry = createSlotRegistry();
    /** @type {any[]} */
    const skipped = [];
    await runRecipe(compileRecipe(SHARED).ast, {}, {
      slotRegistry: registry,
      placement: { plan: ctxA.plan, onSkip: (s) => skipped.push(s) },
    }).catch(() => {
      /* a placed run stops at the cell whose input lives elsewhere — by design */
    });
    expect(skipped.map((s) => s.cell)).toEqual([1]);
    expect(skipped[0].waitingOn).toBe(CEC);

    const built = await offerForSkipped(ctxA, skipped[0], (l) =>
      registry.has(l) ? registry.resolve(l) : null
    );
    expect(built.ok, JSON.stringify(built.refusals)).toBe(true);
    const verdict = await reviewOffer(ctxC, built.json, () => false);
    expect(verdict.ok, verdict.refusals.map((r) => r.reason).join(", ")).toBe(true);
    expect(verdict.bindings.map((b) => b.label)).toEqual(["seed"]);
  });

  it("converges the binding even where the two notebooks have diverged", async () => {
    // `notebook-share.js` lets a peer decline a proposal, so two members can be
    // holding different text. What converges is the *binding* and not the text:
    // both mean the same key by the same header, and both still refuse each
    // other's offers on the digest — which they did before the rotation and for
    // the same reason.
    const cecSource = `${SHARED}\n@${CEC}\nrandom 8 | out $extra\n`;
    const ctxA = await memberContext(SHARED, AFTER, ADA);
    const ctxC = await memberContext(cecSource, AFTER, CEC);

    expect(ctxA.manifest.peers).toEqual(ctxC.manifest.peers);
    expect(ctxA.manifest.peersSha).toBe(ctxC.manifest.peersSha);
    expect(await manifestDigest(ctxA.manifest)).not.toBe(await manifestDigest(ctxC.manifest));
  });
});

/* ───────────────── the window where only one has moved ─────────────────── */

describe("between one member applying the rotation and the other", () => {
  it("refuses, naming a state that is true, and heals when the second follows", async () => {
    // ADA has rotated; CEC has not yet seen the announce, so it is still
    // deriving the three-key roster. That is a real window — the announce is a
    // sealed envelope over the relay — and the disagreement is now purely about
    // *who is in the room*, which is the thing a `peersSha` is supposed to
    // commit to. A refusal is the right answer while it lasts.
    const ctxA = await memberContext(SHARED, AFTER, ADA);
    const stale = await memberContext(SHARED, BEFORE, CEC);

    expect(await manifestDigest(ctxA.manifest)).not.toBe(await manifestDigest(stale.manifest));
    expect(ctxA.manifest.peers).not.toEqual(stale.manifest.peers);

    const registry = createSlotRegistry();
    /** @type {any[]} */
    const skipped = [];
    await runRecipe(compileRecipe(SHARED).ast, {}, {
      slotRegistry: registry,
      placement: { plan: ctxA.plan, onSkip: (s) => skipped.push(s) },
    }).catch(() => {});
    const built = await offerForSkipped(ctxA, skipped[0], (l) =>
      registry.has(l) ? registry.resolve(l) : null
    );

    const early = await reviewOffer(stale, built.json, () => false);
    expect(early.ok).toBe(false);
    expect(early.refusals.map((r) => r.reason)).toContain("unknown-manifest");
    expect(early.refusals[0].message).toContain("not holding the same notebook");

    // The same offer, once CEC's room has moved too. Nothing was re-sent and
    // nothing was re-derived from a message: the announce that moved CEC's room
    // is the whole of what had to happen.
    const ctxC = await memberContext(SHARED, AFTER, CEC);
    const healed = await reviewOffer(ctxC, built.json, () => false);
    expect(healed.ok, healed.refusals.map((r) => r.reason).join(", ")).toBe(true);
  });
});

/* ───────────────────────────── the wiring ─────────────────────────────── */

/**
 * The hook is React and this suite runs in node, so what can be pinned here is
 * that the edit is hung off the *observation* and not off the press, and that
 * the fact it observes is one every member receives. The behaviour of the two
 * ends of that wire is pinned where it can run: `notebook-rotation.test.js`
 * drives two live sessions through a rotation, and `quorum-lifecycle.test.js`
 * drives the snapshot a member who ordered nothing ends up holding.
 */
describe("the hook watches the room rather than the button", () => {
  const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
  const HOOK = read("../toolkit/useNotebook.ts");
  const OPS = read("../lib/toolkit/quorum-ops.js");
  const SESSION = read("../lib/notebook/session.js");

  it("does not edit anything inside `removeFromRoom`", () => {
    // The press happens on one machine. An edit here would strand cells on the
    // initiator and leave everybody else holding them, which is the one outcome
    // worse than doing nothing: today the room is wrong together.
    const at = HOOK.indexOf("const removeFromRoom");
    const body = HOOK.slice(at, HOOK.indexOf("}, []);", at));
    expect(body).toContain("rotateQuorumRoom([fingerprint])");
    expect(body).not.toContain("unassignDeparted");
    expect(body).not.toContain("setCellPeer");
  });

  it("edits from the audience change, through the mutator CellAssign presses", () => {
    expect(HOOK).toMatch(
      /import \{ departedPeers, unassignDeparted \} from "\.\.\/lib\/toolkit\/peer-relabel\.js"/
    );
    expect(HOOK).toMatch(/departedPeers\(before, after\)/);
    expect(HOOK).toMatch(/dropDepartedPlacements\(was\.audience, audience\)/);
    expect(HOOK).toMatch(
      /setCellPeer\(edit\.cell, edit\.peer, edit\.publish, edit\.publishSlots\)/
    );
    // The epoch is the guard, not the audience: a different room opening is not
    // this room shrinking.
    expect(HOOK).toMatch(/if \(!was \|\| epoch <= was\.epoch\) return;/);
  });

  it("says what it did, on the one surface that is on screen either way", () => {
    // The draft narrates on the session sheet because that is where the press
    // was. Here the reader who most needs the sentence pressed nothing and may
    // have no sheet open at all.
    expect(HOOK).toMatch(/setRunStatus\(`The room moved and somebody is no longer in it/);
  });

  it("learns about the move on every member, not only the one that ordered it", () => {
    // The transport tells the layer above at the end of `_applyRotation`, which
    // is the line both `rotateRoom` and the `rotate` branch of `_handleSignal`
    // arrive at. Before this the snapshot was patched inside
    // `rotateQuorumRoom`, which only the initiator ever calls.
    expect(SESSION).toMatch(/this\.onRotate\?\.\(\{/);
    expect(OPS).toMatch(/onRotate: \(\{ epoch, roomId, audience \}\) => \{/);
    const rotate = OPS.slice(OPS.indexOf("export async function rotateQuorumRoom"));
    expect(rotate.slice(0, 400)).not.toContain("patchState");
  });
});
