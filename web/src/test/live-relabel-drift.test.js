/**
 * The same drift, on a room that is already running.
 *
 * `peer-relabel.js` closed this for the *draft* audience, where one person is
 * composing and one person presses the control that renumbers everybody. A live
 * room is the harder half and was deliberately left: removing somebody moves the
 * room (`NotebookSession.rotateRoom`), the audience shrinks, and `peerLabels`
 * numbers what is left. It is the same arithmetic, reproduced here with nothing
 * of the fix involved — a three-key room [ADA, BEA, CEC] hands out
 *
 *     peer1=AAAA  peer2=BBBB  peer3=CCCC
 *
 * and removing BEA leaves
 *
 *     peer1=AAAA  peer2=CCCC
 *
 * so a cell placed on CEC still says `@peer3` and now names nobody at all,
 * while a cell placed on the person who was just removed still says `@peer2`
 * and is now addressed to CEC — the removed member's number, taken over by the
 * member who stayed, with nothing on screen having moved.
 *
 * ## What makes the live case a different decision
 *
 * On a draft, one browser holds the notebook. Here every member holds one, and
 * `buildRunManifest` digests the roster into `peersSha`: two peers committing to
 * different `{label: fingerprint}` bindings produce offers neither can accept.
 * So it is not enough for the machine that pressed Remove to do the right thing
 * — the room has to arrive at *one* binding, and this file's job is to
 * demonstrate that rather than to assert that one machine behaved.
 *
 * The rewrite is therefore **local and derived, not carried**: the mapping is a
 * pure function of the audience before and the audience after, both of which
 * every remaining member already holds identically, so no new message is sent
 * and none is needed. `useNotebook.followRotation` argues it at length. The
 * tests below are written so that the alternatives fail:
 *
 *  - "leave the numbers alone" fails on the literal labels asserted;
 *  - "follow the number rather than the person" fails on the independent check
 *    that each label resolves back to the key the cell was placed on;
 *  - "let one machine rewrite and the others not" fails on the convergence
 *    tests, which apply the rotation to two notebooks and require one binding
 *    and one manifest digest out the other end.
 *
 * Nothing here builds an expectation out of `peerLabels`. It is the function the
 * rule reads, so an expectation derived from it would assert only that the rule
 * agrees with itself.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { peerLabels, roomRoster } from "../lib/notebook/roster.js";
import { relabelAudience, relabelPlacements } from "../lib/toolkit/peer-relabel.js";
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

/** One member's copy of a notebook, rewritten as `followRotation` rewrites it. */
function follow(source, beforeFprs, afterFprs) {
  const moved = relabelAudience(beforeFprs, afterFprs);
  const { edits, note } = relabelPlacements(compileRecipe(source).ast.chains, moved);
  return { source: applyEdits(source, edits), edits, note };
}

/* ─────────────────────────── the drift itself ─────────────────────────── */

describe("what removing somebody does to a notebook already written", () => {
  it("hands the removed member's number to the member who stayed", () => {
    // No fix involved: this is what the product does today, on both machines.
    const before = peerLabels(BEFORE);
    const after = peerLabels(AFTER);
    expect(before.get(BEA)).toBe("peer2");
    expect(after.get(CEC)).toBe("peer2");
    // And CEC's old number now names nobody, so a cell left on it runs nowhere.
    expect([...after.values()]).not.toContain("peer3");
  });

  it("is a shrink and never a grow, which is why nobody is ever added here", () => {
    // `rotateRoom` filters the audience by a remove list and cannot extend it,
    // so the live half of this hazard is always somebody leaving. The draft
    // half is the one where people arrive.
    const moved = relabelAudience(BEFORE, AFTER);
    expect([...moved]).toEqual([
      ["peer2", null],
      ["peer3", "peer2"],
    ]);
  });
});

/* ──────────────────────── the decision, both sides ─────────────────────── */

describe("a live placement follows the person, not the number", () => {
  const SOURCE = ["@peer1", "random 32 | out $a", "", "@peer3 publish", "random 32 | out $b"].join(
    "\n"
  );

  it("moves the header to the label that member holds after the rotation", () => {
    const { source, edits, note } = follow(SOURCE, BEFORE, AFTER);

    // Literals, so "refuse to renumber" — which would leave `@peer3` — fails
    // right here rather than somewhere downstream.
    expect(edits).toEqual([{ cell: 1, peer: "peer2", publish: true, publishSlots: [] }]);
    expect(source).toBe("@peer1\nrandom 32 | out $a\n\n@peer2 publish\nrandom 32 | out $b");

    // The independent check, from the other end: the label the cell now carries
    // has to resolve to the key it was placed on. A rewrite that followed the
    // *number* would have left `@peer3`, which the room no longer binds at all.
    expect(roomRoster(AFTER).roster.peer2).toBe(CEC);
    expect(note).toContain("cell 1 says @peer2 where it said @peer3");
  });

  it("unassigns the removed member's cells rather than leaving the number", () => {
    // The draft's rule, and it holds here for the same reason and more sharply:
    // the vacated number is not merely reused later, it is occupied the instant
    // the rotation lands. Leaving `@peer2` in place would hand BEA's cell to
    // CEC, who is still in the room and would run it.
    const src = "@peer2 publish\nrandom 32 | out $secret";
    const { source, edits, note } = follow(src, BEFORE, AFTER);
    expect(edits).toEqual([{ cell: 0, peer: null, publish: false, publishSlots: [] }]);
    expect(source).toBe("random 32 | out $secret");
    expect(roomRoster(AFTER).roster.peer2).toBe(CEC);
    expect(note).toContain("no longer in the room");
  });

  it("writes the header through the recipe layer, so it parses back", () => {
    // `serializeStep`'s quoting has broken this repo before. Nothing in the
    // rewrite touches text — this is the assertion that would notice if it did.
    const { source } = follow(SOURCE, BEFORE, AFTER);
    const { ast, validation } = compileRecipe(source);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    expect(ast.chains.map((c) => c.peer || "")).toEqual(["peer1", "peer2"]);
    expect(ast.chains[1].publish).toBe(true);
  });
});

/* ───────────────────── two notebooks, one binding ──────────────────────── */

/**
 * The notebook both members hold. Placed on all three so the rotation has
 * something to move, something to strand, and something to leave alone.
 */
const SHARED = `@peer1 publish
bytes deadbeef | encode hex | out $seed

@peer3 publish
in $seed | decode hex | encode base64 | out $b64

@peer1
in $b64 | decode base64 | encode hex | out $final
`;

/** What one member derives from its own copy, after its own rewrite. */
async function memberContext(source, audience, selfFpr) {
  const { roster, me } = roomRoster(audience, [], selfFpr);
  return handoffContext({ source, me, roster, title: "rotation" });
}

describe("both members reach the same binding without exchanging one", () => {
  it("rewrites two copies identically, because the mapping is the same fact", async () => {
    // ADA ordered the rotation; CEC was told about it. Neither sent the other
    // anything about labels — each derived the mapping from the audience it
    // held before and the audience it holds now, which `_handleSignal` makes
    // identical on both.
    const ada = follow(SHARED, BEFORE, AFTER);
    const cec = follow(SHARED, BEFORE, AFTER);
    expect(ada.source).toBe(cec.source);
    // Literal, so a rewrite that produced *some* agreed answer rather than the
    // right one still fails: peer3 became peer2 and peer1 was not disturbed.
    expect(ada.source).toContain("@peer2 publish\n$seed | decode hex");
    expect(ada.source).toContain("@peer1 publish\nbytes deadbeef");

    // And each label resolves to the key its cell was placed on, on both
    // machines, checked against the roster rather than against the rewrite.
    const { roster } = roomRoster(AFTER);
    expect(roster.peer1).toBe(ADA);
    expect(roster.peer2).toBe(CEC);
  });

  it("digests to one manifest, which is what `peersSha` requires of them", async () => {
    const ada = follow(SHARED, BEFORE, AFTER);
    const cec = follow(SHARED, BEFORE, AFTER);
    const ctxA = await memberContext(ada.source, AFTER, ADA);
    const ctxC = await memberContext(cec.source, AFTER, CEC);

    expect(ctxA.manifest.peers).toEqual(["peer1", "peer2"]);
    expect(await manifestDigest(ctxA.manifest)).toBe(await manifestDigest(ctxC.manifest));
    // Two machines, two answers to "which of these am I" — that part must not
    // converge, or every cell would be somebody else's on both.
    expect([ctxA.plan.me, ctxC.plan.me]).toEqual(["peer1", "peer2"]);
    expect(ctxA.plan.cells.map((c) => c.mine)).toEqual([true, false, true]);
    expect(ctxC.plan.cells.map((c) => c.mine)).toEqual([false, true, false]);
  });

  it("carries a cell across the rotation and has it accepted on the other side", async () => {
    // The whole arc, after the room moved: ADA runs, the gate declines the cell
    // that is now CEC's under a number CEC did not hold when the notebook was
    // written, and CEC accepts an offer for it.
    const ada = follow(SHARED, BEFORE, AFTER);
    const cec = follow(SHARED, BEFORE, AFTER);
    const ctxA = await memberContext(ada.source, AFTER, ADA);
    const ctxC = await memberContext(cec.source, AFTER, CEC);

    const registry = createSlotRegistry();
    /** @type {any[]} */
    const skipped = [];
    await runRecipe(compileRecipe(ada.source).ast, {}, {
      slotRegistry: registry,
      placement: { plan: ctxA.plan, onSkip: (s) => skipped.push(s) },
    }).catch(() => {
      /* a placed run stops at the cell whose input lives elsewhere — by design */
    });
    expect(skipped.map((s) => s.cell)).toEqual([1]);
    expect(skipped[0].waitingOn).toBe("peer2");

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
    // holding different text. The rewrite is per-notebook, so what converges is
    // the *binding* and not the text: both end up meaning the same key by
    // `@peer2`, and both still refuse each other's offers on the digest — which
    // they did before the rotation and for the same reason.
    const ada = follow(SHARED, BEFORE, AFTER);
    const cec = follow(`${SHARED}\n@peer3\nrandom 8 | out $extra\n`, BEFORE, AFTER);
    const ctxA = await memberContext(ada.source, AFTER, ADA);
    const ctxC = await memberContext(cec.source, AFTER, CEC);

    expect(ctxA.manifest.peers).toEqual(ctxC.manifest.peers);
    expect(ctxA.manifest.peersSha).toBe(ctxC.manifest.peersSha);
    expect(await manifestDigest(ctxA.manifest)).not.toBe(await manifestDigest(ctxC.manifest));
    // The extra cell followed the same person as the shared one did.
    expect(cec.source.match(/@peer2/g)).toHaveLength(2);
  });
});

/* ───────────────── the window where only one has moved ─────────────────── */

describe("between one member applying the rotation and the other", () => {
  it("refuses, naming a state that is true, and heals when the second follows", async () => {
    // ADA has rotated and rewritten; CEC has not yet seen the announce, so it
    // is still deriving the three-key roster. That is a real window — the
    // announce is a sealed envelope over the relay — and what it must not
    // produce is a *binding* that silently disagrees. A refusal is the right
    // answer while it lasts.
    const ada = follow(SHARED, BEFORE, AFTER);
    const ctxA = await memberContext(ada.source, AFTER, ADA);
    const stale = await memberContext(SHARED, BEFORE, CEC);

    expect(await manifestDigest(ctxA.manifest)).not.toBe(await manifestDigest(stale.manifest));
    expect(ctxA.manifest.peers).not.toEqual(stale.manifest.peers);

    const registry = createSlotRegistry();
    /** @type {any[]} */
    const skipped = [];
    await runRecipe(compileRecipe(ada.source).ast, {}, {
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

    // The same offer, once CEC applies the same rotation to the same notebook.
    // Nothing was re-sent and nothing was re-derived from a message: the
    // announce that moved CEC's room is what moved CEC's labels.
    const cec = follow(SHARED, BEFORE, AFTER);
    const ctxC = await memberContext(cec.source, AFTER, CEC);
    const healed = await reviewOffer(ctxC, built.json, () => false);
    expect(healed.ok, healed.refusals.map((r) => r.reason).join(", ")).toBe(true);
  });
});

/* ───────────────────────────── the wiring ─────────────────────────────── */

/**
 * The hook is React and this suite runs in node, so what can be pinned here is
 * that the rewrite is hung off the *observation* and not off the press, and
 * that the fact it observes is one every member receives. The behaviour of the
 * two ends of that wire is pinned where it can run: `notebook-rotation.test.js`
 * drives two live sessions through a rotation, and `quorum-lifecycle.test.js`
 * drives the snapshot a member who ordered nothing ends up holding.
 */
describe("the hook watches the room rather than the button", () => {
  const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
  const HOOK = read("../toolkit/useNotebook.ts");
  const OPS = read("../lib/toolkit/quorum-ops.js");
  const SESSION = read("../lib/notebook/session.js");

  it("does not rewrite anything inside `removeFromRoom`", () => {
    // The press happens on one machine. A rewrite here would relabel the
    // initiator and leave everybody else on the old numbering, which is the
    // one outcome worse than the drift: today the room is wrong together.
    const at = HOOK.indexOf("const removeFromRoom");
    const body = HOOK.slice(at, HOOK.indexOf("}, []);", at));
    expect(body).toContain("rotateQuorumRoom([fingerprint])");
    expect(body).not.toContain("relabelPlacements");
    expect(body).not.toContain("setCellPeer");
  });

  it("rewrites from the audience change, through the mutator CellAssign presses", () => {
    expect(HOOK).toMatch(
      /import \{ relabelAudience, relabelPlacements \} from "\.\.\/lib\/toolkit\/peer-relabel\.js"/
    );
    expect(HOOK).toMatch(/const moved = relabelAudience\(before, after\)/);
    expect(HOOK).toMatch(/followRotation\(was\.audience, audience\)/);
    expect(HOOK).toMatch(
      /setCellPeer\(edit\.cell, edit\.peer, edit\.publish, edit\.publishSlots\)/
    );
    // The epoch is the guard, not the audience: a different room opening is not
    // this room renumbering.
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
