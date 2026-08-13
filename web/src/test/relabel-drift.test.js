/**
 * A cell assigned to Grace stays assigned to Grace.
 *
 * `peerLabels` numbers the audience in `canonicalAudience` order — sorted
 * fingerprints — because a label has to mean the same person in every browser.
 * The cost is that the numbering is a function of key material: put a third
 * person in a room of two and whoever sorts below them moves down one. A
 * notebook written before that happened still says `@peer2`, and `@peer2` is
 * now somebody else. Nothing on screen changes, nothing refuses, and the run
 * hands a cell to the wrong machine.
 *
 * That drift is reproducible in four lines and was live in the product:
 * `peerLabels(["BBBB…", "CCCC…"])` binds `CCCC…` to `peer2`, and
 * `peerLabels(["BBBB…", "CCCC…", "AAAA…"])` binds `BBBB…` to it.
 *
 * The decision — argued in `peer-relabel.js` — is that the header follows the
 * person. This file pins it from the side that would fail under the other
 * choice, which is the only way a decision can be pinned: it asserts the
 * literal label the cell must now carry, so "leave the numbers alone" fails
 * here, *and* asserts the fingerprint that label resolves to, so a rewrite that
 * followed the number rather than the person fails too.
 *
 * The literals are deliberate. Deriving the expected label from `peerLabels` —
 * the function under test's own input — would assert that the rule agrees with
 * itself, which it does whatever it says.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { peerLabels, roomRoster } from "../lib/notebook/roster.js";
import { relabelAudience, relabelPlacements } from "../lib/toolkit/peer-relabel.js";

/** Three keys whose sort order is their name, so the arithmetic is readable. */
const ADA = "AAAA111122223333444455556666777788889999";
const BEA = "BBBB111122223333444455556666777788889999";
const CEC = "CCCC111122223333444455556666777788889999";

/**
 * Apply the edits the way the shell does — through the chain field, never the
 * text — and hand back the notebook's own source.
 *
 * `setCellPeer` is the mutator on the other side of this in `useNotebook`, and
 * it does exactly this: replace `peer`/`publish`/`publishSlots` on the chain
 * and let `serializeRecipe` write the header. Reproducing it here rather than
 * mounting the hook keeps the suite in node, and the property under test is the
 * pure one — that the edits describe the right cells and the right labels.
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

describe("the drift the audience sort causes", () => {
  it("renumbers a label onto a different person when somebody is added", () => {
    // The defect itself, with no fix involved. This is what a notebook written
    // against the first audience means once the second one exists.
    const before = peerLabels([BEA, CEC]);
    const after = peerLabels([BEA, CEC, ADA]);
    expect(before.get(CEC)).toBe("peer2");
    expect(after.get(CEC)).toBe("peer3");
    expect(after.get(BEA)).toBe("peer2");
  });

  it("says nothing when the numbering did not actually move", () => {
    // A key that sorts last takes the next number and disturbs nobody. A note
    // here would be a rewrite narrated for a rewrite that did not happen.
    const moved = relabelAudience([ADA, BEA], [ADA, BEA, CEC]);
    expect([...moved]).toEqual([]);
    expect(relabelPlacements([{ steps: [], peer: "peer1" }], moved).note).toBe("");
  });
});

describe("a placement follows the person, not the number", () => {
  const SOURCE = "@peer2 publish\nrandom 32 | out $secret";

  it("moves the header to the label that member now holds", () => {
    const moved = relabelAudience([BEA, CEC], [BEA, CEC, ADA]);
    const { edits, note } = relabelPlacements(compileRecipe(SOURCE).ast.chains, moved);

    // The literal, so "refuse to renumber" — which leaves `peer2` in place —
    // fails right here.
    expect(edits).toEqual([
      { cell: 0, peer: "peer3", publish: true, publishSlots: [] },
    ]);
    expect(applyEdits(SOURCE, edits)).toBe("@peer3 publish\nrandom 32 | out $secret");

    // And the other side of the decision: the label the cell now carries has to
    // resolve to the key it was placed on. A rewrite that followed the *number*
    // would have left `peer2`, which is BEA in the new room.
    const { roster } = roomRoster([BEA, CEC, ADA]);
    expect(roster.peer3).toBe(CEC);

    expect(note).toContain("cell 0 says @peer3 where it said @peer2");
    expect(note).toContain("followed the person");
  });

  it("writes the header through the recipe layer, so it parses back", () => {
    // `serializeStep`'s quoting has broken this repo before, when a session
    // wrote a comma into an argument unquoted and the notebook stopped
    // compiling. Nothing here edits text — but the assertion that it round
    // trips is the one that would notice if somebody made it.
    const moved = relabelAudience([BEA, CEC], [BEA, CEC, ADA]);
    const { edits } = relabelPlacements(compileRecipe(SOURCE).ast.chains, moved);
    const rewritten = applyEdits(SOURCE, edits);
    const { ast, validation } = compileRecipe(rewritten);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    expect(ast.chains[0].peer).toBe("peer3");
    expect(ast.chains[0].publish).toBe(true);
  });

  it("keeps a narrowed publish list across the move", () => {
    // `publish=$a` says what of this cell's output may leave the machine. The
    // person did not change, so the claim about them does not get reviewed
    // because their number moved.
    const src = "@peer2 publish=$a\nrandom 32 | out $a | out $b";
    const moved = relabelAudience([BEA, CEC], [BEA, CEC, ADA]);
    const { edits } = relabelPlacements(compileRecipe(src).ast.chains, moved);
    expect(edits[0].publishSlots).toEqual(["a"]);
    expect(applyEdits(src, edits)).toBe("@peer3 publish=$a\nrandom 32 | out $a | out $b");
  });

  it("unassigns a cell whose person left rather than leaving the number", () => {
    // The vacated number is taken immediately — with CEC gone, `peer2` is ADA.
    // Leaving the header would hand CEC's cell to ADA through an edit made for
    // an unrelated reason, which is the drift in its worst form.
    const moved = relabelAudience([BEA, CEC], [BEA, ADA]);
    const { edits, note } = relabelPlacements(compileRecipe(SOURCE).ast.chains, moved);
    expect(edits).toEqual([{ cell: 0, peer: null, publish: false, publishSlots: [] }]);
    expect(applyEdits(SOURCE, edits)).toBe("random 32 | out $secret");
    expect(roomRoster([BEA, ADA]).roster.peer2).toBe(BEA);
    expect(note).toContain("no longer in the room");
    expect(note).toContain("cell 0");
  });

  it("leaves a label the room never bound alone", () => {
    // `@peer5` in a room of two named nobody, so there is nobody for it to
    // follow and nothing to narrate. `planRun` has been saying so all along.
    const src = "@peer5\nrandom 32 | out $x";
    const moved = relabelAudience([BEA, CEC], [BEA, CEC, ADA]);
    const { edits, note } = relabelPlacements(compileRecipe(src).ast.chains, moved);
    expect(edits).toEqual([]);
    expect(note).toBe("");
  });
});

describe("what the draft room promises the session", () => {
  it("hands out labels before anybody has connected", () => {
    // The composing case, and the one that did not work: `handoffWho` reads
    // `quorumState.audience`, which is empty until Start is pressed, so the
    // assignment menu was empty exactly while somebody was writing a ceremony
    // to run later.
    const { roster } = roomRoster([ADA, BEA], [], ADA);
    expect(Object.keys(roster).sort()).toEqual(["peer1", "peer2"]);
  });

  it("gives the same labels the live room will, from the same audience", () => {
    // `startSession` is handed `sessionDraft.audience`, and the live roster is
    // that audience plus whoever has meshed. Composing against a set of labels
    // that changed the instant the room opened would be the whole defect moved
    // one press later.
    const draft = roomRoster([CEC, ADA, BEA], [], ADA);
    const live = roomRoster([CEC, ADA, BEA], [CEC, BEA], ADA);
    expect(live.roster).toEqual(draft.roster);
    expect(live.me).toBe(draft.me);
    expect(draft.me).toBe("peer1");
  });
});
