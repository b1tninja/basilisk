/**
 * A cell assigned to Grace stays assigned to Grace, and now it does so by
 * saying "Grace".
 *
 * ## What this file used to pin, and why the assertions inverted
 *
 * `peerLabels` numbered the audience in `canonicalAudience` order — sorted
 * fingerprints — because a label had to mean the same person in every browser.
 * The cost was that the numbering was a function of key material: put a third
 * person in a room of two and whoever sorted below them moved down one. A
 * notebook written before that happened still said `@peer2`, and `@peer2` was
 * now somebody else. Nothing on screen changed, nothing refused, and the run
 * handed a cell to the wrong machine.
 *
 * The decision then was that *the header follows the person*: every placement
 * was rewritten whenever the audience changed, and this file asserted the
 * literal new label so that "leave the numbers alone" would fail here.
 *
 * A peer is the whole fingerprint now, so the drift has no way to occur. The
 * assertions therefore invert into their strongest form — **adding somebody
 * produces no edits and no sentence at all** — which is a claim about the same
 * scenario that used to require a rewrite, and one that fails loudly if any
 * positional naming ever comes back.
 *
 * ## What did not invert
 *
 * A member who *leaves* still has to have their cells unassigned. That was
 * never about renumbering: a cell addressed to a key that is not in the room
 * will never run, and `planRun` refuses it as `unknown-peer`. Under the old
 * numbering there was a second and worse reason — the vacated number was taken
 * immediately, so the cell would have been handed to whoever sorted into it —
 * and that half is gone. A fingerprint is not inherited.
 *
 * The literals are deliberate. Deriving the expectation from the function under
 * test's own inputs would assert that the rule agrees with itself, which it does
 * whatever it says.
 */
import { describe, expect, it } from "vitest";
import {
  compileRecipe,
  publishedSlots,
  serializeRecipe,
  setPublishedSlots,
} from "../lib/toolkit/recipe.js";
import { roomRoster } from "../lib/notebook/roster.js";
import { departedPeers, unassignDeparted } from "../lib/toolkit/peer-relabel.js";

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
 * pure one — that the edits describe the right cells.
 */
function applyEdits(source, edits) {
  const chains = compileRecipe(source).ast.chains.map((chain) => ({ ...chain }));
  for (const edit of edits) {
    const chain = chains[edit.cell];
    delete chain.peer;
    // The same call `setCellPeer` makes, rather than a second walk: what a cell
    // discloses is written into its steps, and a helper here that decided it
    // some other way would be testing this file's opinion of the edit.
    chain.steps = setPublishedSlots(chain.steps || [], edit.peer ? edit.publishSlots : []);
    if (edit.peer) chain.peer = edit.peer;
  }
  return serializeRecipe(chains);
}

describe("the drift the audience sort used to cause", () => {
  it("does not happen: adding somebody renames nobody", () => {
    // The defect itself, reproduced in the shape it had — a room of two, a
    // third key added that sorts *first*, which is the case that used to shift
    // every label below it — and asserted to be a no-op.
    //
    // Written against `roomRoster` rather than against literals for one side of
    // it, because the claim is about the product's own naming and there is no
    // longer a second numbering to compare against. The literals are the keys.
    const before = roomRoster([BEA, CEC]).roster;
    const after = roomRoster([BEA, CEC, ADA]).roster;
    expect(before[CEC]).toBe(CEC);
    expect(after[CEC]).toBe(CEC);
    expect(after[BEA]).toBe(BEA);
    // Under the old rule `after` would have moved CEC from `peer2` to `peer3`
    // and given `peer2` to BEA. Nothing in the room answers to a position.
    expect(Object.keys(after).some((k) => /^peer\d+$/.test(k))).toBe(false);
  });

  it("has nothing to say when somebody is added", () => {
    // The strongest form of the inversion, on the *hard* case rather than the
    // easy one: ADA sorts first, so under the old numbering this add moved both
    // existing members and produced a rewrite of every placed cell. It now
    // produces no edits, and therefore no sentence — a note here would be a
    // rewrite narrated for a rewrite that did not happen.
    const gone = departedPeers([BEA, CEC], [ADA, BEA, CEC]);
    expect([...gone]).toEqual([]);
    const placed = compileRecipe(`@${CEC}\nrandom 32 | out $secret | publish`).ast.chains;
    expect(unassignDeparted(placed, gone)).toEqual({ edits: [], note: "" });
  });
});

describe("a placement survives everything except its person leaving", () => {
  const SOURCE = `@${CEC}\nrandom 32 | out $secret | publish`;

  it("is untouched by an add, in the notebook's own text", () => {
    const gone = departedPeers([BEA, CEC], [BEA, CEC, ADA]);
    const { edits } = unassignDeparted(compileRecipe(SOURCE).ast.chains, gone);
    expect(edits).toEqual([]);
    // Byte for byte the notebook the author wrote. This is the assertion the
    // old file could not make: it had to accept a rewritten header and check
    // that the *new* label resolved back to CEC.
    expect(applyEdits(SOURCE, edits)).toBe(SOURCE);
    expect(roomRoster([BEA, CEC, ADA]).roster[CEC]).toBe(CEC);
  });

  it("unassigns a cell whose person left", () => {
    // The half that stayed. A cell addressed to a key that is not in the room
    // never runs — `planRun` refuses it `unknown-peer` — so it is handed back
    // to the author rather than left pointing at somebody who is gone.
    const gone = departedPeers([BEA, CEC], [BEA, ADA]);
    expect([...gone]).toEqual([CEC]);
    const { edits, note } = unassignDeparted(compileRecipe(SOURCE).ast.chains, gone);
    expect(edits).toEqual([{ cell: 0, peer: null, publishSlots: [] }]);
    expect(applyEdits(SOURCE, edits)).toBe("random 32 | out $secret");
    expect(note).toContain("no longer in the room");
    expect(note).toContain("cell 0");
    // And the reason the old file gave for this — that the vacated number was
    // taken by whoever sorted into it — is not a thing that can happen. Nobody
    // in the room after the removal answers to CEC.
    expect(roomRoster([BEA, ADA]).roster[CEC]).toBeUndefined();
  });

  it("writes the header through the recipe layer, so it parses back", () => {
    // `serializeStep`'s quoting has broken this repo before, when a session
    // wrote a comma into an argument unquoted and the notebook stopped
    // compiling. Nothing here edits text — but the assertion that it round
    // trips is the one that would notice if somebody made it.
    const src = `@${CEC}\nrandom 32 | out $a | publish | out $b`;
    const gone = departedPeers([BEA, CEC], [BEA, ADA]);
    const { edits } = unassignDeparted(compileRecipe(src).ast.chains, gone);
    const rewritten = applyEdits(src, edits);
    const { ast, validation } = compileRecipe(rewritten);
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    expect(ast.chains[0].peer).toBeUndefined();
    // The `publish` goes with the peer: a value sent to nobody is not a claim
    // about anything, and a cell that kept one would not compile.
    expect(publishedSlots(ast.chains[0])).toEqual([]);
    expect(rewritten).toBe("random 32 | out $a | out $b");
  });

  it("matches a header whatever case it was written in", () => {
    // `normalizePeerRef` upper-cases a fingerprint header, so this is belt on
    // an AST built by hand rather than parsed — and it is the one place a
    // departure could silently miss a cell.
    const gone = departedPeers([BEA, CEC], [BEA, ADA]);
    const { edits } = unassignDeparted([{ steps: [], peer: CEC.toLowerCase() }], gone);
    expect(edits).toEqual([{ cell: 0, peer: null, publishSlots: [] }]);
  });

  it("leaves a peer the room never bound alone", () => {
    // `@peer5` in a room of keys named nobody, so there is nobody for it to
    // follow and nothing to narrate. This is also what a notebook written
    // before the change looks like: `planRun` has been saying "no one in this
    // room answers to it" all along, and goes on saying it.
    const src = "@peer5\nrandom 32 | out $x";
    const gone = departedPeers([BEA, CEC], [BEA, ADA]);
    const { edits, note } = unassignDeparted(compileRecipe(src).ast.chains, gone);
    expect(edits).toEqual([]);
    expect(note).toBe("");
  });
});

describe("what the draft room promises the session", () => {
  it("names the peers before anybody has connected", () => {
    // The composing case, and the one that did not work: `handoffWho` reads
    // `quorumState.audience`, which is empty until Start is pressed, so the
    // assignment menu was empty exactly while somebody was writing a ceremony
    // to run later.
    const { roster } = roomRoster([ADA, BEA], [], ADA);
    expect(Object.keys(roster).sort()).toEqual([ADA, BEA].sort());
  });

  it("gives the same names the live room will, from the same audience", () => {
    // `startSession` is handed `sessionDraft.audience`, and the live roster is
    // that audience plus whoever has meshed. Composing against names that
    // changed the instant the room opened would be the whole defect moved one
    // press later.
    const draft = roomRoster([CEC, ADA, BEA], [], ADA);
    const live = roomRoster([CEC, ADA, BEA], [CEC, BEA], ADA);
    expect(live.roster).toEqual(draft.roster);
    expect(live.me).toBe(draft.me);
    expect(draft.me).toBe(ADA);
  });
});
