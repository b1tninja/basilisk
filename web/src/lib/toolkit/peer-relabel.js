/**
 * The room shrinking, and what it does to a notebook already written for it.
 *
 * ## What this module used to be, and why most of it is gone
 *
 * A `@peer` header names a *person*, and it used to name them by **position**:
 * `peerLabels` numbered the audience in `canonicalAudience` order, because a
 * positional label was the only naming two browsers could agree on without
 * talking first. That bought agreement and cost meaning — `@peer2` tells a
 * reader nothing — and it cost more than meaning. The sort is over key
 * material, so a third person added to a room of two landed wherever their
 * fingerprint happened to fall and every label from that position on shifted by
 * one. A cell that said `@peer2` still said `@peer2`, now meant somebody else,
 * and nothing on screen moved.
 *
 * This module existed to repair that drift: `relabelAudience` worked out how the
 * numbers had moved and `relabelPlacements` rewrote every header to follow the
 * person it was placed on. Two commits (`96dde48` for a draft audience,
 * `4b3305d` for a live room) were spent building and then extending it.
 *
 * **A peer is now the whole fingerprint, so a peer cannot renumber.** Adding
 * somebody changes nothing about what anyone else is called; the drift is gone
 * at the root rather than repaired, and the machinery that repaired it is gone
 * with it. What is left is the one case that was never about renumbering at all.
 *
 * ## Somebody who leaves still has to be dealt with
 *
 * A member removed from the audience is no longer anywhere in the room, and a
 * cell still addressed to them will never run: `planRun` refuses it as
 * `unknown-peer`, and a run that reached it would stop. So their cells are
 * unassigned, and the reader is told which ones.
 *
 * This part is *unchanged in substance* and its reasoning is simpler than it
 * was. Under positional labels the argument had a second, worse half — the
 * vacated number was immediately occupied by whoever sorted into it, so leaving
 * a departed member's header alone would have handed their cell to the person
 * who *stayed*. That cannot happen now. A fingerprint is not inherited. What
 * remains is only the first half: a cell addressed to somebody who is not in the
 * room is a cell that does not run, and the honest thing to do with it is to say
 * so and hand it back to the author.
 *
 * ## What is never done silently
 *
 * Every rewrite produces a sentence naming the cells it touched. A notebook that
 * changed under the reader with no word about it is the defect whichever
 * direction the change went in, and the sentence is generated here — beside the
 * edit that earns it — rather than in the shell, so nothing can apply the edits
 * and forget to say so.
 *
 * ## What no rewrite can rescue
 *
 * A peer typed by hand that named nobody — `@alice` in a room of two keys, or a
 * `@peer1` left in a notebook written before this change — is not reported and
 * not touched. It was bound to no fingerprint, so there is no person for it to
 * follow; `planRun` says "no one in this room answers to it" and goes on saying
 * so. Reassigning it is the author's act, through the same menu they would have
 * used to place it.
 *
 * @module lib/toolkit/peer-relabel
 */

import { canonicalAudience } from "../notebook/room.js";

/**
 * Who is in the notebook's headers and no longer in the room.
 *
 * Derived from the two audiences and nothing else. Under positional labels this
 * had to go through `peerLabels` on both sides — the only thing that handed out
 * a label — and the comparison was between two numberings. There are no
 * numberings now, so this is a set difference over fingerprints, which is what
 * the question always was underneath.
 *
 * Canonicalised on both sides so that a caller passing raw input (spaced
 * fingerprints out of a paste box, mixed case out of a link) cannot report
 * somebody as having left because the two lists were spelled differently.
 *
 * @param {string[]} [beforeFprs] the audience the notebook's headers were
 *   written against
 * @param {string[]} [afterFprs] the audience as it stands now
 * @returns {Set<string>} members of `before` that `after` does not contain
 */
export function departedPeers(beforeFprs, afterFprs) {
  const after = new Set(canonicalAudience(afterFprs || []));
  return new Set(canonicalAudience(beforeFprs || []).filter((f) => !after.has(f)));
}

/**
 * One cell's header, cleared — in the shape `setCellPeer` takes.
 *
 * Edits rather than a new chain list, and deliberately: the notebook's text is
 * `serializeRecipe(chains)`, so the only safe way to change a header is to
 * change the field and let the recipe layer write it. `serializeStep`'s quoting
 * has bitten this repo before — a comma inside an argument round-tripped
 * unquoted and the notebook stopped compiling — and every one of those bugs
 * arrived through somebody editing recipe text as a string. Nothing here
 * touches text.
 *
 * @typedef {object} PlacementEdit
 * @property {number} cell  index into the chain list, as the plan numbers them
 * @property {string|null} peer  the peer it should carry now — always null here
 * @property {boolean} publish
 * @property {string[]} publishSlots
 */

/**
 * Unassign every cell placed on somebody who has left, and say which.
 *
 * `publish` and `publishSlots` are dropped along with the peer, for the reason
 * `setCellPeer` gives: a modifier attached to nobody is not a claim about
 * anything. There is no longer a branch that *keeps* them, because there is no
 * longer a case where a placement survives with a different name.
 *
 * @param {import("./recipe.js").RecipeChain[]} [chains]
 * @param {Set<string>|Iterable<string>} [gone] `departedPeers`' answer
 * @returns {{ edits: PlacementEdit[], note: string }} `note` is "" when there
 *   was nothing to do, so a caller can show it unconditionally and stay quiet
 */
export function unassignDeparted(chains, gone) {
  /** @type {PlacementEdit[]} */
  const edits = [];
  const left = gone instanceof Set ? gone : new Set(gone || []);
  // There is no early return for an empty `gone`, deliberately. It would be a
  // second way to produce the "nothing to say" answer, indistinguishable from
  // the one below by any caller and by any test — mutating it away changed no
  // assertion in this repo, which is the definition of a branch nobody
  // consumes. The walk over an empty set finds nothing and falls out the same
  // door.
  /** @type {string[]} */
  const stranded = [];
  (chains || []).forEach((chain, cell) => {
    // Upper-cased on the way in, because a header carries whatever
    // `normalizePeerRef` canonicalised and the departed set is canonical hex. A
    // hand-typed name never matches, which is the intended outcome — see the
    // module note on what no rewrite can rescue.
    const was = String(chain?.peer || "").toUpperCase();
    if (!was || !left.has(was)) return;
    edits.push({ cell, peer: null, publish: false, publishSlots: [] });
    stranded.push(`cell ${cell}`);
  });

  if (!stranded.length) return { edits, note: "" };
  return {
    edits,
    note:
      `${stranded.length === 1 ? "One cell was" : `${stranded.length} cells were`} ` +
      `placed on somebody who is no longer in the room (${stranded.join(", ")}), ` +
      `and a key nobody else holds is not inherited. ${
        stranded.length === 1 ? "It runs" : "They run"
      } anywhere now — assign ${stranded.length === 1 ? "it" : "them"} again.`,
  };
}
