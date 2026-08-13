/**
 * Renumbering the room, and what it does to a notebook already written for it.
 *
 * A `@peer` header is the one thing in a recipe that names a *person*, and it
 * names them by position. `peerLabels` numbers the audience in
 * `canonicalAudience` order because a label has to mean the same human in every
 * browser — the notebook round-trips through text and is digested into
 * manifests — and sorted fingerprints are the only ordering two machines can
 * agree on without talking first. That is the right choice, and it carries a
 * consequence nobody chose: the sort is over key material, so a third person
 * added to a room of two lands wherever their fingerprint happens to fall, and
 * every label from that position on shifts by one. A cell that said `@peer2`
 * still says `@peer2`, now means a different person, and nothing on screen
 * moved.
 *
 * That is the hazard this module exists to refuse. It has to be refused *here*,
 * in a pure function, because it is a rule about whose work runs on whose
 * machine and a rule like that should be decidable without a browser.
 *
 * ## The decision: the header follows the person
 *
 * When the audience changes, the placements are rewritten so that a cell
 * assigned to Grace is still assigned to Grace under whatever number she now
 * holds. The alternative — leave the numbers alone and refuse to renumber — was
 * considered and is not available, for two reasons rather than one:
 *
 * 1. **The author picked a person, not a position.** Nobody looks at a room and
 *    chooses "second in sorted fingerprint order". They choose Grace, from a
 *    list that showed them Grace. The number is an encoding the room imposes so
 *    that two machines can say the same thing, and an encoding that changes
 *    under a statement is the encoding's problem to fix, not the author's.
 * 2. **"Refuse to renumber" cannot mean what it sounds like.** The sort is not
 *    a display choice this layer could opt out of: `deriveRoomMaterial` and
 *    `peerLabels` both go through `canonicalAudience`, so the room the session
 *    actually opens will be numbered that way whatever a draft decides. Holding
 *    a draft's numbering fixed would make the labels right while composing and
 *    wrong the moment Start is pressed — the same drift, moved later, and
 *    harder to see because by then there is a session to blame. The only honest
 *    reading of "refuse" is refusing to change the audience at all once a cell
 *    is placed, which strands the ceremony the reader is in the middle of
 *    writing. That is the uselessness this work exists to remove.
 *
 * `relabel-drift.test.js` pins the choice from both sides: a cell placed on
 * `@peer2` must read `@peer3` after a lower-sorting key joins, and must still
 * resolve to the fingerprint it was placed on. Under "refuse" the first
 * assertion fails; under a rewrite that follows the *number* instead of the
 * person, the second does.
 *
 * ## What is never done silently
 *
 * Every rewrite produces a sentence naming the cells it touched. A notebook
 * that changed under the reader with no word about it is the defect whichever
 * direction the change went in, and the sentence is generated here — beside the
 * edit that earns it — rather than in the shell, so nothing can apply the edits
 * and forget to say so.
 *
 * ## Somebody who leaves cannot be followed
 *
 * A member removed from the audience has no new label, so their cells are
 * unassigned rather than left pointing at the number they used to hold. Leaving
 * it is the worst form of the drift: the vacated number is immediately occupied
 * by whoever sorts into that position, so a cell placed on the person who left
 * would come to name the person who stayed, and it would arrive there through
 * an edit the reader made for an unrelated reason.
 *
 * ## What no rewrite can rescue
 *
 * A label typed by hand that named nobody — `@peer3` in a room of two — is not
 * reported and not touched. It was bound to no fingerprint, so there is no
 * person for it to follow; `planRun` said "no one in this room answers to it"
 * and goes on saying so until a third person makes it true. That it acquires a
 * meaning when the room grows is the only meaning the room can give it, and it
 * is the meaning the author was anticipating by typing it.
 *
 * @module lib/toolkit/peer-relabel
 */

import { peerLabels } from "../notebook/roster.js";
import { PEER_SIGIL } from "./recipe-parse.js";

/**
 * How the labels move when the audience changes.
 *
 * Both sides go through `peerLabels`, which is the only thing in the product
 * that hands out a label. Deriving the "before" numbering by any other route —
 * remembering what was shown, counting the list, keeping a parallel map — would
 * be a second copy of the numbering rule, and the two copies would eventually
 * disagree about exactly the question this function exists to answer.
 *
 * Labels whose meaning did not change are left out, so an empty result is the
 * honest "nothing to say" and a caller cannot narrate a renumbering that did
 * not happen. Adding somebody whose fingerprint sorts last is the common case
 * of that.
 *
 * @param {string[]} [beforeFprs] the audience the notebook's headers were
 *   written against
 * @param {string[]} [afterFprs] the audience as it stands now
 * @returns {Map<string, string|null>} old label → the label that member holds
 *   now, or `null` when they are no longer in the audience at all
 */
export function relabelAudience(beforeFprs, afterFprs) {
  const before = peerLabels(beforeFprs || []);
  const after = peerLabels(afterFprs || []);
  /** @type {Map<string, string|null>} */
  const moved = new Map();
  for (const [fpr, label] of before) {
    const now = after.get(fpr) ?? null;
    if (now !== label) moved.set(label, now);
  }
  return moved;
}

/**
 * One cell's header, rewritten — in the shape `setCellPeer` takes.
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
 * @property {string|null} peer  the label it should carry now, or null to clear
 * @property {boolean} publish
 * @property {string[]} publishSlots
 */

/**
 * Move every placement onto the label its person holds now, and say so.
 *
 * `publish` and `publishSlots` ride along untouched when the cell keeps a peer:
 * they say what of this cell's output may leave the machine, which is a
 * decision about the same person and is not up for review because their number
 * changed. A cleared placement drops them, for the reason `setCellPeer` gives —
 * a modifier attached to nobody is not a claim about anything.
 *
 * @param {import("./recipe.js").RecipeChain[]} [chains]
 * @param {Map<string, string|null>} [moved] `relabelAudience`'s answer
 * @returns {{ edits: PlacementEdit[], note: string }} `note` is "" when there
 *   was nothing to do, so a caller can show it unconditionally and stay quiet
 */
export function relabelPlacements(chains, moved) {
  /** @type {PlacementEdit[]} */
  const edits = [];
  const followed = [];
  const stranded = [];
  if (!moved || !moved.size) return { edits, note: "" };

  (chains || []).forEach((chain, cell) => {
    const was = String(chain?.peer || "");
    if (!was || !moved.has(was)) return;
    const now = moved.get(was) ?? null;
    edits.push({
      cell,
      peer: now,
      publish: now ? !!chain.publish : false,
      publishSlots: now && chain.publish ? [...(chain.publishSlots || [])] : [],
    });
    if (now) {
      followed.push(
        `cell ${cell} says ${PEER_SIGIL}${now} where it said ${PEER_SIGIL}${was}`
      );
    } else {
      stranded.push(`cell ${cell}`);
    }
  });

  const parts = [];
  if (followed.length) {
    parts.push(
      `The room is numbered by fingerprint, so changing who is in it moves the ` +
        `labels: ${followed.join(", ")}. The same key is behind each of them — ` +
        `the placement followed the person, only the number moved.`
    );
  }
  if (stranded.length) {
    parts.push(
      `${stranded.length === 1 ? "One cell was" : `${stranded.length} cells were`} ` +
        `placed on somebody who is no longer in the room (${stranded.join(", ")}), ` +
        `and nobody inherits a number. ${
          stranded.length === 1 ? "It runs" : "They run"
        } anywhere now — assign ${stranded.length === 1 ? "it" : "them"} again.`
    );
  }
  return { edits, note: parts.join(" ") };
}
