/**
 * What a peer's cell announcement *says* — face up, face down, and out loud.
 *
 * `announceCellState` in `lib/notebook/session.js` decides what crosses the
 * wire; this module decides what a person is told about it, and it is a module
 * rather than three lines in a component for the reason `run-offers.js` gives:
 * the copy is the part that can be wrong, and it is pinnable in node without a
 * renderer.
 *
 * ## The model this is drawing
 *
 * A card table. A hand is dealt or it is not; and if it is, the cards are
 * either face up in front of you or face down in front of somebody else. All
 * three states exist and only one of them is "you can read it":
 *
 * - **Not dealt** — the peer has said nothing about that cell. There is no row.
 *   Deliberately not a row saying "not yet": these are live announcements with
 *   no replay and no catch-up, so absence means *nothing has been said*, which
 *   is not the same claim as *this has not happened* and must not be printed as
 *   one. A peer who joined late has no rows at all, and a table that filled in
 *   "not yet" for them would be inventing the room's history.
 * - **Face down** — the cell finished and wrote a slot that is not on this
 *   machine. The slot is *named*, because everyone in the room holds the same
 *   notebook and can read which slots that cell writes; what is added is that
 *   it now exists. Nothing here implies it could be fetched: there is no
 *   request on this wire, and a sentence that hinted at one would be naming a
 *   remedy that cannot be performed.
 * - **Face up** — the cell finished and this machine holds a slot of that
 *   name. It reads like any other slot, because it is one.
 *
 *   **A slot of that *name*, and the distinction is not pedantry.** This said
 *   "because a value actually arrived", which implies transit — and the row is
 *   drawn beside the peer's fingerprint, so a reader takes it to mean *their*
 *   output is here. `facesFor` asks `hasSlot(label)` and nothing else. On an
 *   unplaced cell, which is `mine` on every machine, both ends run the same
 *   cell and write the same label locally; with a `random` source they then
 *   hold *different* values under one name and both rows read face up. Nothing
 *   crossed. Saying so plainly is the honest half of this; making the row mean
 *   the stronger thing would mean comparing something the announcement carries,
 *   which is a protocol change and a disclosure, and is not made here.
 *
 * ## Why `here` is asked of the registry and not of the announcement
 *
 * The peer's frame carries labels only, and a label is not possession. Whether
 * `$share-2` is on *this* machine is a question only this machine's slot
 * registry can answer, and asking it at the moment of drawing is what keeps a
 * face-down row from turning face up on the strength of somebody else's say-so.
 * A row goes face up when a value arrived, never when a peer said it wrote one.
 *
 * @module lib/toolkit/cell-state
 */

/**
 * @typedef {object} PeerCellState
 * @property {string} from
 * @property {number} cell
 * @property {"running"|"done"|"refused"} state
 * @property {string[]} slots
 * @property {number} ts
 */

/**
 * @typedef {object} SlotFace
 * @property {string} slot  the label, as the notebook spells it, without `$`
 * @property {boolean} here whether this machine holds it *now*
 */

/**
 * Which of a finished cell's slots are face up on this machine.
 *
 * Empty for every state but `done`: a cell that is still running has written
 * nothing yet, and a refused one is not making a claim about slots at all.
 *
 * @param {PeerCellState} row
 * @param {(label: string) => boolean} hasSlot
 * @returns {SlotFace[]}
 */
export function facesFor(row, hasSlot) {
  if (!row || row.state !== "done") return [];
  return (row.slots || []).map((slot) => ({ slot, here: !!hasSlot(slot) }));
}

/**
 * What a screen reader is told when one of these lands, or `""` for silence.
 *
 * **Silent on `running`, and that is `7ac9f50`'s rule applied rather than a new
 * one.** A live region announces on change, so a twelve-cell notebook across
 * three peers is thirty-six interruptions in one ceremony — and every `running`
 * among them is a fact the listener cannot act on, arriving between the ones
 * they came for. That is exactly the drowning the per-cell ticker was made
 * silent to prevent, and a peer's ticker is no more announceable than this
 * machine's own.
 *
 * A cell **finishing or refusing** is the other half of that rule: it is an
 * event a person needs and cannot otherwise learn. The visible table has it
 * either way, and a sighted reader can see the row move; the announcement is
 * what a reader who cannot see the tray gets instead.
 *
 * The fingerprint is whole. It is the only name a peer has here — the roster is
 * identity-mapped, so a peer *is* their key — and a row telling somebody which
 * peer just did something is the last place to print part of who they are.
 *
 * @param {PeerCellState} row
 * @param {(label: string) => boolean} hasSlot
 * @returns {string}
 */
export function describeCellState(row, hasSlot) {
  if (!row) return "";
  if (row.state === "refused") {
    // The state, never the sentence. The refusal's own text can name slots,
    // keys or reasons that are the running peer's business, so nothing crosses
    // that could be repeated here — and this says so, rather than leaving a
    // reader to wonder whether the reason is somewhere on this screen.
    return `${row.from} refused cell ${row.cell}. The reason stayed on their machine.`;
  }
  if (row.state !== "done") return "";
  const faces = facesFor(row, hasSlot);
  if (!faces.length) return `${row.from} finished cell ${row.cell}.`;
  const down = faces.filter((f) => !f.here).map((f) => `$${f.slot}`);
  const up = faces.filter((f) => f.here).map((f) => `$${f.slot}`);
  const parts = [`${row.from} finished cell ${row.cell}.`];
  if (up.length) parts.push(`${up.join(", ")} ${up.length === 1 ? "is" : "are"} here.`);
  if (down.length) {
    // Named, and stated as somebody else's. No remedy, because there is none:
    // nothing on this wire asks a peer for a value, and "ask them to send it"
    // would be a sentence about a control that does not exist.
    parts.push(
      `${down.join(", ")} ${down.length === 1 ? "exists" : "exist"} on their machine and did not come here.`
    );
  }
  return parts.join(" ");
}
