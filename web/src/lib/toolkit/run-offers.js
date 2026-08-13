/**
 * What a run that has finished still owes the room, and the sentence saying so.
 *
 * Pressing Run on a notebook with `@peer` headers has always done half of the
 * thing it reads as. The gate declines the cells that are not this machine's,
 * the queue lists them, and there the arc stopped: `offerCell` had exactly one
 * caller in the whole product — a per-row **Offer** button — so a placed run was
 * Run, and then one more press for every cell somebody else owns. The queue's
 * own empty state said otherwise, in as many words: *"the cells that are not
 * yours are declined here and offered to whoever owns them"*. Nothing offered
 * them. This module is what makes that sentence true.
 *
 * ## Why this is allowed to happen without a press
 *
 * An offer runs nothing on anybody's machine. It is a document that sits pending
 * until the person holding it presses accept — `acceptHandoff` is where a
 * handoff stops being JSON and becomes bindings in a registry, and that stays a
 * press. What the automatic send removes is not a decision; it is a second press
 * that only restates the first. The reader already said "run this notebook", and
 * this notebook says cell 3 is `@peer2`'s. Making them say it again per cell is
 * the same "finished mechanism with no entry point" defect one layer along: the
 * entry point exists, and it is on the wrong side of the decision.
 *
 * ## Why the result coming back is not the same question, and stays a press
 *
 * The mirror automation — a peer who accepted a cell, ran it, and has the answer
 * — was considered and refused, and the reason is in this module because it is
 * the reason this one is safe.
 *
 * An offer is bounded by *the run that is sending it*. `skipped` below is the
 * gate's own report, written during that run and cleared at the start of the
 * next, so every cell in it was declined by the run now asking to hand it over.
 * There is no way for a cell to be in that list for some other reason.
 *
 * A result has no equivalent. `runFrom` runs every cell from an index onward, so
 * a peer who accepted cell 1 and then presses Run for their own reasons runs it
 * again, and again, and nothing anywhere records *why* it ran. The only record
 * that a cell was ever accepted is the shell's `owedBack` list, and that is a
 * record of a past press, not of this run's purpose — bound to it, an automatic
 * send would fire on every subsequent Run of that notebook, forever, for reasons
 * having nothing to do with the peer waiting. "Be certain it cannot fire for a
 * cell that was run for some other reason" is not satisfiable with what exists,
 * so it is not automated, and `HandoffQueue` says out loud that sending it back
 * is a press.
 *
 * @module lib/toolkit/run-offers
 */

import { PEER_SIGIL } from "./recipe-parse.js";

/**
 * What binds one offer, so a re-fire cannot repeat it.
 *
 * Cell *and* label, not the cell alone: a notebook edited between two runs can
 * move a placement, and "cell 3 has gone out" would then suppress an offer to
 * somebody who has never been sent anything. The pair is the claim actually
 * being made — this cell, to this person.
 *
 * Not exported. The caller never builds one — it reads `key` off the offers
 * this module hands back — and an export nothing calls is the shape of defect
 * this repo keeps finding.
 *
 * @param {number} cell
 * @param {string} peer
 * @returns {string}
 */
function offerKey(cell, peer) {
  return `${cell}${PEER_SIGIL}${peer}`;
}

/**
 * @typedef {object} PlannedOffer
 * @property {number} cell
 * @property {string} peer  the label the plan says owns it
 * @property {string} key   {@link offerKey}, for the caller's bound
 */

/**
 * The offers a finished run has not made yet.
 *
 * **Bounded by what has gone out, never by a clock.** This is
 * `NotebookSession._invited`'s rule in the layer above it: a set of the things
 * already served, consulted before serving, so a caller that runs twice for one
 * run — an effect re-firing on a re-render is the ordinary way that happens —
 * sends nothing the second time. A timer would answer "how long ago" when the
 * question is "did this go".
 *
 * The bound belongs to the caller rather than to this module because it has to
 * be marked *before* the send is awaited, which is the same order `_onKnock`
 * uses: a second pass that arrives while the first is still in flight must find
 * the cell already claimed.
 *
 * A cell the gate declined but placed on nobody is dropped here rather than
 * offered and refused downstream. `offerCell` would answer "that cell was not
 * left to anybody", which is true and is not news to a reader who can see the
 * cell has no header.
 *
 * @param {{ cell: number, waitingOn?: string }[]} [skipped] the gate's report
 * @param {{ has: (key: string) => boolean }} [already] what has gone out
 * @returns {PlannedOffer[]} in cell order, which is the order they were declined
 */
export function pendingOffers(skipped, already) {
  /** @type {PlannedOffer[]} */
  const out = [];
  const seen = new Set();
  for (const sk of skipped || []) {
    const cell = Number(sk?.cell);
    const peer = String(sk?.waitingOn || "");
    if (!Number.isInteger(cell) || !peer) continue;
    const key = offerKey(cell, peer);
    // The gate reports per declined cell, so a duplicate would mean one cell
    // declined twice in a run. Guarded anyway: this list is the argument to a
    // send, and the cheapest place to be certain one cell means one document.
    if (seen.has(key)) continue;
    seen.add(key);
    if (already && already.has(key)) continue;
    out.push({ cell, peer, key });
  }
  return out;
}

/**
 * @typedef {object} OfferOutcome
 * @property {number} cell
 * @property {string} peer
 * @property {boolean} ok
 * @property {string} [why]  the handoff layer's own sentence, when it refused
 */

/**
 * The sentence a run appends to its own verdict, built from what happened.
 *
 * Built here, from the outcomes, rather than assembled by the caller — the rule
 * `relabelPlacements` states for the same reason: a narration written apart
 * from the acts it describes is a narration that can be applied without them, or
 * they without it. This one cannot claim a cell went out unless `ok` says it
 * did.
 *
 * **Failures are named, one per cell, in the handoff layer's own words.** A run
 * that quietly offered nothing is the experience this whole arc exists to end,
 * and it is exactly what a summary like "2 of 3 sent" would produce: the reader
 * learns a number and not which peer is not in the room. `offerCell` refuses for
 * real, distinguishable states — nobody answers to that label, the peer is in
 * the audience but has not meshed, the cell was left to nobody — and each of
 * those sentences names a different remedy.
 *
 * @param {OfferOutcome[]} [outcomes]
 * @returns {string} "" when there was nothing to report, so a caller can append
 *   it unconditionally and stay quiet
 */
export function narrateOffers(outcomes) {
  const sent = (outcomes || []).filter((o) => o.ok);
  const kept = (outcomes || []).filter((o) => !o.ok);
  const parts = [];
  if (sent.length) {
    const each = sent.map((o) => `cell ${o.cell} to ${PEER_SIGIL}${o.peer}`);
    parts.push(
      `Handed ${each.join(", ")} — nothing runs there until they accept, and ` +
        `the answer comes back when they send it.`
    );
  }
  for (const o of kept) {
    parts.push(
      `Cell ${o.cell} could not go to ${PEER_SIGIL}${o.peer}. ` +
        `${o.why || "The handoff was refused and gave no reason."}`
    );
  }
  return parts.join(" ");
}

/**
 * What a run says when it declined cells for a room that is no longer there.
 *
 * Reachable only by the session ending between the first cell and the last: the
 * gate is built from a live roster, so a run that begins without a room declines
 * nothing and never gets here. It names *that* state rather than the button's —
 * `HandoffQueue`'s `NO_SESSION` is for a control that was never live, and saying
 * "no session is open" to somebody whose session just dropped mid-run would
 * describe the wrong half of what happened.
 *
 * @param {PlannedOffer[]} [waiting]
 * @returns {string}
 */
export function narrateNoSession(waiting) {
  const cells = (waiting || []).map((o) => o.cell);
  if (!cells.length) return "";
  const which =
    cells.length === 1
      ? `Cell ${cells[0]} is`
      : `Cells ${cells.slice(0, -1).join(", ")} and ${cells[cells.length - 1]} are`;
  return (
    `The session ended before this run did, so ${which.toLowerCase()} still ` +
    `planned and still theirs with nowhere to go. Open the room again under ` +
    `Share and handing ${cells.length === 1 ? "it" : "them"} over is one press.`
  );
}
