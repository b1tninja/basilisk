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
 * this notebook says whose cell 3 is. Making them say it again per cell is
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
 * ## Declined is not the same question as owed
 *
 * The first version of this module offered every cell the gate declined, and
 * that is a wider claim than the paragraphs above justify. The gate declines a
 * cell because it is not this machine's to *perform*; an offer says something
 * else — that this machine is holding up the cell, or waiting on it. Those come
 * apart constantly, and when they do the queue tells a second, wrong story about
 * how a value arrives.
 *
 * Two of them, both watched happening. A joiner who adopted a creator's notebook
 * adopted the creator's own session cells with it — Start appended `agent.unlock`
 * and `quorum.offer` under the opener's header — so the joiner's run declined
 * them and offered them *back* to the creator, who ran them half an hour ago to
 * open the room the offer travels over. Start writes no cells now
 * (`START_OPENS`), so that particular pair can no longer be adopted by anybody;
 * the case is kept here because it is the clearest statement of what the rule is
 * for, and because a hand-written `quorum.offer` reaches the same shape. The
 * second one is live and always was: in a ceremony the holder's `quorum.recv`
 * cell is placed on the holder, so the dealer's run declines it and offers it to
 * them — an offer to run a cell whose entire job is to receive something the
 * dealer is sending by another path.
 *
 * So the rule is **this machine has to be on one end of the cell**:
 *
 * - it reads a value produced here, so nothing can run there until this machine
 *   sends it; or
 * - it writes a value read here, so nothing more can run here until that answer
 *   comes back.
 *
 * Either one, never both required, and the two are genuinely different — this
 * repo contains a cell of each kind. `placed-journey`'s cell 1 reads `$seed`
 * from a *witnessed* cell, which every participant runs, so its offer carries
 * nothing at all; it is owed because the creator's next cell reads the `$b64` it
 * writes. The mirror is a cell that consumes a private value from here and
 * writes something only its own peer goes on to use.
 *
 * A cell that satisfies neither is one this notebook mentions and this machine
 * has no part in. It stays in the queue, with the press still on it and a row
 * that says why nothing went out — `offerCell` is unchanged and a reader who
 * knows better than the plan can still send it.
 *
 * @module lib/toolkit/run-offers
 */

import { slotsFromElsewhere } from "./handoff.js";
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
 * Does this cell need a value that was produced on this machine?
 *
 * `slotsFromElsewhere` is `buildOfferFor`'s own reckoning of what the offer
 * would carry, imported rather than reproduced — see its note. The extra
 * condition is the one `buildOfferFor` applies a line later, where a row whose
 * producer is not `mine` is refused as `incomplete`: a slot a *third* peer wrote
 * is not this machine's to hand over, and an offer built on one would be refused
 * by the same module that would have built it.
 *
 * @param {import("./plan.js").RunPlan} plan
 * @param {number} cell
 * @param {string} runner  the peer the cell was placed on
 */
function readsFromHere(plan, cell, runner) {
  for (const row of slotsFromElsewhere(plan, cell, runner)) {
    if (plan.cells[row.from]?.mine) return true;
  }
  return false;
}

/**
 * Does anything this machine runs read what this cell writes?
 *
 * Off `consumes[].from`, which is the plan's own dependency answer and the same
 * field `placementGate` stops a run on — so "this run cannot continue without
 * that cell" and "that cell is owed an offer" can never be two different
 * readings of the notebook.
 *
 * Every cell of the plan, not only the ones this run walked. A reader above the
 * window has already run and is waiting; a reader below it will run next press.
 * Narrowing to the window would drop an offer somebody is genuinely waiting on,
 * which is the one failure worth being generous about.
 *
 * @param {import("./plan.js").RunPlan} plan
 * @param {number} cell
 */
function writesToHere(plan, cell) {
  for (const reader of plan.cells || []) {
    if (!reader?.mine) continue;
    for (const row of reader.consumes || []) {
      if (row.from === cell) return true;
    }
  }
  return false;
}

/**
 * @typedef {object} OfferSplit
 * @property {PlannedOffer[]} owed   to send, in the order they were declined
 * @property {PlannedOffer[]} aside  declined, and not this machine's to hand over
 */

/**
 * What a finished run owes the room, and what it merely declined.
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
 * the cell already claimed. It filters `owed` alone — `aside` is a reading of
 * the notebook rather than a record of an act, so it is the same answer on every
 * pass and a caller may fold it in as many times as it likes.
 *
 * A cell the gate declined but placed on nobody is in neither list. `offerCell`
 * would answer "that cell was not left to anybody", which is true and is not
 * news to a reader who can see the cell has no header.
 *
 * @param {{ cell: number, waitingOn?: string }[]} [skipped] the gate's report
 * @param {{ has: (key: string) => boolean }} [already] what has gone out
 * @param {import("./plan.js").RunPlan} [plan] the plan that gate was built from
 * @returns {OfferSplit}
 */
export function offersOwed(skipped, already, plan) {
  /** @type {OfferSplit} */
  const split = { owed: [], aside: [] };
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
    const planned = plan?.cells?.[cell];
    if (!planned) {
      // Unreachable rather than guarded against: `placement.onSkip` is a field
      // of the object the plan is handed to, so a skipped cell exists only
      // because that plan did. Refused in `placementGate`'s words and for its
      // reason — the alternatives are offering everything, which is the defect
      // this rule exists to remove, and offering nothing, which withholds a
      // value somebody is waiting on. Neither may be chosen by default.
      throw new Error(
        `run-offers: cell ${cell} was declined and this plan does not describe ` +
          "it — the gate's report and the plan it came from are one run's " +
          "answer, and whether an offer is owed cannot be decided without both"
      );
    }
    const runner = planned.runsOn[0] || peer;
    if (readsFromHere(plan, cell, runner) || writesToHere(plan, cell)) {
      if (already && already.has(key)) continue;
      split.owed.push({ cell, peer, key });
    } else {
      split.aside.push({ cell, peer, key });
    }
  }
  return split;
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
 * `unassignDeparted` states for the same reason: a narration written apart
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
