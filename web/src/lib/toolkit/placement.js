/**
 * The gate — a cell the plan placed on somebody else does not run here.
 *
 * `planRun` already answered *where every cell runs*, from the recipe text and
 * a roster, before anything started. This module answers nothing. It is the
 * one place that **acts** on that answer, and its whole design is about not
 * becoming a second opinion: it reads `mine`, `runsOn`, `why` and `consumes`
 * off the cells the plan produced and never re-derives a placement from a
 * header, a slot name or an owner. A run that decided placement twice would
 * eventually decide it two ways, and the divergence would appear as a key
 * leaving a machine it was never supposed to leave.
 *
 * ## Absence is not permission
 *
 * The obvious way to add a gate to the hottest path in the product is a
 * parameter that defaults to "run everything", and it is wrong in a specific
 * way: the moment a caller passes a plan that is *partly* filled in — built
 * before a roster arrived, built for a different notebook, built without
 * knowing which peer this is — every cell it does not describe runs locally,
 * silently, on the wrong machine. That is the exact failure this unit exists
 * to prevent, reintroduced by the gate's own defaulting.
 *
 * So the boundary has two states and no third:
 *
 * - **No `placement` at all** — `placementGate` returns `null`, the engine
 *   never enters this module, and the run is the run it was before this file
 *   existed. Every existing caller is in this state, and `run-gate.test.js`
 *   holds it by running every shipped preset and every `docs/RECIPE.md` fence
 *   both ways in one process and comparing.
 * - **A `placement`** — the caller is asserting that the decision has been
 *   made. Then it must be *complete*, and each way of being incomplete is
 *   refused here rather than defaulted through: a plan that refused, a plan
 *   that does not know who `me` is while placing cells on peers, a plan that
 *   describes a different number of cells than the run is about to walk, a
 *   cell index the plan never covered.
 *
 * ## What a downstream cell sees
 *
 * A skipped cell's `out` slots are never registered, so a later cell reading
 * one would today get `in $x: unknown slot (register earlier with out $x)` —
 * a sentence that blames the author for forgetting an `out` when in fact the
 * value exists, on somebody else's machine, and nothing in this run can carry
 * it here. Worse, an op that reads its slot through an optional param could
 * fall through to a bound key or a pasted input and produce a plausible
 * artifact from the wrong material.
 *
 * So the check happens *before the cell runs at all*, against the plan's own
 * dependency answer (`consumes[].from`), and it **stops the run**: a placed
 * notebook that cannot complete is a stopped run, never a short one that looks
 * finished. The one thing that makes the cell run anyway is the value actually
 * being present — `hasSlot` is asked first — which is precisely the seam the
 * handoff unit will deliver through. When a transport registers `$x`, this
 * check stops firing on its own, with no edit here.
 *
 * @module lib/toolkit/placement
 */

import { PEER_SIGIL, SLOT_SIGIL } from "./recipe-parse.js";

/**
 * A cell this run declined to perform, and who it belongs to.
 *
 * `waitingOn` is the peer, not a fingerprint — the roster crossing belongs to
 * `plan.js` and stays there.
 * @typedef {object} SkippedCell
 * @property {number} cell
 * @property {string} waitingOn   peer label, or `*` for a rendezvous
 * @property {string[]} runsOn    every peer the plan named for it
 * @property {string} why         the plan's sentence, verbatim
 * @property {string[]} produces  slot labels that will not exist here
 */

/**
 * @typedef {object} Placement
 * @property {import("./plan.js").RunPlan} plan  a `planRun` result, whole
 * @property {number} [firstCell]  plan index of the first cell this run walks.
 *   Only needed by a caller that runs one cell at a time against a one-chain
 *   AST (the notebook kernel), where the chain's own index is 0 and its index
 *   *in the plan* is the thing the gate has to be told.
 * @property {(skipped: SkippedCell) => void} [onSkip]  called once per cell
 *   left to somebody else, in run order
 */

/**
 * Stamp a thrown error with structure, leaving the message untouched — the
 * same non-enumerable, best-effort attribution `engine.js` uses for the step a
 * failure came from, for the same reason: a serialized error must not grow a
 * field, and a frozen one must not turn into a different failure.
 * @param {Error} err @param {string} key @param {*} value
 */
function attribute(err, key, value) {
  try {
    Object.defineProperty(err, key, { value, enumerable: false, configurable: true });
  } catch (_) {
    /* frozen error: attribution is best-effort */
  }
  return err;
}

/**
 * The sentence a person reads when a cell needs a value that was made
 * somewhere else. Built here so the gate and its tests cannot drift.
 * @param {{ cell: number, slot: string, from: number, peer: string }} at
 */
export function withheldSlotMessage(at) {
  const peer = at.peer ? `\`${PEER_SIGIL}${at.peer}\`` : "another peer";
  return (
    `Cell ${at.cell} reads \`${SLOT_SIGIL}${at.slot}\`, which cell ${at.from} ` +
    `writes on ${peer}. This run did not perform cell ${at.from}, so ` +
    `\`${SLOT_SIGIL}${at.slot}\` was never produced here and nothing in this ` +
    `run carries it between peers. The run stops here rather than continuing ` +
    `without it — take the value from ${peer} into ` +
    `\`${SLOT_SIGIL}${at.slot}\` first, or move cell ${at.cell} to ${peer}.`
  );
}

/** @param {string} msg */
function boundaryError(msg) {
  return new Error(`placement: ${msg}`);
}

/**
 * Read a placement, or refuse it.
 *
 * @param {Placement|null|undefined} placement
 * @param {{ cells: number, first: number, count: number }} shape
 *   `cells` — non-empty chains in the whole AST this run was handed;
 *   `first` — plan index the run starts at, as the AST reads it;
 *   `count` — non-empty chains this run will actually walk.
 * @returns {{
 *   firstCell: number,
 *   admit: (index: number, hasSlot: (label: string) => boolean) => boolean,
 * } | null}  `null` means there is no placement and the engine runs as it
 *   always has. Never a gate that admits everything — the two are the same
 *   behaviour and must not be the same object, because only one of them is a
 *   decision.
 */
export function placementGate(placement, shape) {
  if (placement == null) return null;
  if (typeof placement !== "object") {
    throw boundaryError("expected a { plan } object, or nothing at all");
  }

  const plan = placement.plan;
  if (!plan || !Array.isArray(plan.cells)) {
    throw boundaryError(
      "a placement carries the whole `planRun` result — `plan.cells` is " +
        "missing, and a gate cannot be run off a plan it does not have"
    );
  }
  if (plan.ok === false) {
    const first = plan.refusals?.[0];
    throw boundaryError(
      `this plan refused the run${first ? ` at ${first.path} (${first.field})` : ""} — ` +
        "a refused plan is a reason not to start, never permission to run the " +
        "cells it did not refuse"
    );
  }
  // A plan built without `me` marks every placed cell as somebody else's, so
  // accepting one here would skip the entire notebook and report success. The
  // plan already says so itself, as a `who-am-i` ask; this is that ask reaching
  // the one caller that must not proceed past it.
  if (plan.play !== "solo" && !plan.me) {
    throw boundaryError(
      "this plan does not know which peer you are, so every placed cell would " +
        "read as somebody else's and this run would perform none of them — " +
        "plan again with `me`"
    );
  }

  const firstCell = placement.firstCell ?? shape.first;
  if (!Number.isInteger(firstCell) || firstCell < 0) {
    throw boundaryError(`firstCell must be a cell index, got ${String(firstCell)}`);
  }
  // A plan for a different notebook. Only checkable when the caller did not
  // hand-place the window, which is exactly when it is worth checking: a whole
  // AST and a plan of a different length cannot be about the same recipe.
  if (placement.firstCell == null && plan.cells.length !== shape.cells) {
    throw boundaryError(
      `this plan describes ${plan.cells.length} ` +
        `${plan.cells.length === 1 ? "cell" : "cells"} and this run has ` +
        `${shape.cells} — plan the recipe that is about to run`
    );
  }
  if (firstCell + shape.count > plan.cells.length) {
    throw boundaryError(
      `this run walks cells ${firstCell}–${firstCell + shape.count - 1} and the ` +
        `plan stops at ${plan.cells.length - 1} — a cell the plan never placed ` +
        "would run here by default, which is the one thing a gate exists to prevent"
    );
  }

  /** @param {number} index */
  const cellAt = (index) => {
    // By position *and* by `index`: `plan.cells[n].index` is the cell's own
    // number, and a plan whose array order and indices disagree is not one this
    // gate is entitled to guess about.
    const cell = plan.cells[index];
    if (!cell || cell.index !== index) {
      throw boundaryError(
        `no plan for cell ${index} — a cell the plan does not describe does ` +
          "not run here"
      );
    }
    return cell;
  };

  return {
    firstCell,
    /**
     * @param {number} index
     * @param {(label: string) => boolean} hasSlot
     * @returns {boolean} true when this peer performs the cell
     */
    admit(index, hasSlot) {
      const cell = cellAt(index);
      if (!cell.mine) {
        placement.onSkip?.({
          cell: index,
          waitingOn: cell.peer || cell.runsOn[0] || "",
          runsOn: [...cell.runsOn],
          why: cell.why,
          produces: [...(cell.produces || [])],
        });
        return false;
      }
      // Mine, but reading something a peer's cell writes. Asked of the registry
      // first: a value that is already here arrived legitimately (a previous
      // run, a preseeded registry, and — once it exists — a handoff), and this
      // gate has nothing to say about a value it can see.
      for (const slot of cell.consumes || []) {
        if (slot.from < 0 || slot.from === index) continue;
        const producer = plan.cells[slot.from];
        if (!producer || producer.mine) continue;
        if (hasSlot(slot.label)) continue;
        throw attribute(
          new Error(
            withheldSlotMessage({
              cell: index,
              slot: slot.label,
              from: slot.from,
              peer: producer.peer || producer.runsOn[0] || "",
            })
          ),
          "basiliskWithheld",
          {
            cell: index,
            slot: slot.label,
            from: slot.from,
            peer: producer.peer || producer.runsOn[0] || "",
          }
        );
      }
      return true;
    },
  };
}
