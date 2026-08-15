/**
 * The run, reified — one identity for "whatever happened after a press".
 *
 * Until this module existed a run was implicit. `runFrom` walked from an index
 * to the end of the notebook; nothing recorded why a cell ran; the only place a
 * "run" was a *thing* was an ad-hoc `{ run, sent }` ref invented so automatic
 * offers could be bounded by the run that caused them. Every one of those
 * absences had already cost something on the record: the dealer-absent e2e had
 * to delete a cell to run one phase, automating `sendCellResult` was refused
 * with "nothing records why a cell ran", and a recovering machine could not
 * name whose shares rebuilt the secret (dealer-absent finding 7a).
 *
 * A run is `{ id, cause, scope, record }`:
 *
 * - **`cause`** — what started it. Today that is always a person's press, and
 *   the object says which press and where: the notebook's Run at a cell, or a
 *   ceremony stage's own button. It is carried into the kernel's run log so a
 *   receipt can answer "why did this cell run" — the exact fact whose absence
 *   made an automatic result-send unsafe to build. Recording the cause does
 *   not reopen that decision: `sendCellResult` stays a press; the record is
 *   what makes the refusal's premise checkable. No other cause kinds are
 *   declared here, deliberately — a vocabulary for causes nothing can produce
 *   would be the citation-without-mechanism defect this repo keeps finding,
 *   so `startSession` (which runs no cells since `START_OPENS`) and an
 *   accepted handoff (which registers bindings and runs nothing) get a cause
 *   kind on the day something makes them start a run.
 *
 * - **`scope`** — the cells this run may execute, inclusive on both ends.
 *   `runFrom(i)` is a run whose scope is `i..end` — the behaviour it always
 *   had, now stated instead of implied — and a ceremony stage's run is scoped
 *   to its one cell. Nothing here adds a control that runs a narrower scope;
 *   whether a per-cell button should exist is a product decision this module
 *   does not make. What scope buys today is that the loop's bounds and the
 *   record agree by construction, and that a future phase-scoped run (the
 *   recover generator's missing control) has a place to say what it means.
 *
 * - **`record`** — what the run did. The kernel writes it as cells execute:
 *   per-cell reads/writes with the sender's fingerprint where a value came
 *   over the room (`meta.from`), values received in-pipeline, the placement
 *   gate's declines, the offer verdicts, and the offer keys already handed
 *   out. The last four replace `skippedRef`, `autoOffered`'s source,
 *   `offersSentRef` and `runPlanRef` in `useNotebook` — one identity, one
 *   place, so a decline and the plan that declined it can no longer come from
 *   different runs.
 *
 * Session-scoped by construction: a run lives in memory, is referenced from a
 * ref and the kernel's run log, and is never persisted — the record names key
 * ids, which is the activity log's rule for why localStorage may not hold it.
 *
 * @module lib/toolkit/run
 */

/**
 * @typedef {object} RunCause
 * @property {"press"} kind   the only kind anything can produce today — see
 *   the module note for why no others are declared
 * @property {string} press   which control: `"run-from"` (the notebook's Run,
 *   from a cell) or `"ceremony-stage"` (a CeremonySheet stage button)
 * @property {number} [cell]  where the press landed, for `run-from`
 * @property {string} [stage] which stage, for `ceremony-stage`
 */

/**
 * @typedef {object} RunScope
 * @property {number} from  first cell this run may execute
 * @property {number} to    last cell this run may execute, inclusive
 */

/**
 * Where a value came from, when it came from another machine.
 *
 * `from` is a whole fingerprint and only ever a fingerprint: `quorum.recv`
 * stamps the sender's key-confirmed fingerprint on what it delivers. A value
 * that arrived over a hand-carried `peer.*` link instead carries `link` — the
 * link's local name — and deliberately no `from`, because the peer on such a
 * link is not identified by any key and a link id printed where a fingerprint
 * goes would be an unverified origin dressed as a verified one.
 *
 * @typedef {object} RunOrigin
 * @property {string} [from]  whole fingerprint of the key-confirmed sender
 * @property {string} [link]  local name of the hand-carried link it came over
 */

/**
 * @typedef {object} RunCellRecord
 * @property {number} cell
 * @property {({ slot: string } & RunOrigin)[]} reads     slots this cell resolved
 * @property {({ slot: string } & RunOrigin)[]} writes    slots this cell registered
 * @property {(RunOrigin & { step: string })[]} received  values that arrived
 *   over a channel *inside* the pipeline, before any slot held them
 */

/**
 * @typedef {object} RunOfferVerdict
 * @property {number} cell
 * @property {string} peer
 * @property {"sent"|"refused"|"aside"} state
 * @property {string} [why]
 */

/**
 * @typedef {object} RunRecord
 * @property {RunCellRecord[]} cells     one entry per cell the kernel performed
 * @property {import("./placement.js").SkippedCell[]} declined  the gate's
 *   reports, in decline order — was `skippedRef`
 * @property {RunOfferVerdict[]} offers  latest verdict per declined cell —
 *   was the source `autoOffered` had to be
 * @property {Set<string>} sent          offer keys already handed out, marked
 *   before the send is awaited — was `offersSentRef.sent`
 */

/**
 * @typedef {object} Run
 * @property {number} id
 * @property {RunCause} cause
 * @property {RunScope} scope
 * @property {RunRecord} record
 * @property {import("./plan.js").RunPlan|null} plan  the plan the gate was
 *   built from, kept for exactly as long as its declines are — was `runPlanRef`
 */

/**
 * Runs, counted, so an offer can be bounded by the one that caused it.
 *
 * A module counter rather than a per-hook ref because the id's only job is to
 * be distinct from every other run this session — the object's identity does
 * the real work now, and callers compare runs by reference, not by number.
 */
let nextRunId = 0;

/**
 * Mint a run. The record starts empty and the kernel fills it in.
 *
 * @param {{ cause: RunCause, scope: RunScope }} spec
 * @returns {Run}
 */
export function createRun({ cause, scope }) {
  return {
    id: ++nextRunId,
    cause,
    scope: { from: Number(scope?.from) || 0, to: Number(scope?.to) || 0 },
    record: {
      cells: [],
      declined: [],
      offers: [],
      sent: new Set(),
    },
    plan: null,
  };
}

/**
 * Which cells of the notebook this run's scope admits — the non-empty ones,
 * in order. This is the list the run loop walks, derived from the scope the
 * run states rather than from an index the loop happens to remember, so the
 * bounds the record claims and the bounds the loop honoured cannot differ.
 *
 * @param {RunScope} scope
 * @param {{ steps?: unknown[] }[]} chains
 * @returns {number[]}
 */
export function cellsInScope(scope, chains) {
  const out = [];
  for (let i = 0; i < (chains || []).length; i++) {
    if (i < scope.from || i > scope.to) continue;
    if ((chains[i]?.steps?.length ?? 0) > 0) out.push(i);
  }
  return out;
}

/**
 * Fold a pass's offer verdicts into the run's record, latest per cell winning,
 * and return the folded list sorted by cell.
 *
 * A merge rather than a replace because `handOffPlaced` reports twice — the
 * cells it is leaving alone before the sends, the outcomes after — and because
 * the effect that calls it can re-fire on a re-render, where the second pass
 * finds every send already claimed and knows only about the `aside` half. A
 * replace there would erase this run's record of what went out. The queue's
 * rows render the returned copy; the record on the run is the one place the
 * verdicts live.
 *
 * @param {Run} run
 * @param {RunOfferVerdict[]} rows
 * @returns {RunOfferVerdict[]}
 */
export function noteOfferVerdicts(run, rows) {
  const by = new Map(run.record.offers.map((o) => [o.cell, o]));
  for (const row of rows || []) by.set(row.cell, row);
  run.record.offers = [...by.values()].sort((a, b) => a.cell - b.cell);
  return run.record.offers.slice();
}
