/**
 * A run that finishes hands over what it owes, and says what happened.
 *
 * The first defect this pins: `HandoffQueue`'s empty state told the reader that
 * cells placed on other people "are declined here and offered to whoever owns
 * them", and `offerCell` had exactly one caller in the entire product — the
 * per-row **Offer** button's own click handler. A placed run was Run, followed
 * by one press for every cell somebody else owns, and the copy described a
 * product that did not exist.
 *
 * The second is the overshoot of the first. `handOffPlaced` then offered *every*
 * cell the gate declined, and "the gate declined it" is a narrower fact than an
 * offer claims: a joiner who adopts a creator's notebook adopts the creator's
 * own session cells with it, so the joiner's run offered them back to the
 * creator who had already run them, and a dealer's run offered a holder their
 * own `quorum.recv` — a second, wrong story about how the share arrives. Both
 * are notebooks, so both are reproduced here as notebooks: compiled, planned and
 * gated, with the same `placementGate` the product runs.
 *
 * Three kinds of proof, on purpose. The rule is a pure function over a real plan
 * and is exercised as one. The wiring around it lives in a React hook that this
 * suite runs in node and cannot render, so it is pinned by reading the source
 * for the properties that make the automation safe — where it is called from,
 * when the bound is written, and what does *not* happen after Stop. That is the
 * same shape `session-flow.test.js` uses on the same file, for the same reason.
 * And the copy is read for the sentences the behaviour makes true.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { planRun } from "../lib/toolkit/plan.js";
import { placementGate } from "../lib/toolkit/placement.js";
import { sessionRecipe } from "../lib/toolkit/session-flow.js";
import {
  narrateNoSession,
  narrateOffers,
  offersOwed,
} from "../lib/toolkit/run-offers.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const HOOK = read("../toolkit/useNotebook.ts");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const QUEUE = read("../toolkit/widgets/HandoffQueue.tsx");

/**
 * Three peers, spelled the way `3d69090` made a peer: the whole fingerprint.
 *
 * Repeated characters rather than realistic hex so a failure message says which
 * peer at a glance — `plan.js` only ever compares these for equality.
 */
const ADA = "A".repeat(40);
const BEA = "B".repeat(40);
const CAI = "C".repeat(40);
const room = (...fprs) => Object.fromEntries(fprs.map((f) => [f, f]));

/**
 * Run one peer's gate over a notebook and hand back both halves of the answer.
 *
 * The plan *and* the report, because the whole question this module now answers
 * needs both, and building the report by hand would let the test agree with a
 * rule the product's own gate does not produce.
 *
 * `from` is the cell the run starts at, because pressing a cell's own Run is not
 * the same run as Run all and the two decline different cells — the journey's
 * joiner presses the first, and that is what makes their skipped list the three
 * cells `a4f9399`'s report named. `holds` is what an accepted offer already put
 * in the registry, which is the only reason such a run gets past its first cell.
 *
 * The walk stops where the product's does. `admit` throws when a cell that runs
 * here reads a slot a declined cell writes, `runFrom` lets it out as `Failed`,
 * and the `finally` hands over what was declined *up to that point* — so a
 * helper that walked past the throw would be building a skipped list no run can
 * produce.
 *
 * @param {string} source @param {string} me @param {string[]} members
 * @param {{ from?: number, holds?: string[] }} [pressed]
 */
function declined(source, me, members, pressed = {}) {
  const { from = 0, holds = [] } = pressed;
  const compiled = compileRecipe(source);
  expect(compiled.validation?.errors ?? [], source).toEqual([]);
  const plan = planRun(compiled, { me, roster: room(...members) });
  expect(plan.ok, JSON.stringify(plan.refusals)).toBe(true);
  const skipped = [];
  const gate = placementGate(
    { plan, onSkip: (sk) => skipped.push(sk) },
    { cells: plan.cells.length, first: from, count: plan.cells.length - from }
  );
  const have = new Set(holds);
  for (let i = from; i < plan.cells.length; i++) {
    let admitted;
    try {
      admitted = gate.admit(i, (label) => have.has(label));
    } catch (_) {
      break;
    }
    if (admitted) for (const label of plan.cells[i].produces) have.add(label);
  }
  return { plan, skipped };
}

/**
 * `placed-journey`'s notebook, plus the two cells Start appends to it.
 *
 * The headers are the ones the journey's assignment menu writes, `publish` and
 * all: without it `$b64` is a private value and `plan.js` forces the cell that
 * reads it onto its owner, which is a different notebook from the one two
 * browsers are known to run.
 *
 * `sessionRecipe` is called rather than transcribed, because the defect is
 * precisely that those two cells travel inside the proposal placed on whoever
 * opened the room — a copy of their text here would stop reproducing it the
 * moment `session-flow.js` changed its mind.
 */
const JOURNEY = [
  `@${ADA} publish\nbytes deadbeef | encode hex | out $seed`,
  `@${BEA} publish\nin $seed | decode hex | encode base64 | out $b64`,
  `@${ADA}\nin $b64 | out $done`,
  sessionRecipe({ audience: [ADA, BEA], keyFingerprint: ADA }),
].join("\n\n");

/**
 * `docs/LANGUAGE.md`'s ceremony in the verbs this build has: `scatter` is one
 * `quorum.send` per holder, and `gather` is the holder's own `quorum.recv`.
 */
const CEREMONY = [
  `@${ADA}\nrandom 32 | sss.split threshold=2 shares=3 | blip39 | out $shares`,
  `@${ADA}\nin $shares | at 1 | quorum.send to=${BEA}`,
  `@${BEA}\nquorum.recv | out $mine`,
  `@${ADA}\nin $shares | at 2 | quorum.send to=${CAI}`,
  `@${CAI}\nquorum.recv | out $theirs`,
].join("\n\n");

describe("which declined cells a finished run owes the room", () => {
  it("owes the cell whose answer this notebook goes on to read", () => {
    // The creator's own run, and the arc `placed-journey` walks.
    const { plan, skipped } = declined(JOURNEY, ADA, [ADA, BEA]);
    expect(skipped.map((s) => s.cell)).toEqual([1]);
    const { owed, aside } = offersOwed(skipped, new Set(), plan);
    expect(owed).toEqual([{ cell: 1, peer: BEA, key: `1@${BEA}` }]);
    expect(aside).toEqual([]);
  });

  it("sets aside the creator's session cells, replayed on a joiner", () => {
    // The first of the two observed defects, and `a4f9399`'s own report of it:
    // "Handed cell 2 to @peer1, cell 3 to @peer1, cell 4 to @peer1", where only
    // cell 2 is the point. The joiner adopted the whole notebook, including
    // `agent.unlock` and `quorum.offer` under the creator's header, and pressed
    // the accepted cell's own Run — so the run starts at cell 1 and declines the
    // three below it.
    //
    // Cell 2 is owed: it reads the `$b64` this machine just wrote, and nothing
    // else can carry it. Cells 3 and 4 are the creator's session cells, which
    // the creator ran to open the room this offer would travel over.
    const { plan, skipped } = declined(JOURNEY, BEA, [ADA, BEA], {
      from: 1,
      holds: ["seed"],
    });
    expect(skipped.map((s) => s.cell)).toEqual([2, 3, 4]);
    const { owed, aside } = offersOwed(skipped, new Set(), plan);
    expect(owed).toEqual([{ cell: 2, peer: ADA, key: `2@${ADA}` }]);
    expect(aside.map((o) => o.cell)).toEqual([3, 4]);
  });

  it("owes the creator's first cell to a joiner who has not been handed anything", () => {
    // Run all on a fresh joiner, and the difference from the press above is the
    // point. Cell 0 is the creator's and produces the `$seed` this machine's own
    // cell reads, so the gate declines cell 0 and then stops the run at cell 1 —
    // and the offer is this machine saying it cannot get past it. That the
    // creator ran cell 0 long ago does not make the value present here.
    const { plan, skipped } = declined(JOURNEY, BEA, [ADA, BEA]);
    expect(skipped.map((s) => s.cell)).toEqual([0]);
    const { owed, aside } = offersOwed(skipped, new Set(), plan);
    expect(owed).toEqual([{ cell: 0, peer: ADA, key: `0@${ADA}` }]);
    expect(aside).toEqual([]);
  });

  it("sets aside a holder's own quorum.recv, seen from the dealer", () => {
    // The second, and the worse of the two: an offer to run the cell whose
    // entire job is to receive what the dealer is sending by another path.
    const { plan, skipped } = declined(CEREMONY, ADA, [ADA, BEA, CAI]);
    expect(skipped.map((s) => s.cell)).toEqual([2, 4]);
    const { owed, aside } = offersOwed(skipped, new Set(), plan);
    expect(owed).toEqual([]);
    expect(aside.map((o) => o.cell)).toEqual([2, 4]);
  });

  it("owes a cell that reads a value only this machine holds", () => {
    // The other half of the rule, and the one the ceremony does not exercise:
    // nothing here reads what `$mixed` is, but the cell cannot run at all until
    // Ada's `$salt` reaches Bea. Withholding this offer would strand Bea with a
    // cell that stops the moment it reads that slot.
    const source = [
      `@${ADA} publish\nrandom 32 | encode hex | out $salt`,
      `@${BEA}\nin $salt | decode hex | encode base64 | out $mixed`,
    ].join("\n\n");
    const { plan, skipped } = declined(source, ADA, [ADA, BEA]);
    const { owed, aside } = offersOwed(skipped, new Set(), plan);
    expect(owed).toEqual([{ cell: 1, peer: BEA, key: `1@${BEA}` }]);
    expect(aside).toEqual([]);
  });

  it("sets aside a cell whose input is a third peer's to send", () => {
    // Cai's cell reads Bea's value. `buildOfferFor` refuses exactly this as
    // `incomplete` — "the offer @bea makes is theirs to make" — so an offer Ada
    // sent could carry nothing and would come back a refusal naming somebody
    // else's job. Nothing is withheld that could have been delivered.
    const source = [
      `@${ADA} publish\nrandom 32 | encode hex | out $salt`,
      `@${BEA} publish\nrandom 32 | encode hex | out $pepper`,
      `@${CAI}\nin $pepper | decode hex | encode base64 | out $mixed`,
    ].join("\n\n");
    const { plan, skipped } = declined(source, ADA, [ADA, BEA, CAI]);
    expect(skipped.map((s) => s.cell)).toEqual([1, 2]);
    const { owed, aside } = offersOwed(skipped, new Set(), plan);
    expect(owed).toEqual([]);
    expect(aside.map((o) => o.cell)).toEqual([1, 2]);
  });

  it("drops a cell the run already handed over, and keeps saying which are aside", () => {
    // The property that makes an automatic offer safe to re-enter. `offerCell`
    // deliberately does not consume the skipped cell — that is what makes
    // recovery after a reload possible and `HandoffQueue` promises it in
    // writing — so nothing downstream would stop a second pass from sending the
    // same document twice.
    //
    // `aside` is not bounded that way and must not be: it is a reading of the
    // notebook rather than a record of an act, and the row that says a cell was
    // left alone has to survive the second pass that finds the sends claimed.
    const { plan, skipped } = declined(JOURNEY, ADA, [ADA, BEA]);
    const first = offersOwed(skipped, new Set(), plan);
    const sent = new Set(first.owed.map((o) => o.key));
    expect(sent.size).toBe(1);
    const again = offersOwed(skipped, sent, plan);
    expect(again.owed).toEqual([]);
    expect(again.aside).toEqual(first.aside);
  });

  it("keys on the cell and the peer together, so a moved placement is still sent", () => {
    // A notebook edited between two runs can move a cell onto somebody else.
    // Bounded by the cell alone, "cell 1 has gone out" would suppress an offer
    // to a person who has never been sent anything.
    const moved = JOURNEY.replace(`@${BEA} publish\nin $seed`, `@${CAI} publish\nin $seed`);
    expect(moved, "the placement this test moves is not where it was").not.toBe(JOURNEY);
    const { plan, skipped } = declined(JOURNEY, ADA, [ADA, BEA]);
    const sent = new Set(offersOwed(skipped, new Set(), plan).owed.map((o) => o.key));
    const next = declined(moved, ADA, [ADA, BEA, CAI]);
    expect(offersOwed(next.skipped, sent, next.plan).owed).toEqual([
      { cell: 1, peer: CAI, key: `1@${CAI}` },
    ]);
  });

  it("says nothing about a cell the gate declined for nobody", () => {
    // `offerCell` would answer "that cell was not left to anybody", which is
    // true and is not news to a reader looking at a cell with no header.
    const { plan } = declined(JOURNEY, ADA, [ADA, BEA]);
    const out = offersOwed([{ cell: 1, waitingOn: "" }, { cell: 2 }], new Set(), plan);
    expect(out).toEqual({ owed: [], aside: [] });
  });

  it("counts one declined cell as one document even if the gate reports it twice", () => {
    const { plan, skipped } = declined(JOURNEY, ADA, [ADA, BEA]);
    const { owed } = offersOwed([...skipped, ...skipped], new Set(), plan);
    expect(owed).toHaveLength(1);
  });

  it("refuses to guess when the plan and the gate's report came apart", () => {
    // `placementGate`'s rule one layer along: the two answers a default could
    // pick — offer everything, offer nothing — are the noise this rule removes
    // and a value somebody is waiting on, and neither may be chosen silently.
    const { skipped } = declined(JOURNEY, BEA, [ADA, BEA]);
    expect(() => offersOwed(skipped, new Set(), null)).toThrow(/does not describe it/);
    expect(() => offersOwed(skipped, new Set(), { cells: [] })).toThrow(/one run's answer/);
  });
});

describe("the sentence a run appends to its own verdict", () => {
  it("names the cells that went and who has them", () => {
    const note = narrateOffers([
      { cell: 1, peer: "peer2", ok: true },
      { cell: 3, peer: "peer3", ok: true },
    ]);
    expect(note).toContain("cell 1 to @peer2");
    expect(note).toContain("cell 3 to @peer3");
    expect(note).toMatch(/nothing runs there until they accept/);
  });

  it("names a refusal per cell, in the handoff layer's own words", () => {
    // The failure this exists to prevent is a run that offered nothing and said
    // so as a number. `offerCell` refuses for states that are distinguishable
    // and point at different remedies, and a count would erase the difference.
    const note = narrateOffers([
      { cell: 1, peer: "peer2", ok: true },
      { cell: 2, peer: "peer3", ok: false, why: "Nobody in this room answers to @peer3." },
      {
        cell: 4,
        peer: "peer4",
        ok: false,
        why: "No verified peer holds that fingerprint yet.",
      },
    ]);
    expect(note).toContain("cell 1 to @peer2");
    expect(note).toContain("Cell 2 could not go to @peer3. Nobody in this room answers to @peer3.");
    expect(note).toContain("Cell 4 could not go to @peer4.");
    expect(note).toContain("No verified peer holds that fingerprint yet.");
  });

  it("still says something when a refusal arrives with no reason", () => {
    expect(narrateOffers([{ cell: 1, peer: "peer2", ok: false }])).toMatch(
      /Cell 1 could not go to @peer2\. \S/
    );
  });

  it("is empty when there is nothing to report, so a caller can append it blind", () => {
    expect(narrateOffers([])).toBe("");
    expect(narrateNoSession([])).toBe("");
  });

  it("names the cells stranded when the room went away mid-run", () => {
    // Reachable only this way: the gate is built from a live roster, so a run
    // that begins without a room declines nothing and never gets here.
    const one = narrateNoSession([{ cell: 2, peer: "peer2", key: "2@peer2" }]);
    expect(one).toMatch(/session ended before this run did/);
    expect(one).toContain("cell 2 is");
    const two = narrateNoSession([
      { cell: 1, peer: "peer2", key: "1@peer2" },
      { cell: 3, peer: "peer3", key: "3@peer3" },
    ]);
    expect(two).toContain("cells 1 and 3 are");
  });
});

describe("the run is what hands them over, not a second press", () => {
  it("calls the offer from an effect, never from inside runFrom", () => {
    // `autoRunFrom`'s hazard, one arc along: `offerCell` reads `source`,
    // `title` and the roster through closures `runFrom` does not depend on, so
    // calling it in the run's own body would offer the notebook as it stood
    // when that callback was built.
    expect(HOOK).toMatch(/setFinishedRun\(seq\);/);
    expect(HOOK).toMatch(
      /if \(finishedRun == null\) return;[\s\S]{0,120}void handOffPlaced\(finishedRun\);/
    );
    // And the run's own body does not reach for it.
    const runBody = HOOK.slice(
      HOOK.indexOf("const runFrom = useCallback"),
      HOOK.indexOf("Guided key ceremony")
    );
    expect(runBody).not.toMatch(/handOffPlaced\(/);
    expect(runBody).not.toMatch(/offerCell\(/);
  });

  it("marks a cell as handed over before the send is awaited", () => {
    // `NotebookSession._onKnock`'s order, and its reason: the failure being
    // prevented is two passes overlapping, and a mark written after the answer
    // comes back is not written during the window that matters.
    expect(HOOK).toMatch(/bound\.sent\.add\(o\.key\);\s*\n\s*const r = await offerCell\(o\.cell\);/);
  });

  it("bounds re-offering by what went out, and by the run, rather than by a clock", () => {
    expect(HOOK).toMatch(/offersSentRef = useRef<\{ run: number; sent: Set<string> \}>/);
    expect(HOOK).toMatch(/offersSentRef\.current = \{ run: seq, sent: new Set<string>\(\) \};/);
    // The guard that stops a stale run's offers being marked against a fresh
    // bound.
    expect(HOOK).toMatch(/if \(bound\.run !== run\) return;/);
    expect(HOOK).not.toMatch(/setTimeout\([^)]*handOffPlaced/);
  });

  it("does not hand anything over after Stop, and does not go quiet about it", () => {
    // The whole argument for sending without a press is that it restates the
    // decision Run already made. Stop takes that decision back, so the run that
    // was stopped is the one run that finishes without asking for the send —
    // and it says the cells are still theirs rather than ending in silence.
    const stopped = HOOK.indexOf("Stopped — nothing was handed over");
    expect(stopped).toBeGreaterThan(0);
    expect(HOOK.slice(stopped, stopped + 400)).toMatch(/still theirs, and handing/);
    // Asked for on the other branch and on no other line: one occurrence, and
    // it is the body of the `else` the stop check opens. Written as two
    // assertions because "it is inside an else" and "there is no second copy
    // outside one" are the two ways this can go wrong.
    expect(HOOK.match(/setFinishedRun\(seq\)/g)).toHaveLength(1);
    expect(HOOK).toMatch(/\} else \{\r?\n\s*setFinishedRun\(seq\);\r?\n\s*\}/);
  });

  it("puts what happened on the run line, which is the surface always on screen", () => {
    expect(HOOK).toMatch(/setRunStatus\(\(prev\) => `\$\{prev\} \$\{narrateOffers\(outcomes\)\}`/);
    expect(HOOK).toMatch(/setRunStatus\(\(prev\) => `\$\{prev\} \$\{narrateNoSession\(waiting\)\}`/);
  });

  it("builds the run from the room as it stands, or there is nothing to hand over", () => {
    // Found while watching this work in a browser: `runFrom` closed over
    // `handoffWho` without depending on it, so it kept whichever roster was
    // current the last time `chains` changed. Compose the cells and *then*
    // press Start — the flow `96dde48` exists to allow — and `me` is "", no
    // plan is built, no placement reaches `runCell`, and the notebook runs
    // every cell locally including other people's. An automatic offer over an
    // empty skipped list is silence, which is the failure this arc is about.
    const deps = /\[buildBindings, chains, compiled\.validation, ([^\]]*)\]/.exec(HOOK);
    expect(deps, "runFrom's dependency list moved").not.toBeNull();
    expect(deps[1]).toContain("handoffWho");
  });

  it("still leaves the accepted cell in the sender's list", () => {
    // The recovery `HandoffQueue` promises in writing survives the automation:
    // sending is still non-destructive, so asking a peer to hand a cell over
    // again is still a complete fix.
    expect(HOOK).not.toMatch(/skippedRef\.current\s*=\s*skippedRef\.current\.filter/);
  });
});

describe("the result coming back is still a press, and the panel says why", () => {
  it("has no caller but the one a person reaches", () => {
    // `runFrom` runs every cell from an index onward, so a cell accepted from a
    // peer runs again on every later press of Run, and nothing records why a
    // cell ran. An automatic send could not tell a run made for them from a run
    // made for the reader.
    const calls = SHELL.match(/nb\.sendCellResult\(/g) || [];
    expect(calls).toHaveLength(1);
    expect(SHELL).toMatch(/onSendResult=\{\(cell, label\) => \{[\s\S]{0,80}nb\.sendCellResult\(cell, label\)/);
    expect(HOOK).not.toMatch(/void sendCellResult\(/);
  });

  it("says so in the row that is waiting for it", () => {
    expect(QUEUE).toMatch(/This one is not sent for you/);
    expect(QUEUE).toMatch(/nothing here can tell a run made for them from a\s*\n?\s*run made for you/);
  });
});

describe("the copy describes what the code does", () => {
  it("promises the automatic hand-over, and only for the cells that get one", () => {
    expect(QUEUE).toMatch(/the ones this machine is an end of are handed to whoever owns them/);
    expect(QUEUE).toMatch(/Nothing runs on their machine until they accept/);
    // The old sentence claimed an offer nothing made.
    expect(QUEUE).not.toMatch(/declined here and offered to whoever owns them/);
    // And its replacement claimed one for every declined cell, which is the
    // sentence the creator's session cells made false.
    expect(QUEUE).not.toMatch(/the cells that are not yours are declined here, and handed to/);
    // The reader is told which cells those are, in the terms the rule uses.
    expect(QUEUE).toMatch(/needs a value made here, or writes one this notebook goes on to read/);
  });

  it("draws all four states of a row apart", () => {
    expect(QUEUE).toContain("data-offer-state");
    expect(QUEUE).toMatch(/Handed to \$\{peer\(c\.peer\)\} when the run finished/);
    expect(QUEUE).toMatch(/The run tried to hand this over and could not/);
    expect(QUEUE).toMatch(/Nothing has gone out for this cell/);
    // The fourth is a decision rather than an outcome, and says so: it names
    // both halves of the rule and points at no remedy, because there is none to
    // point at unless the peer asks for one.
    // The condition, not only the sentence: a branch nothing can reach is the
    // shape of defect this repo keeps finding, and a string search finds the
    // words either way.
    expect(QUEUE).toMatch(/: c\.offered === "aside"\s*\r?\n\s*\? `Left alone, and nothing here is waiting on it/);
    expect(QUEUE).toMatch(/reads no value made on this machine, and nothing in this notebook reads what it writes/);
    // And the button says "again" only where something was actually tried — a
    // cell the run set aside has had nothing sent for it.
    expect(QUEUE).toMatch(/c\.offered === "sent" \|\| c\.offered === "refused" \? " again" : ""/);
  });

  it("joins the run's own verdicts to the rows they are about", () => {
    expect(SHELL).toMatch(/new Map\(nb\.autoOffered\.map\(/);
    expect(SHELL).toMatch(/\[nb\.busy, nb\.skippedCells, nb\.autoOffered\]/);
    expect(SHELL).toMatch(/offered: noted \? noted\.state : \("none" as const\)/);
  });

  it("records the aside verdict whether or not there is a room to send in", () => {
    // The row for a holder's `quorum.recv` must not read "nothing has gone out"
    // as though the session were the reason — it would not have gone out in a
    // full room either. So the verdict is folded in above the session check.
    const body = HOOK.slice(
      HOOK.indexOf("const handOffPlaced = useCallback"),
      HOOK.indexOf("const sendCellResult = useCallback")
    );
    expect(body).toMatch(/noteOffers\(\s*aside\.map[\s\S]*?\)\);[\s\S]*?if \(!getLiveSession\(\)\)/);
    // Folded in, never replacing: the effect can re-fire, and the second pass
    // knows only about the aside half.
    expect(HOOK).toMatch(/const by = new Map\(prev\.map\(\(o\) => \[o\.cell, o\]\)\);/);
    expect(HOOK).not.toMatch(/setAutoOffered\(outcomes\)/);
  });

  it("keeps the plan beside the report of what it declined", () => {
    // The rule needs `consumes[].from`, `produces` and `mine`, and none of them
    // is in the gate's report. A plan from a different run answering about this
    // run's declines is the failure this pins.
    expect(HOOK).toMatch(/skippedRef\.current = \[\];[\s\S]{0,600}runPlanRef\.current = null;/);
    expect(HOOK).toMatch(/runPlanRef\.current = plan;\s*\r?\n\s*placement = \{ plan, onSkip:/);
    // The sentence a Stop leaves behind names what this run *would* have sent,
    // not every cell the gate declined — otherwise it invites the reader to
    // press Hand over on the very documents the rule exists to stop.
    expect(HOOK).toMatch(/const \{ owed: waiting \} = offersOwed\(/);
    // And no call site decides without the plan. Both of them — the run's own
    // send and that sentence — name the same ref.
    const calls = [...HOOK.matchAll(/offersOwed\(/g)];
    expect(calls).toHaveLength(2);
    for (const at of calls) {
      expect(HOOK.slice(at.index, at.index + 200)).toContain("runPlanRef.current");
    }
  });
});
