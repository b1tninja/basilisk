/**
 * A run that finishes hands over what it declined, and says what happened.
 *
 * The defect this pins: `HandoffQueue`'s empty state told the reader that cells
 * placed on other people "are declined here and offered to whoever owns them",
 * and `offerCell` had exactly one caller in the entire product — the per-row
 * **Offer** button's own click handler. A placed run was Run, followed by one
 * press for every cell somebody else owns, and the copy described a product
 * that did not exist.
 *
 * Two halves, and they are different kinds of proof on purpose. `run-offers.js`
 * is a pure module and is exercised as one: real inputs, real answers, no
 * browser. The wiring around it lives in a React hook that this suite runs in
 * node and cannot render, so it is pinned by reading the source for the
 * properties that make the automation safe — where it is called from, when the
 * bound is written, and what does *not* happen after Stop. That is the same
 * shape `session-flow.test.js` uses on the same file, for the same reason.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  narrateNoSession,
  narrateOffers,
  pendingOffers,
} from "../lib/toolkit/run-offers.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const HOOK = read("../toolkit/useNotebook.ts");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const QUEUE = read("../toolkit/widgets/HandoffQueue.tsx");

/** The gate's own report shape, as `placement.js` writes it into `onSkip`. */
const skip = (cell, waitingOn, produces = []) => ({
  cell,
  waitingOn,
  runsOn: [waitingOn],
  why: "not-mine",
  produces,
});

describe("what a finished run still owes the room", () => {
  it("names every declined cell and the label that owns it, in cell order", () => {
    const out = pendingOffers([skip(3, "peer2", ["b64"]), skip(1, "peer3")], new Set());
    expect(out).toEqual([
      { cell: 3, peer: "peer2", key: "3@peer2" },
      { cell: 1, peer: "peer3", key: "1@peer3" },
    ]);
  });

  it("drops a cell the run already handed over", () => {
    // The property that makes an automatic offer safe to re-enter. `offerCell`
    // deliberately does not consume the skipped cell — that is what makes
    // recovery after a reload possible and `HandoffQueue` promises it in
    // writing — so nothing downstream would stop a second pass from sending the
    // same document twice.
    const skipped = [skip(1, "peer2"), skip(2, "peer3")];
    const sent = new Set(pendingOffers(skipped, new Set()).map((o) => o.key));
    expect(sent.size).toBe(2);
    expect(pendingOffers(skipped, sent)).toEqual([]);
  });

  it("keys on the cell and the peer together, so a moved placement is still sent", () => {
    // A notebook edited between two runs can move a cell onto somebody else.
    // Bounded by the cell alone, "cell 1 has gone out" would suppress an offer
    // to a person who has never been sent anything.
    const sent = new Set(pendingOffers([skip(1, "peer2")], new Set()).map((o) => o.key));
    expect(pendingOffers([skip(1, "peer3")], sent)).toEqual([
      { cell: 1, peer: "peer3", key: "1@peer3" },
    ]);
  });

  it("says nothing about a cell the gate declined for nobody", () => {
    // `offerCell` would answer "that cell was not left to anybody", which is
    // true and is not news to a reader looking at a cell with no header.
    expect(pendingOffers([skip(4, ""), { cell: 5 }], new Set())).toEqual([]);
  });

  it("counts one declined cell as one document even if the gate reports it twice", () => {
    const out = pendingOffers([skip(1, "peer2"), skip(1, "peer2")], new Set());
    expect(out).toHaveLength(1);
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
  it("promises the automatic hand-over, and only what it does", () => {
    expect(QUEUE).toMatch(/handed to whoever owns them as the run ends/);
    expect(QUEUE).toMatch(/Nothing runs on their machine until they accept/);
    // The old sentence claimed an offer nothing made.
    expect(QUEUE).not.toMatch(/declined here and offered to whoever owns them/);
  });

  it("draws a row that has already gone differently from one that has not", () => {
    expect(QUEUE).toContain("data-offer-state");
    expect(QUEUE).toMatch(/Handed to \$\{peer\(c\.peer\)\} when the run finished/);
    expect(QUEUE).toMatch(/The run tried to hand this over and could not/);
    expect(QUEUE).toMatch(/Nothing has gone out for this cell/);
    // And the button stops offering to do a thing that is done.
    expect(QUEUE).toMatch(/c\.offered === "none" \? "" : " again"/);
  });

  it("joins the run's own report to the rows it is about", () => {
    expect(SHELL).toMatch(/new Map\(nb\.autoOffered\.map\(/);
    expect(SHELL).toMatch(/\[nb\.busy, nb\.skippedCells, nb\.autoOffered\]/);
  });
});
