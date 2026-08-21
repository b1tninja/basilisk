/**
 * A peer running their own cells, said out loud — the wire half.
 *
 * ## The gap, reproduced
 *
 * Nine payload kinds crossed the document channel before this one — `chat`,
 * `kc`, `attestation`, `notebook`, `notebook-ack`, `notebook-held`, `handoff`,
 * `result`, `envelope` — and **not one of them says "I ran cell N"**. `handoff`
 * asks somebody else to run one, `result` returns the published slots of a cell
 * they were handed, `attestation` signs a whole finished run after the fact. So
 * a peer running their *own* cells, which is the whole of what a placed
 * ceremony is, was invisible: in a deal, nobody could see the dealer's cell run
 * until a share happened to arrive, and until then every other screen was
 * indistinguishable from a dealer who had walked away.
 *
 * The first test here is that absence, made to happen on purpose: a meshed,
 * key-confirmed, notebook-shared pair, in which one side runs and the other
 * hears nothing.
 *
 * ## What this file is entitled to prove, and what it is not
 *
 * Two sessions in node, no React and no kernel — so a *run* here is the call
 * the run loop makes, and what is under test is the frame, the gate and the
 * refusals. That the run loop makes the call at all is source-anchored at the
 * end of this file and driven for real in `three-party-ceremony.e2e.js`, where
 * three browsers watch a dealer deal.
 */
import { afterEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { decryptSessionPayload, encryptSessionPayload } from "../lib/notebook/crypto.js";
import { signOpenPgp } from "../lib/pgp/sign.js";
import {
  buildNotebookProposal,
  proposalToJson,
} from "../lib/toolkit/notebook-share.js";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;

afterEach(async () => {
  await pair?.stop();
  pair = null;
});

const TITLE = "Thursday key ceremony";
const SOURCE = `@peer1
bytes deadbeef | encode hex | out $seed | publish
`;

async function cleartext(text, key) {
  const { armored } = await signOpenPgp(text, [key], "cleartext");
  return armored;
}

/** A meshed pair with both ends key-confirmed. */
async function meshed() {
  pair = await makeQuorumPair();
  await pair.start();
  const { creator, joiner } = pair;
  const ready = await until(
    () =>
      creator.session.peers.get(joiner.fpr)?.kcVerified === true &&
      joiner.session.peers.get(creator.fpr)?.kcVerified === true
  );
  expect(ready, `errors: ${[...creator.errors, ...joiner.errors].map((e) => e.message)}`).toBe(
    true
  );
  return { creator, joiner };
}

/** The same pair, with the notebook actually shared — the press this gates on. */
async function sharing() {
  const { creator, joiner } = await meshed();
  const signed = await cleartext(
    proposalToJson(buildNotebookProposal({ title: TITLE, source: SOURCE })),
    creator.privateKey
  );
  expect(await creator.session.shareNotebook(signed)).toBe(1);
  await pair.settle();
  return { creator, joiner };
}

/** The creator up and alone in the room, with nobody confirmed. */
async function creatorAlone() {
  pair = await makeQuorumPair();
  await pair.creator.session.start();
  await pair.settle();
  return pair;
}

/** Bring the joiner in and wait until both ends have confirmed each other. */
async function joinerArrives() {
  await pair.joiner.session.start();
  const ok = await until(
    () =>
      pair.creator.session.peers.get(pair.joiner.fpr)?.kcVerified === true &&
      pair.joiner.session.peers.get(pair.creator.fpr)?.kcVerified === true
  );
  expect(
    ok,
    `errors: ${[...pair.creator.errors, ...pair.joiner.errors].map((e) => e.message)}`
  ).toBe(true);
  await pair.settle();
}

/**
 * Read frames off a peer's channel by wrapping `send`, and open them.
 *
 * `notebook-travels.js` makes the argument: the pairwise key is the same object
 * on both ends, so the sender's own key opens what the sender wrote — which is
 * what makes this an assertion about bytes on the wire rather than about the
 * argument to a helper.
 */
function tapFrames(side, toFpr) {
  const peer = side.session.peers.get(toFpr);
  const real = peer.channel.send.bind(peer.channel);
  /** @type {Promise<any>[]} */
  const frames = [];
  peer.channel.send = (text) => {
    const { blob } = JSON.parse(text);
    frames.push(decryptSessionPayload(peer.sessionKey, blob).then((pt) => JSON.parse(pt)));
    return real(text);
  };
  return { frames, restore: () => (peer.channel.send = real) };
}

/** Put one hand-built frame on a peer's channel, sealed under the real key. */
async function inject(from, toFpr, body) {
  const peer = from.session.peers.get(toFpr);
  const blob = await encryptSessionPayload(peer.sessionKey, JSON.stringify(body));
  peer.channel.send(JSON.stringify({ v: 1, blob }));
}

/* ────────────────────────────── the gap ─────────────────────────────────── */

describe("a peer running their own cells", () => {
  it("said nothing whatever before this, on a room that was working", async () => {
    const { creator, joiner } = await sharing();
    // Everything is right: meshed, key-confirmed, the notebook shared and
    // acknowledged. The creator now runs a cell — and this is the reproduction,
    // because the *only* frames this room has a vocabulary for are somebody
    // asking a peer to run a cell, somebody returning one they were handed, and
    // somebody signing a finished run. Running your own is none of the three.
    const tap = tapFrames(creator, joiner.fpr);
    await pair.settle();
    tap.restore();
    const kinds = (await Promise.all(tap.frames)).map((f) => f.kind);
    expect(kinds).not.toContain("cell-state");
    expect(joiner.cellStates).toEqual([]);
  });

  it("crosses as one frame the far session hands straight up", async () => {
    const { creator, joiner } = await sharing();
    expect(
      await creator.session.announceCellState({ cell: 0, state: "running" })
    ).toBe(1);
    expect(await until(() => joiner.cellStates.length === 1, 3000)).toBe(true);
    expect(joiner.cellStates[0]).toMatchObject({
      from: creator.fpr,
      cell: 0,
      state: "running",
      slots: [],
    });
    expect(joiner.errors).toEqual([]);
  });
});

/* ─────────────────────── what the frame carries ─────────────────────────── */

describe("what a cell announcement carries", () => {
  it("is a cell, a state, slot labels and a clock — and nothing else", async () => {
    const { creator, joiner } = await sharing();
    const tap = tapFrames(creator, joiner.fpr);
    await creator.session.announceCellState({
      cell: 3,
      state: "done",
      slots: ["share-2", "expected"],
    });
    tap.restore();
    const rows = (await Promise.all(tap.frames)).filter((f) => f.kind === "cell-state");
    expect(rows).toHaveLength(1);
    // **The whole of it, asserted whole.** A field added here without an
    // argument is a field a reader of this test has to justify.
    expect(Object.keys(rows[0]).sort()).toEqual(["cell", "kind", "slots", "state", "ts"]);
    expect(rows[0].slots).toEqual(["share-2", "expected"]);
  });

  it("carries labels and never a value", async () => {
    const { creator, joiner } = await sharing();
    const tap = tapFrames(creator, joiner.fpr);
    // The label of a slot holding a secret is safe for a stated reason: every
    // peer already holds the shared notebook, so they know cell 3 writes
    // `$share-2`. The *value* is the thing that must never be derivable from
    // this frame, and there is no field it could ride in.
    await creator.session.announceCellState({
      cell: 3,
      state: "done",
      slots: ["share-2"],
    });
    tap.restore();
    const wire = JSON.stringify(
      (await Promise.all(tap.frames)).filter((f) => f.kind === "cell-state")
    );
    expect(wire).not.toContain("deadbeef");
    expect(wire).not.toContain(TITLE);
  });

  it("refuses to let a running cell claim it wrote anything", async () => {
    const { creator, joiner } = await sharing();
    const tap = tapFrames(creator, joiner.fpr);
    await creator.session.announceCellState({
      cell: 1,
      state: "running",
      slots: ["share-2"],
    });
    tap.restore();
    const rows = (await Promise.all(tap.frames)).filter((f) => f.kind === "cell-state");
    // A cell that has not finished has written nothing, and a frame saying
    // otherwise would be an outcome announced before it happened.
    expect(rows[0].slots).toEqual([]);
  });

  it("carries the state of a refusal and never its sentence", async () => {
    const { creator, joiner } = await sharing();
    const tap = tapFrames(creator, joiner.fpr);
    await creator.session.announceCellState({
      cell: 2,
      state: "refused",
      slots: ["share-2"],
    });
    tap.restore();
    const rows = (await Promise.all(tap.frames)).filter((f) => f.kind === "cell-state");
    // "Their cell 2 refused" is the shared fact. *Why* can name the running
    // peer's slots, keys or files, and there is deliberately no field on this
    // frame it could travel in — so the assertion is on the shape, which is
    // what makes it impossible rather than merely unused.
    expect(Object.keys(rows[0]).sort()).toEqual(["cell", "kind", "slots", "state", "ts"]);
    expect(rows[0].slots).toEqual([]);
    expect(rows[0].state).toBe("refused");
  });

  it("reaches the wire in the order the run made them, under a slow first seal", async () => {
    const { creator, joiner } = await sharing();
    // **The delay is what makes this an assertion.** The run loop fires `done`
    // for one cell and `running` for the next with no await between them, and
    // each send seals under a pairwise key first. Left as two independent
    // promise chains, whichever seal resolves first writes first — and a cell
    // whose `done` overtook its own `running` would leave a row on every peer's
    // screen saying a finished cell had just started.
    //
    // Written without the delay this test passes either way: node's WebCrypto
    // happens to settle equal-sized payloads in submission order, so the bug is
    // real and invisible. Slowing the *first* seal is the oracle — it inverts
    // the resolution order, so only a queue can keep the wire order.
    const real = globalThis.crypto.subtle.encrypt.bind(globalThis.crypto.subtle);
    let nth = 0;
    globalThis.crypto.subtle.encrypt = async (...args) => {
      const wait = nth++ === 0 ? 80 : 0;
      const out = await real(...args);
      if (wait) await new Promise((r) => setTimeout(r, wait));
      return out;
    };
    try {
      void creator.session.announceCellState({ cell: 0, state: "running" });
      void creator.session.announceCellState({ cell: 0, state: "done", slots: ["seed"] });
      void creator.session.announceCellState({ cell: 1, state: "running" });
      expect(await until(() => joiner.cellStates.length === 3, 6000)).toBe(true);
    } finally {
      globalThis.crypto.subtle.encrypt = real;
    }
    expect(joiner.cellStates.map((r) => `${r.cell}:${r.state}`)).toEqual([
      "0:running",
      "0:done",
      "1:running",
    ]);
  });
});

/* ──────────────────────────── the press gate ────────────────────────────── */

describe("a notebook nobody shared is nobody's business", () => {
  it("says nothing at all unless somebody here pressed Share", async () => {
    const { creator, joiner } = await meshed();
    await pair.settle();
    // `announceNotebookHeld`'s consent rule, and strictly weaker here: after a
    // press this disclosure is *smaller* than the consent already given,
    // because that press offered these peers the entire text and this offers
    // them the fact that a line of it ran. Before a press there is no consent
    // for it to be smaller than.
    expect(await creator.session.announceCellState({ cell: 0, state: "running" })).toBe(0);
    await pair.settle();
    expect(joiner.cellStates).toEqual([]);
  });

  it("keeps announcing after the retention goes stale, because typing un-says nothing", async () => {
    const { creator, joiner } = await sharing();
    // The press is the decision; the bytes are what go stale. `_sharedEver`
    // survives an edit for the same reason `announceNotebookHeld` does — the
    // room has already been offered this text.
    creator.session.retireSharedNotebook();
    expect(await creator.session.announceCellState({ cell: 0, state: "running" })).toBe(1);
    expect(await until(() => joiner.cellStates.length === 1, 3000)).toBe(true);
  });

  it("stops when the session does", async () => {
    const { creator } = await sharing();
    creator.session.stop();
    expect(await creator.session.announceCellState({ cell: 0, state: "running" })).toBe(0);
  });
});

/* ───────────────────────────── a late arrival ───────────────────────────── */

describe("somebody who was not there", () => {
  it("is told nothing about what already ran, and nothing pretends otherwise", async () => {
    const { creator, joiner } = await creatorAlone();
    const signed = await cleartext(
      proposalToJson(buildNotebookProposal({ title: TITLE, source: SOURCE })),
      creator.privateKey
    );
    await creator.session.shareNotebook(signed);
    // The whole notebook runs while there is nobody in the room to hear it.
    expect(await creator.session.announceCellState({ cell: 0, state: "running" })).toBe(0);
    expect(
      await creator.session.announceCellState({ cell: 0, state: "done", slots: ["seed"] })
    ).toBe(0);

    await joinerArrives();
    // **No replay, no catch-up, and deliberately no mechanism for one.** These
    // are events pushed as they happen; the run record and the receipt on the
    // machine that ran the cells remain the authority at the end. A protocol
    // for "what did I miss" would be this session speaking for a run that had
    // already finished, which is what a receipt is for.
    expect(joiner.cellStates).toEqual([]);
    // The notebook itself *does* reach them, because a retained proposal is
    // replayed on key confirmation — so this is a newcomer holding the text,
    // able to read exactly which slots cell 0 writes, and with no row claiming
    // it ran. The two boundaries are separate and stay separate.
    expect(await until(() => joiner.notebooks.length === 1, 4000)).toBe(true);
    expect(joiner.cellStates).toEqual([]);

    // And from the moment they are in, they hear everything.
    expect(await creator.session.announceCellState({ cell: 1, state: "running" })).toBe(1);
    expect(await until(() => joiner.cellStates.length === 1, 3000)).toBe(true);
    expect(joiner.cellStates[0]).toMatchObject({ cell: 1, state: "running" });
  });
});

/* ──────────────────────── what an arrival may not do ────────────────────── */

describe("an arriving announcement", () => {
  it("is dropped in silence when it names a state this version cannot read", async () => {
    const { creator, joiner } = await sharing();
    await inject(creator, joiner.fpr, {
      kind: "cell-state",
      cell: 0,
      state: "reticulating",
      slots: [],
      ts: Date.now(),
    });
    await pair.settle();
    // Silence, not a refusal: a refusal would let any confirmed peer put errors
    // on this screen by sending rubbish. It is also how a future state reaches
    // an old receiver — as nothing, rather than as a row it cannot read.
    expect(joiner.cellStates).toEqual([]);
    expect(joiner.errors).toEqual([]);
  });

  it("is dropped when the cell index is not one", async () => {
    const { creator, joiner } = await sharing();
    for (const cell of [-1, 1.5, "two", null]) {
      await inject(creator, joiner.fpr, {
        kind: "cell-state",
        cell,
        state: "done",
        slots: [],
        ts: Date.now(),
      });
    }
    await pair.settle();
    expect(joiner.cellStates).toEqual([]);
    expect(joiner.errors).toEqual([]);
  });

  it("refuses an oversized slot list whole rather than trimming it", async () => {
    const { creator, joiner } = await sharing();
    await inject(creator, joiner.fpr, {
      kind: "cell-state",
      cell: 0,
      state: "done",
      slots: Array.from({ length: 40 }, (_, i) => `s${i}`),
      ts: Date.now(),
    });
    await pair.settle();
    // **Whole, never trimmed.** "The slots this cell wrote" is a claim about a
    // set, and a list quietly cut to the cap would be a smaller set wearing the
    // shape of the full one, which a reader has no way to tell apart. An
    // announcement that cannot be made honestly is not made.
    expect(joiner.cellStates).toEqual([]);
  });

  it("registers nothing, moves no cell, and touches no run", async () => {
    const { creator, joiner } = await sharing();
    const before = JSON.stringify([...joiner.session.peers.values()].map((p) => ({
      notebookHeld: p.notebookHeld,
      notebookSent: p.notebookSent,
      kcVerified: p.kcVerified,
    })));
    const rosters = joiner.rosters.length;
    await creator.session.announceCellState({ cell: 0, state: "done", slots: ["seed"] });
    expect(await until(() => joiner.cellStates.length === 1, 3000)).toBe(true);
    // The weakest arrival on this channel, treated as the weakest. `onResult`'s
    // note says a result that resumed a run on a peer's say-so would continue
    // this machine on values nobody looked at; a *state* has not even got
    // values, so it may not move anything at all — including the roster, which
    // ICE already emits several times a second and which a peer must not be
    // able to drive.
    expect(
      JSON.stringify([...joiner.session.peers.values()].map((p) => ({
        notebookHeld: p.notebookHeld,
        notebookSent: p.notebookSent,
        kcVerified: p.kcVerified,
      })))
    ).toBe(before);
    expect(joiner.rosters.length).toBe(rosters);
  });
});

/* ────────────────────────── the product reaches it ──────────────────────── */

const read = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
const HOOK = read("../toolkit/useNotebook.ts");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const OPS = read("../lib/toolkit/quorum-ops.js");
const WIDGET = read("../toolkit/widgets/RoomCells.tsx");

describe("who consumes this", () => {
  it("is announced by the run loop, around the cell the loop is on", () => {
    // The recurring defect here is a finished mechanism with no caller. The run
    // loop is the caller, and these are the three lines that make it one.
    expect(HOOK).toMatch(
      /if \(!run\.plan \|\| run\.plan\.cells\[i\]\?\.mine\) announceCell\(run, i, "running"\)/
    );
    expect(HOOK).toMatch(/announceCell\(run, i, "done"\)/);
    expect(HOOK).toMatch(/if \(at >= 0\) announceCell\(run, at, "refused"\)/);
  });

  it("reads the run record for the slots and writes nothing back to it", () => {
    // The record and the receipt are the ledger. The live view needs one fact
    // they hold, so it reads it — a `find`, and no assignment anywhere near it.
    expect(HOOK).toMatch(
      /const performed = run\.record\.cells\.find\(\(c\) => c\.cell === cell\)/
    );
    expect(HOOK).not.toMatch(/run\.record\.cells\.(push|splice|pop|shift)/);
    // And the record's presence is what says the cell ran *here*: the kernel
    // pushes an entry when it performs a cell and returns before that when the
    // placement gate declines, so a declined cell announces nothing and the
    // peer whose cell it is announces it instead.
    expect(HOOK).toMatch(/if \(state === "done" && !performed\) return/);
  });

  it("reaches a table a person can look at, and only while a room exists", () => {
    expect(HOOK).toMatch(/^\s{4}peerCellRows,$/m);
    expect(SHELL).toMatch(/<RoomCells rows=\{nb\.peerCellRows\} \/>/);
    expect(SHELL).toMatch(/\{sessionLive \? \([\s\S]{0,600}<RoomCells/);
    expect(WIDGET).toMatch(/data-room-cells/);
    expect(WIDGET).toMatch(/data-room-cell-state/);
  });

  it("says on the table that nothing here is caught up", () => {
    // The worst reading a person could take from this surface is that an empty
    // stretch means nothing ran. There is no replay on this wire, so the table
    // has to say which of the two it is showing.
    expect(WIDGET).toMatch(/never caught up/);
    expect(WIDGET).toMatch(/nobody told you rather\s*\n?\s*than nothing ran/);
  });

  it("names a face-down slot without offering a way to get it", () => {
    expect(WIDGET).toMatch(/on their machine — it did not come here/);
    // No control, and no sentence pointing at one. Nothing on this wire
    // requests a value, so a button here would be a control whose whole effect
    // is to make a reader believe they had done something.
    const table = /<ul className="flex flex-wrap[\s\S]*?<\/ul>/.exec(WIDGET);
    expect(table, "the slot list is not where this test thinks it is").toBeTruthy();
    expect(table[0]).not.toMatch(/onClick|<[Bb]utton/);
  });

  it("holds the rows on the exchange, bounded, and drops them with the room", () => {
    // Session-scoped by construction and never persisted: they live on the
    // exchange, and the exchange closing clears them. Rows kept past a close
    // would be a table of live-looking states nothing can ever move again —
    // including cells stuck at `running` for the rest of the page.
    expect(OPS).toMatch(/ex\.cellStates\.clear\(\)/);
    expect(OPS).toMatch(/while \(byCell\.size > PEER_CELL_CAP\)/);
    expect(OPS).not.toMatch(/localStorage[\s\S]{0,80}cellState/i);
  });

  it("keeps the ticker out of the live region and lets the outcome in", () => {
    // `7ac9f50`'s rule, applied rather than restated — the assertion is that
    // the hook routes this through `announce` (region only) and not `narrate`
    // (region *and* the run's own status line, which an arriving fact would
    // overwrite milliseconds after a person could read it).
    const effect = /const onCellState = \(ev: Event\) => \{[\s\S]*?\n {4}\}/.exec(HOOK);
    expect(effect, "the cell-state listener is not where this test thinks it is").toBeTruthy();
    expect(effect[0]).toMatch(/if \(said\) announce\(said\)/);
    expect(effect[0]).not.toMatch(/narrate\(|setRunStatus\(/);
  });
});
