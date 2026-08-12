/**
 * The shared-notebook joining flow — its derivations, its link, and the fact
 * that something renders it.
 *
 * The transport was proven before any of this existed: `quorum-lifecycle`
 * covers the session manager, `notebook-dtls-binding` covers the key
 * confirmation, and `placed-run-arc.e2e` drives an offer and a result between
 * two real browsers. What had no test — because it had no code — was the
 * surface: how a room is named, what an invite contains, and what a person is
 * told while nothing appears to be happening.
 *
 * Two halves, and the second is the one this repo keeps needing. The first pins
 * the sentences and the link format. The second pins the *consumers*, because
 * this codebase's recurring defect is a finished mechanism nothing renders —
 * `ShareSheet` shipped a "Start shared session" button that ToolkitShell never
 * gave a handler, and `useNotebook` shipped `offerCell`, `acceptHandoff`,
 * `sendCellResult` and `skippedCells` that nothing called. Both are asserted
 * here by reading the shell, in the style `boundary-ui.test.js` established.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  INVITE_CARRIES,
  INVITE_OMITS,
  confirmationReadout,
  parseInviteAudience,
  rosterCounts,
  sessionReadout,
  sessionRecipe,
  sessionStage,
  startIssues,
} from "../lib/toolkit/session-flow.js";
import { hashForJoin, parseToolkitHash } from "../lib/toolkit/fragment.js";
import { deriveRoomId } from "../lib/notebook/room.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const HOOK = read("../toolkit/useNotebook.ts");
const SHEET = read("../toolkit/widgets/SessionSheet.tsx");
const LIVE = read("../toolkit/widgets/SessionLive.tsx");
const START = read("../toolkit/widgets/SessionStart.tsx");
const INVITE = read("../toolkit/widgets/InviteCard.tsx");
const QUEUE = read("../toolkit/widgets/HandoffQueue.tsx");

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const LIN = "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029";

const connected = (authenticated) => ({ state: "connected", authenticated });

/* ─────────────────────────── joined vs verified ─────────────────────────── */

describe("the roster is three numbers, not one", () => {
  it("counts joined and verified separately", () => {
    // `ShareSheet`'s RosterCount exists because a single "2 peers" hides the gap
    // an attacker holding a forwarded link would sit in. Same rule, one layer
    // down, so both surfaces get it from one derivation.
    expect(rosterCounts([connected(true), connected(false)])).toEqual({
      joined: 2,
      verified: 1,
      pending: 1,
      down: 0,
    });
  });

  it("counts a dead link as neither joined nor missing", () => {
    // The third number the other two cannot express. A failed peer is not
    // "waiting to be confirmed" and it is not absent either.
    expect(rosterCounts([connected(true), { state: "failed", authenticated: true }])).toEqual({
      joined: 1,
      verified: 1,
      pending: 0,
      down: 1,
    });
  });

  it("does not count a peer that has not arrived", () => {
    // `projectRosterPeers` puts every audience member in the roster from the
    // moment the session starts, at state "new". Counting those as joined would
    // report a full room before anybody connected.
    expect(rosterCounts([{ state: "new" }, { state: "new" }])).toMatchObject({ joined: 0 });
  });
});

describe("the stage splits the two phases that cover four situations", () => {
  it("tells an empty room from one where somebody is unconfirmed", () => {
    expect(sessionStage({ phase: "waiting", peers: [] })).toBe("waiting");
    expect(sessionStage({ phase: "waiting", peers: [connected(false)] })).toBe("unconfirmed");
  });

  it("tells a fully confirmed room from a half-confirmed one", () => {
    expect(sessionStage({ phase: "connected", peers: [connected(true)] })).toBe("verified");
    expect(
      sessionStage({ phase: "connected", peers: [connected(true), connected(false)] })
    ).toBe("partial");
  });

  it("refuses to call an empty room verified, whatever the phase says", () => {
    // `connected` with nobody in the roster is reachable — a peer can drop
    // between the phase patch and the roster emit — and "1 peer confirmed" over
    // an empty list would be the worst possible reading of it.
    expect(sessionStage({ phase: "connected", peers: [] })).toBe("waiting");
  });
});

/* ──────────────────── what the reader is actually told ──────────────────── */

describe("the readout carries the transport facts a phase name cannot", () => {
  it("explains a silent room by the relay keeping no history", () => {
    // The load-bearing sentence of the whole flow. `NotebookSession.start()`
    // publishes the signed invite exactly once, and Web PubSub brokers only to
    // the connections in the group at that instant — so a joiner arriving a
    // second later is in the right room and will never see the introduction.
    const read = sessionReadout({ phase: "waiting", role: "creator", peers: [] });
    expect(read.tone).toBe("warn");
    expect(read.why).toMatch(/published once|keeps no history/);
    // And therefore the remedy is "start again", not "wait longer" — which is
    // the opposite of what a spinner would have taught.
    expect(read.next).toMatch(/start this again/);
  });

  it("inverts that advice for the joiner", () => {
    const joiner = sessionReadout({ phase: "waiting", role: "joiner", peers: [] });
    expect(joiner.headline).toBe("Waiting for the invite");
    expect(joiner.next).toMatch(/start the session again/);
  });

  it("says what confirmation actually bound, and never asks for a comparison", () => {
    const read = sessionReadout({ phase: "connected", peers: [connected(true)] });
    expect(read.tone).toBe("brand");
    expect(read.why).toMatch(/room id/);
    expect(read.why).toMatch(/fingerprints/);
    expect(read.why).toMatch(/nothing to type/);
  });

  it("spends --error on a half-confirmed room and --warn on an unconfirmed one", () => {
    // A peer mid-handshake has not failed confirmation, it has not reached it,
    // and badging every join as a security problem is how a real one stops
    // being read. A room where some are confirmed and some are not is the other
    // thing entirely: a claim that failed to be established.
    expect(sessionReadout({ phase: "waiting", peers: [connected(false)] }).tone).toBe("warn");
    expect(
      sessionReadout({ phase: "connected", peers: [connected(true), connected(false)] }).tone
    ).toBe("error");
  });

  it("quotes the transport's own last words on a failure", () => {
    // This module did not observe the failure. Inventing a sentence for it is
    // how a panel and a tile come to hold two opinions about one cause.
    const read = sessionReadout({
      phase: "failed",
      status: "Signalling dropped — reconnecting…",
      peers: [],
    });
    expect(read.why).toBe("Signalling dropped — reconnecting…");
    expect(read.next).toMatch(/Restart the connection/);
  });
});

describe("nothing in this flow asks a person to compare a code", () => {
  it("never asks for one, in any sentence it can produce", () => {
    // Key confirmation here is a `kc` frame carrying a transcript hash, checked
    // by the machine. A "compare these words with your friend" screen would be
    // a different protocol and a convincing lie about what the code does.
    //
    // Asserted over the strings themselves rather than over the source files:
    // both modules *explain* the absence in their prose ("nothing for you to
    // compare", "there is no short authentication string"), so a grep for the
    // words would fail on the very comments that make the rule explicit. Every
    // stage and every peer state is enumerated, so a new branch cannot slip a
    // request in.
    const sentences = [];
    for (const phase of ["idle", "offering", "waiting", "connected", "failed", "closed"]) {
      for (const role of ["creator", "joiner"]) {
        for (const peers of [
          [],
          [connected(false)],
          [connected(true)],
          [connected(true), connected(false)],
        ]) {
          const r = sessionReadout({ phase, role, peers, status: "" });
          sentences.push(r.headline, r.why, r.next || "");
        }
      }
    }
    for (const state of ["new", "connecting", "connected", "failed", "disconnected", "closed"]) {
      for (const authenticated of [true, false]) {
        const r = confirmationReadout({ state, authenticated });
        sentences.push(r.verdict, r.why);
      }
    }
    const all = sentences.join(" · ");
    // An *ask* — "compare these", "compare the code". The one sentence that
    // uses the verb at all uses it to say the opposite, and is asserted for
    // below rather than pattern-matched around.
    expect(all).not.toMatch(/compare (?:these|the|this|that|it|them|codes|words|numbers)/i);
    expect(all).not.toMatch(/aloud|read it back|say the words/i);
    expect(all).not.toMatch(/safety number|authentication string|emoji|check the code/i);
    // Not vacuous: these sentences really are the ones on screen, they describe
    // confirmation, and one of them states the absence in so many words.
    expect(all).toMatch(/transcript hash/);
    expect(all).toMatch(/nothing for you to compare/);
  });

  it("says confirmation is automatic where a reader will look for the ask", () => {
    const read = confirmationReadout(connected(true));
    expect(read.verdict).toBe("confirmed");
    expect(read.why).toMatch(/transcript hash/);
    expect(sessionReadout({ phase: "connected", peers: [connected(true)] }).why).toMatch(
      /nothing for you to compare/
    );
  });

  it("withholds a verdict while the link is still coming up", () => {
    expect(confirmationReadout({ state: "connecting" }).tone).toBe("muted");
    expect(confirmationReadout({ state: "connecting" }).verdict).toBe("connecting");
    expect(confirmationReadout(connected(false)).verdict).toBe("unconfirmed");
    expect(confirmationReadout({ state: "failed" }).verdict).toBe("link down");
  });
});

/* ────────────────────────── naming the room ─────────────────────────────── */

describe("a room is refused before it is derived, not after", () => {
  it("names each missing thing separately", () => {
    expect(startIssues({ audience: [], keyFingerprint: "" })).toHaveLength(2);
    expect(startIssues({ audience: [ADA, GRACE], keyFingerprint: ADA })).toEqual([]);
  });

  it("catches a key that is not in the room", () => {
    // The refusal easiest to hit and hardest to diagnose without it: the room is
    // a digest of the audience, so opening it under a key outside the list
    // derives a *different* room and both ends wait forever in rooms neither
    // can see. `NotebookSession` refuses the same thing — "Local key must be in
    // the room audience" — a moment later, with the reader no longer looking at
    // the list that caused it.
    const issues = startIssues({ audience: [ADA, GRACE], keyFingerprint: LIN });
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatch(/not in the audience/);
  });

  it("refuses a second exchange, as the transport does", () => {
    const issues = startIssues({ audience: [ADA, GRACE], keyFingerprint: ADA, live: true });
    expect(issues[0]).toMatch(/already open/);
  });

  it("makes the two roles a visible choice, and says why the order matters", () => {
    // Which end presses first is a correctness question, not a preference: the
    // invite is published once onto a relay with no history. Collapsing the two
    // into one "Connect" would make that failure look like a network problem.
    expect(START).toMatch(/I am starting it/);
    expect(START).toMatch(/I was invited/);
    expect(START).toMatch(/relay keeps no history/);
    expect(START).toMatch(/let them press Join first/);
  });

  it("shows the cells before it writes them", () => {
    // The claim is that a session is an ordinary recipe. A reader who cannot see
    // the recipe has only our word for it.
    expect(START).toMatch(/the cells this writes/);
    expect(START).toMatch(/data-session-recipe/);
  });
});

describe("starting a session is a recipe, not a code path", () => {
  it("writes the two cells a person could have typed", () => {
    const text = sessionRecipe({ audience: [GRACE, ADA], keyFingerprint: ADA });
    expect(text).toContain(`agent.unlock ${ADA} | out $me`);
    expect(text).toContain(`quorum.offer to="${[ADA, GRACE].sort().join(",")}" key=$me`);
  });

  it("keeps agent.unlock its own cell", () => {
    // It is the step that exports a private key into the run and is marked as
    // such everywhere — the registry's `exposure`, the chip's warn underline,
    // the exposure trace across the notebook. Folding it into a `key=`
    // parameter would erase that mark at the moment it matters most.
    const text = sessionRecipe({ audience: [ADA, GRACE], keyFingerprint: ADA });
    const [first, blank, second] = text.split("\n");
    expect(first.startsWith("agent.unlock")).toBe(true);
    expect(blank).toBe("");
    expect(second.startsWith("quorum.")).toBe(true);
  });

  it("writes quorum.join for the invited side", () => {
    expect(
      sessionRecipe({ audience: [ADA, GRACE], keyFingerprint: GRACE, role: "join" })
    ).toContain("quorum.join");
  });

  it("sorts the audience the way the room derivation does", async () => {
    // The recipe's `to=` is what `execQuorumOpen` hands to `deriveRoomId`, and
    // it canonicalises again — but a recipe whose text differed by order would
    // be two spellings of one room in the notebook, in Source view, and in the
    // receipt.
    const text = sessionRecipe({ audience: [GRACE, ADA], keyFingerprint: ADA });
    const to = text.match(/to="([^"]+)"/)[1].split(",");
    expect(to).toEqual([ADA, GRACE].sort());
    // Not vacuous: that list really is what names the room.
    expect(await deriveRoomId(to, { relyingPartyId: "example.test" })).toBe(
      await deriveRoomId([GRACE, ADA], { relyingPartyId: "example.test" })
    );
  });
});

/* ───────────────────────────── the invite ───────────────────────────────── */

describe("the invite is an audience and nothing else", () => {
  it("round-trips through the fragment", () => {
    const hash = hashForJoin([GRACE, ADA]);
    expect(hash.ok).toBe(true);
    const action = parseToolkitHash(hash.hash);
    expect(action.kind).toBe("join");
    expect(action.audience).toEqual([ADA, GRACE].sort());
  });

  it("carries no room id, so the room never travels", () => {
    // The room is the truncated digest and the whole point is that it is
    // derived at both ends. A link that carried it would be a link that could
    // be checked against a lobby without holding the audience — which is the
    // gap `deriveRoomMaterial` exists to keep open.
    const { hash } = hashForJoin([ADA, GRACE]);
    expect(hash).toBe(`#j=${[ADA, GRACE].sort().join(",")}`);
    expect(hash).not.toMatch(/room|key=|token/i);
  });

  it("refuses an audience that derives no room", () => {
    const refused = hashForJoin([ADA]);
    expect(refused.ok).toBe(false);
    expect(refused.reason).toMatch(/at least two/);
    // …and the parser will not open one either, so a hand-edited link cannot
    // reach a half-built session.
    expect(parseToolkitHash(`#j=${ADA}`).kind).toBe("unknown");
  });

  it("loads no notebook, because a session does not carry one", () => {
    // Both sides arrive at the same recipe text independently — that is what
    // makes a shared run a reproducible build rather than a screen share. A
    // link that opened a session *and* replaced your notebook would be the
    // thing this design refuses, so `join` is returned before `r=` is read and
    // `loadFromHash` returns on it.
    const action = parseToolkitHash(`#j=${ADA},${GRACE}&r=input|gpg.encrypt`);
    expect(action.kind).toBe("join");
    expect(action.recipe).toBeUndefined();
    expect(HOOK).toMatch(/action\.kind === "join"[\s\S]{0,80}\)\s*\{\s*return;/);
  });

  it("takes a pasted link or a pasted list, and says which is which nowhere", () => {
    // A paste box that complained about the `https://` in front of a list would
    // be complaining that the reader pasted what they were sent.
    const url = `https://basilisk.pages.dev/toolkit#j=${ADA},${GRACE}`;
    expect(parseInviteAudience(url)).toEqual([ADA, GRACE].sort());
    expect(parseInviteAudience(`${GRACE}\n${ADA}`)).toEqual([ADA, GRACE].sort());
    expect(parseInviteAudience("nothing here")).toEqual([]);
  });

  it("states what it does not carry, as data rather than as copy", () => {
    // A security claim owned by a component is a claim no test can pin.
    expect(INVITE_OMITS.join(" ")).toMatch(/room id/);
    expect(INVITE_OMITS.join(" ")).toMatch(/token/);
    expect(INVITE_OMITS.join(" ")).toMatch(/private key/);
    expect(INVITE_CARRIES.join(" ")).toMatch(/public fingerprints/);
    expect(INVITE).toMatch(/INVITE_CARRIES\.map/);
    expect(INVITE).toMatch(/INVITE_OMITS\.map/);
  });
});

/* ────────────────────── something actually renders it ───────────────────── */

describe("the flow has a way in — three of them", () => {
  it("gives ShareSheet's Start button the handler it never had", () => {
    // The tier that needs the most explanation was the one with no entry point:
    // `onStartSession` is a prop `ShareSheet` has always accepted and the shell
    // never passed, so the button rendered and did nothing.
    expect(SHELL).toMatch(/onStartSession=\{\(\) => \{[\s\S]{0,120}setSheet\("session"\)/);
  });

  it("renders the sheet from the shell, at the top level", () => {
    expect(SHELL).toMatch(/<SessionSheet/);
    expect(SHELL).toMatch(/open=\{nb\.sheet === "session"\}/);
  });

  it("opens it from the Connections tab too", () => {
    expect(SHELL).toMatch(/onClick=\{\(\) => nb\.setSheet\("session"\)\}/);
  });

  it("opens it from an invite link, without loading anything", () => {
    expect(SHELL).toMatch(/action\.kind !== "join"/);
    expect(SHELL).toMatch(/role: "join", audience: action\.audience/);
  });
});

describe("the shell wires the flow to the real session", () => {
  it("starts one by writing cells and running them", () => {
    expect(SHELL).toMatch(/nb\.startSession\(\{/);
    expect(HOOK).toMatch(/const text = sessionRecipe\(draft\)/);
    // The run is deferred to an effect, because `runFrom` closes over the
    // chains: calling it in the same handler that appended the cells would run
    // the notebook as it was *before* the session cell existed.
    expect(HOOK).toMatch(/setAutoRunFrom\(/);
    expect(HOOK).toMatch(/if \(autoRunFrom == null\) return;[\s\S]{0,160}runFrom\(at\)/);
  });

  it("builds the invite from the audience, never from the roster", () => {
    // The roster holds who arrived; an invite is for the people who have not.
    expect(SHELL).toMatch(/hashForJoin\(sessionAudience\)/);
    expect(SHELL).toMatch(/nb\.quorumState\.audience/);
  });

  it("carries the audience on the exchange state so an invite can be built at all", () => {
    const OPS = read("../lib/toolkit/quorum-ops.js");
    expect(OPS).toMatch(/audience: \[\.\.\.audience\]/);
  });

  it("removes a peer by moving the room, and says so", () => {
    expect(SHELL).toMatch(/onRemove: \(fingerprint: string\) =>/);
    expect(HOOK).toMatch(/rotateQuorumRoom\(\[fingerprint\]\)/);
    // The note matters as much as the call: "Remove" alone reads as an eviction
    // the service performs, and no signalling service this app can reach offers
    // one.
    expect(LIVE).toMatch(/moves the room rather than evicting/);
  });
});

describe("the handoff arc finally has a surface", () => {
  it("renders the queue in the Connections tab", () => {
    expect(SHELL).toMatch(/<HandoffQueue/);
  });

  it("wires all four calls that had no caller", () => {
    // `offerCell`, `acceptHandoff`, `sendCellResult` and `skippedCells` shipped
    // in `useNotebook` and were reachable from nothing. `placed-run-arc.e2e.js`
    // drives the same four between two browsers; this is the product's own.
    for (const call of [
      "nb.offerCell(cell)",
      "nb.acceptHandoff(id)",
      "nb.sendCellResult(cell, label)",
      "nb.skippedCells()",
    ]) {
      expect(SHELL, call).toContain(call);
    }
  });

  it("reads the pending row before taking it, so the sender is not lost", () => {
    // `takeHandoff` removes the document, and the shell needs the sender
    // afterwards to know who is owed a signed answer.
    expect(SHELL).toMatch(
      /const row = pendingHandoffs\.find\(\(h\) => h\.id === id\);[\s\S]{0,80}nb\.acceptHandoff\(id\)/
    );
  });

  it("re-reads the queue on an event rather than mirroring it", () => {
    // A document may be taken exactly once, so a copy in React state would be a
    // second answer to "is this still pending".
    expect(HOOK).toMatch(/basilisk:quorum-handoffs/);
    expect(SHELL).toMatch(/void nb\.handoffTick;/);
  });

  it("keeps the three waits apart", () => {
    for (const attr of ["data-handoff-outgoing", "data-handoff-pending", "data-handoff-owed"]) {
      expect(QUEUE, attr).toContain(attr);
    }
    // And the rule the middle list exists to state.
    expect(QUEUE).toMatch(/registers nothing|Accepting is what/);
  });

  it("says a reload drops what you owed, and how to get it back", () => {
    // The third list is shell state built at the accept press, so a reload ends
    // it and nothing restores it. That is deliberate: persisting it would put a
    // record of what crossed in storage the exchange is built to do without.
    // What the panel owes the reader is therefore the recovery, not the row —
    // `offerCell` leaves the cell in the sender's skipped list, so their press
    // survives and asking them to repeat it is a complete fix.
    expect(QUEUE).toContain("data-handoff-reload");
    expect(QUEUE).toMatch(/nothing wrote down what you took/);
    expect(QUEUE).toMatch(/ask them to hand it over again/);
  });

  it("leaves the accepted cell in the sender's list, which is what makes that true", () => {
    // The sentence above is only honest while `offerCell` is non-destructive.
    // If sending ever consumed the skipped entry, the recovery it promises
    // would stop existing and the copy would have to change with it.
    expect(HOOK).toMatch(
      /const skipped = skippedRef\.current\.find\(\(sk\) => sk\.cell === cell\);/
    );
    expect(HOOK).not.toMatch(/skippedRef\.current\s*=\s*skippedRef\.current\.filter/);
  });
});

describe("the session's window is a window, and not a fourth Share row", () => {
  it("is a Sheet", () => {
    expect(SHEET).toMatch(/<Sheet open=\{open\}/);
    expect(SHEET).toMatch(/side="right"/);
  });

  it("shows the naming half only while there is nothing to watch", () => {
    expect(SHEET).toMatch(/\{live \? <SessionLive \{\.\.\.live\} \/> : <SessionStart \{\.\.\.start\} \/>\}/);
  });

  it("says the notebook does not cross", () => {
    expect(SHEET).toMatch(/never crosses/);
  });
});
