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
  attestationReadout,
  attestationVerdict,
  confirmationReadout,
  parseInviteAudience,
  pasteReadout,
  rosterCounts,
  sessionReadout,
  sessionRecipe,
  sessionStage,
  startIssues,
  sessionKeyChoices,
} from "../lib/toolkit/session-flow.js";
import { buildAttestation, manifestAttestedBy } from "../lib/toolkit/attest.js";
import { buildRunManifest } from "../lib/toolkit/manifest.js";
/**
 * `keyOwesPassphrase` moved to `key-power.js` — it is the fact that separates
 * `loaded` from `ready`, so it belongs to the vocabulary rather than to the
 * session's refusals, and the layering has to run that way round for
 * `startIssues` to be able to ask what a key can do. The assertions below are
 * unchanged; only where the function is imported from is.
 */
import { keyOwesPassphrase } from "../lib/toolkit/key-power.js";
import { hashForJoin, parseToolkitHash } from "../lib/toolkit/fragment.js";
import { formatFingerprint } from "../lib/utils.js";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { STEPS } from "../lib/toolkit/registry.js";
import { planRun } from "../lib/toolkit/plan.js";
import { deriveRoomId } from "../lib/notebook/room.js";
import { roomRoster } from "../lib/notebook/roster.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const HOOK = read("../toolkit/useNotebook.ts");
const SHEET = read("../toolkit/widgets/SessionSheet.tsx");
const LIVE = read("../toolkit/widgets/SessionLive.tsx");
const START = read("../toolkit/widgets/SessionStart.tsx");
const INVITE = read("../toolkit/widgets/InviteCard.tsx");
const QUEUE = read("../toolkit/widgets/HandoffQueue.tsx");
const SHARE = read("../toolkit/widgets/ShareSheet.tsx");

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
  it("explains a silent room by nobody being in it", () => {
    // This assertion used to be `/published once|keeps no history/` with a
    // remedy of `/start this again/`, and both are now false. The invite is
    // published again for any member who joins later and announces itself
    // (`NotebookSession._onKnock`), so a late arrival is no longer a cause of
    // silence and restarting the creator no longer fixes anything — it was only
    // ever a way to re-publish while the other side happened to be listening.
    //
    // Pinned tighter rather than looser: an empty room now has exactly two
    // causes a reader can act on, and the copy must name them instead of
    // teaching a ritual.
    const read = sessionReadout({ phase: "waiting", role: "creator", peers: [] });
    expect(read.tone).toBe("warn");
    expect(read.why).toMatch(/published again for anyone who joins later/);
    expect(read.why).toMatch(/derives a different room/);
    expect(read.next).toMatch(/Restarting this side changes nothing/);
  });

  it("inverts that advice for the joiner", () => {
    const joiner = sessionReadout({ phase: "waiting", role: "joiner", peers: [] });
    expect(joiner.headline).toBe("Waiting for the invite");
    // Was `/start the session again/` — the joiner used to be told to ask the
    // creator to restart. It announces itself now, so the only thing left that
    // it can act on is whether the two audiences agree.
    expect(joiner.why).toMatch(/whether they started before you or after/);
    expect(joiner.next).toMatch(/nothing to restart on this side/);
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

  it("holds the same rule in the widgets, not only in the module", () => {
    // The guard above enumerates every sentence `session-flow.js` can produce
    // and was taken to mean the rule was kept. It was not: `ShareSheet` told
    // the reader to match a short code against their peer, in a warning and
    // again in a doc comment, and neither is a string this module emits. A rule
    // asserted over one module is a rule that holds in one module.
    //
    // Source text rather than rendered output, because these are TSX and the
    // node suite has no renderer — which also means prose about the absence has
    // to avoid the ask phrasing itself. That is the right constraint: a comment
    // is read by the next person to touch the file, and this is precisely the
    // sentence that must not survive there either.
    for (const [name, src] of Object.entries({ SHARE, LIVE, START, SHEET, SHELL, QUEUE })) {
      expect(src, name).not.toMatch(
        /compare (?:these|the|this|that|it|them|codes|words|numbers)/i
      );
      expect(src, name).not.toMatch(/aloud|read it back|say the words/i);
      expect(src, name).not.toMatch(/safety number|authentication string|check the code/i);
    }
    // Not vacuous — the surface that carried the claim still discusses
    // confirmation, so a passing grep means the wording changed rather than the
    // subject disappearing.
    expect(SHARE).toMatch(/unconfirmed/);
    expect(SHARE).toMatch(/nothing for you to compare/);
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

  it("counts an audience by identities, not by entries", () => {
    // Reported the other way round — as a session that waits forever for a
    // peer who is structurally excluded, because a room whose only distinct
    // fingerprint is yours has a roster of nobody. It cannot get that far:
    // `canonicalAudience` dedupes, so naming one identity twice is one
    // identity here, in `execQuorumOpen`'s `to=`, and again in
    // `requireSelfInAudience` — three refusals before a room is derived, and
    // this is the one a reader can still act on.
    const issues = startIssues({ audience: [ADA, ADA], keyFingerprint: ADA });
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatch(/at least two people/);
  });

  it("refuses a second exchange, as the transport does", () => {
    const issues = startIssues({ audience: [ADA, GRACE], keyFingerprint: ADA, live: true });
    expect(issues[0]).toMatch(/already open/);
  });

  it("makes the two roles a visible choice, and says what each one does", () => {
    // The roles stay a visible choice — one end publishes the introduction and
    // the other verifies it, and two browsers that pick the same role are a room
    // where nobody is ever introduced. Collapsing them into one "Connect" would
    // make that look like a network problem.
    //
    // What is gone is the *ordering*. This used to pin `/relay keeps no
    // history/` and `/let them press Join first/`, which asked two people to
    // coordinate the order they pressed buttons in and left them with silence
    // when they failed. A joiner announces itself now and the creator
    // republishes for it, so the copy has to say the order does not decide it —
    // that is pinned below, so the old instruction cannot come back.
    expect(START).toMatch(/I am starting it/);
    expect(START).toMatch(/I was invited/);
    expect(START).toMatch(/the order the two of you press in does not decide whether you meet/);
    expect(START).toMatch(/Arriving late costs nothing/);
    expect(START).not.toMatch(/press Join first/);
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
    //
    // Two cells, read as cells rather than as lines: each now carries a `@peer`
    // header of its own (see below), so the first line of the text is a header
    // and not the op. Splitting on the blank line is what "its own cell" means
    // anyway — the line arithmetic was standing in for it.
    const text = sessionRecipe({ audience: [ADA, GRACE], keyFingerprint: ADA });
    const cells = text.split("\n\n");
    expect(cells).toHaveLength(2);
    expect(cells[0].split("\n").at(-1).startsWith("agent.unlock")).toBe(true);
    expect(cells[1].split("\n").at(-1).startsWith("quorum.")).toBe(true);
  });

  it("places both cells on the person opening the session", () => {
    // The blocker `placed-journey.e2e.js` walked into: these two cells travel
    // inside the notebook `shareNotebook` sends, so a peer who adopted one and
    // pressed Run stopped at `agent.unlock <the sender's fingerprint>` with
    // "Key not found in vault" — asked to open a key that is not theirs and
    // never will be. Unheaded, they are `no-private-input` cells that every
    // participant runs; headed, the gate that already declines a peer's cells
    // declines these.
    //
    // Asked of `roomRoster` rather than written down here: what the room calls
    // a member is the room's answer, and a test that spelled it itself would
    // pass on the day the two stopped agreeing. It is the key now — the roster
    // is identity-mapped — and that is asserted rather than assumed, because it
    // is the whole of what replaced the positional label.
    const { me } = roomRoster([ADA, GRACE], [], ADA);
    expect(me, "the room could not name a key in its own audience").toBe(ADA);
    const text = sessionRecipe({ audience: [GRACE, ADA], keyFingerprint: ADA });
    for (const cell of text.split("\n\n")) {
      expect(cell.split("\n")[0]).toBe(`@${me}`);
    }
    // Not `publish`. `$me` is an unlocked private key, and a header that let it
    // out of this machine would be the one thing placement exists to prevent —
    // `planRun` refuses `publish-secret` for it, which is a refusal this must
    // never have to reach.
    expect(text).not.toContain("publish");

    // And it is the *reader's* label, not a fixed one: the other member of the
    // same room writes their own.
    expect(
      sessionRecipe({ audience: [ADA, GRACE], keyFingerprint: GRACE, role: "join" }).split("\n")[0]
    ).toBe(`@${roomRoster([ADA, GRACE], [], GRACE).me}`);
  });

  it("makes the session cells run on one machine and no other", () => {
    // The property the header exists for, asserted through `planRun` rather
    // than by reading the text: the gate acts on `mine`, so a header that
    // parsed and planned as everybody's would be a header that changed nothing.
    const { roster } = roomRoster([ADA, GRACE], []);
    const source = sessionRecipe({ audience: [ADA, GRACE], keyFingerprint: ADA });
    const compiled = compileRecipe(source);
    expect(compiled.validation.errors).toEqual([]);

    const mine = planRun(compiled, { me: ADA, roster });
    expect(mine.ok, JSON.stringify(mine.refusals)).toBe(true);
    expect(mine.cells.map((c) => c.mine)).toEqual([true, true]);
    // The ask this header answers, gone because it is answered.
    expect(mine.asks.map((a) => a.reason)).not.toContain("vault-locality");

    const theirs = planRun(compiled, { me: GRACE, roster });
    expect(theirs.ok, JSON.stringify(theirs.refusals)).toBe(true);
    expect(theirs.cells.map((c) => c.mine)).toEqual([false, false]);

    // Not vacuous: without the header the same two cells are everybody's, which
    // is what put "Key not found in vault" in front of the peer who adopted it.
    const bare = planRun(
      compileRecipe(`agent.unlock ${ADA} | out $me\n\nquorum.offer to="${ADA},${GRACE}" key=$me | out $session`),
      { me: GRACE, roster }
    );
    expect(bare.cells.map((c) => c.mine)).toEqual([true, true]);
  });

  it("writes cells the notebook can still read back", () => {
    // The shipped blocker, and the reason it was a blocker: `startSession`
    // appends these cells and the notebook's `source` is `serializeRecipe` of
    // what it holds. The audience is comma-joined, `serializeStep` did not
    // quote a comma, and `to=` is positional — so the source came back as
    // `quorum.offer 9F2A…,D772… key=$me` and the whole notebook stopped
    // compiling with `Unexpected "," · Unexpected "<next fingerprint>"`. Every
    // session did this; the run only surfaced it once it got far enough to
    // matter.
    //
    // Compiling `sessionRecipe`'s own text was not enough to catch it — that
    // always passed. The property is the *round trip*, because the text the
    // user ends up holding is the serialized form, not the generated one.
    for (const role of ["offer", "join"]) {
      for (const audience of [[ADA, GRACE], [ADA, GRACE, LIN]]) {
        const first = compileRecipe(sessionRecipe({ audience, keyFingerprint: ADA, role }));
        expect(first.validation.errors, `${role} ${audience.length}`).toEqual([]);
        const source = serializeRecipe({ chains: first.ast.chains });
        const second = compileRecipe(source);
        expect(
          second.validation.errors.map((e) => e.message),
          `${role} with ${audience.length} members serialized to:\n${source}`
        ).toEqual([]);
        // The audience has to survive as itself, not merely parse.
        const quorumStep = second.ast.chains
          .flatMap((c) => c.steps || [])
          .find((s) => String(s.name).startsWith("quorum."));
        expect(String(quorumStep?.params?.to || "").split(",").sort()).toEqual(
          [...audience].sort()
        );
      }
    }
  });

  it("is not covered by the documented-example sweep, which is why this exists", () => {
    // `recipe-roundtrip.test.js` sweeps every registry `Example:` that compiles
    // standalone. `quorum.offer`'s names `key=$me`, a slot an earlier cell
    // registers, so it is filtered out of that sweep — the one op whose example
    // carries a comma was the one the sweep could not see. Pinned so that
    // removing this test is a deliberate act rather than an assumption that the
    // sweep has it.
    const spec = STEPS.find((s) => s.name === "quorum.offer");
    expect(spec.doc).toMatch(/Example:/);
    expect(compileRecipe(/Example:\s*`([^`]+)`/.exec(spec.doc)[1]).validation.errors.length)
      .toBeGreaterThan(0);
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

  it("takes the form this product prints, which is the one it used to refuse", () => {
    // The reported bug. `formatFingerprint` groups hex into four-character
    // blocks, so My Keys, the Keyring and every roster row show `AABB CCDD …`
    // — and this parser wanted a contiguous run, which is a stricter alphabet
    // than `normalizeFingerprintInput` two calls later already accepted. Every
    // paste of a fingerprint the product itself displayed yielded zero, in
    // silence. Extraction now happens in `findFingerprints`, beside the
    // normaliser it has to agree with.
    expect(parseInviteAudience(formatFingerprint(ADA))).toEqual([ADA]);
    expect(
      parseInviteAudience(`${formatFingerprint(GRACE)}\n${formatFingerprint(ADA)}`)
    ).toEqual([ADA, GRACE].sort());
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

/* ─────────────────────── what a paste says it did ───────────────────────── */

describe("a paste says what it found, in four distinguishable states", () => {
  it("names how many an invite carries, and settles the role", () => {
    // A link says something a list cannot: whoever sent it is the end that
    // publishes. Leaving the role as a toggle beside that is leaving the one
    // decision that decides whether anybody meets at all to a guess.
    const read = pasteReadout(
      `https://basilisk.pages.dev/toolkit#j=${ADA},${GRACE},${LIN}`,
      { audience: [ADA] }
    );
    expect(read.kind).toBe("invite");
    expect(read.role).toBe("join");
    expect(read.sentence).toMatch(/names 3 people/);
    expect(read.sentence).toMatch(/joining/);
    expect(read.audience).toEqual([ADA, GRACE, LIN].sort());
  });

  it("counts what was added apart from what was already there", () => {
    const read = pasteReadout(`${formatFingerprint(ADA)}\n${GRACE}\n${LIN}`, {
      audience: [ADA],
    });
    expect(read.kind).toBe("fingerprints");
    expect(read.added.sort()).toEqual([GRACE, LIN].sort());
    expect(read.already).toEqual([ADA]);
    expect(read.sentence).toBe("Added 2. One was already in the room.");
    // The role is not this paste's to settle — a bare list says nothing about
    // which end you are.
    expect(read.role).toBeNull();
  });

  it("says so when a paste added nobody, rather than looking like a no-op", () => {
    const read = pasteReadout(GRACE, { audience: [ADA, GRACE] });
    expect(read.kind).toBe("fingerprints");
    expect(read.added).toEqual([]);
    expect(read.sentence).toMatch(/^Nothing new\./);
    expect(read.audience).toEqual([ADA, GRACE].sort());
  });

  it("tells a short key id apart from nothing at all", () => {
    // 8, 16 and 32 are the lengths `SEARCH_HEX_LENGTHS` accepts for a lookup
    // and the search page already warns are collision-prone. A room is
    // `SHA-256(hostname | sorted fingerprints)`, so an id that can name more
    // than one key names no room — and this state used to read as nothing
    // having happened, which is the worst possible answer for somebody who
    // pasted a real identifier.
    for (const id of [ADA.slice(-8), ADA.slice(-16), ADA.slice(0, 32)]) {
      const read = pasteReadout(id, { audience: [ADA] });
      expect(read.kind, id).toBe("short-id");
      expect(read.sentence, id).toMatch(/more than one key/i);
      expect(read.sentence, id).toMatch(/room is derived from full fingerprints/);
      expect(read.audience, id).toEqual([ADA]);
    }
  });

  it("says what a fingerprint looks like when it found none", () => {
    const read = pasteReadout("see you at three", { audience: [] });
    expect(read.kind).toBe("nothing");
    expect(read.sentence).toMatch(/40 hex characters/);
    expect(read.sentence).toMatch(/64 for a v6/);
    // The two things a reader would otherwise have to guess: that the printed
    // form is acceptable, and that the one arrangement the extractor refuses is
    // two fingerprints with nothing between them.
    expect(read.sentence).toMatch(/spaces, colons and hyphens/);
    expect(read.sentence).toMatch(/own line|commas/);
  });

  it("is what the box renders, and the box commits on a press", () => {
    // Three halves of one report. The trigger was `onBlur`, which commits at a
    // moment the reader did not choose and — when it found nothing — left no
    // message and nothing to press again. Blur is no longer a commit, Add is,
    // and the sentence is rendered every time whatever it found.
    expect(START).toMatch(/import \{ pasteReadout \}/);
    expect(START).not.toMatch(/onBlur/);
    expect(START).toMatch(/const result = pasteReadout\(pasted, \{ audience \}\)/);
    expect(START).toMatch(/onClick=\{addPasted\}/);
    expect(START).toMatch(/aria-live="polite"/);
    expect(START).toMatch(/read\?\.sentence/);
  });

  it("hands the shell the reading rather than the text", () => {
    // Parsing the paste a second time in the shell would be two answers to
    // "who did that add", one of them on screen and one of them in the room.
    expect(SHELL).toMatch(/onPaste: \(result\) =>/);
    // The readout's audience still goes straight in — through
    // `setDraftAudience`, which is the one door every audience change takes so
    // that a paste renumbering the room carries the notebook's placements with
    // it. A paste that set `sessionDraft.audience` directly would be the drift
    // `peer-relabel.js` exists to refuse, arriving through the box.
    expect(SHELL).toMatch(/setDraftAudience\(result\.audience\)/);
    // Only a link settles which end you are; a bare list leaves it alone.
    expect(SHELL).toMatch(/role: result\.role \|\| d\.role/);
    expect(SHELL).not.toMatch(/parseInviteAudience/);
  });

  it("keeps all four apart, which is the whole point of having four", () => {
    const kinds = [
      pasteReadout(`#j=${ADA},${GRACE}`, {}).kind,
      pasteReadout(formatFingerprint(ADA), {}).kind,
      pasteReadout("DEADBEEF", {}).kind,
      pasteReadout("hello", {}).kind,
    ];
    expect(new Set(kinds).size).toBe(4);
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
    expect(SHELL).toMatch(/role: "join"/);
    // The audience the link carried, through the same door as every other
    // audience change. An invite is a room arriving from outside, and a
    // notebook may already be placed against a different one — via a ref
    // because this listener is mounted once and must not re-subscribe.
    expect(SHELL).toMatch(/draftAudienceRef\.current\(action\.audience\)/);
  });
});

describe("naming a room is a picker, and the picker was already built", () => {
  it("wires the search that existed and this panel never reached", () => {
    // `recipient-picker.js` has exported `searchRecipients` and
    // `listTrustedRecipientSuggestions` since the encrypt side was written, and
    // `RecipientBinderHost` already hosts them for recipients. The session
    // panel used neither: its only suggestion source was `nb.vaultKeys` —
    // this browser's *own* keys, the one group that is mostly not your peers,
    // and the one that is already in the room the moment a key is chosen.
    expect(SHELL).toMatch(/listTrustedRecipientSuggestions,?\n?\s*searchRecipients/);
    expect(SHELL).toMatch(/trusted: trustedPeers/);
    expect(SHELL).toMatch(/onSearch: async \(query: string\) =>/);
    expect(SHELL).toMatch(/await searchRecipients\(query\)/);
    expect(SHELL).not.toMatch(/suggestions: sessionKeys\.map/);
  });

  it("keeps the widget prop-driven, which is the design surface's own rule", () => {
    // `ds-entry.ts` states that every widget on the surface takes plain props
    // and reads no store. A component that opened IndexedDB and searched a
    // keyserver on mount would make that sentence false for the sync *and* for
    // the next person who reads it.
    expect(START).not.toMatch(/recipient-picker/);
    expect(START).toMatch(/onSearch\?: \(query: string\) => Promise<RecipientChoice\[\]>/);
    expect(START).toMatch(/trusted\?: RecipientChoice\[\]/);
  });

  it("makes the pick the add — one press, no second confirm", () => {
    expect(START).toMatch(/onClick=\{\(\) => add\(t\.fingerprint\)\}/);
    // The hit row became its own component so `useRefusal` is called once
    // per row rather than conditionally inside the map, and the press now
    // goes through `refusal.guard` so an already-added key refuses instead
    // of silently doing nothing. Still one press, still no second confirm.
    expect(START).toMatch(/onClick=\{refusal\.guard\(\(\) => onAdd\(hit\.fingerprint\)\)\}/);
    // The whole fingerprint, never the short form. `shortFpr` is a label here
    // and a truncated identity is what caused a live bug one layer down.
    expect(START).toMatch(/onAudience\(\[\.\.\.audience, clean\]\)/);
  });

  it("sends every door onto the room through one function", () => {
    // The audience is sorted, so any change to it can renumber every `@peerN`
    // in the notebook. `setDraftAudience` is what carries the placements over
    // that change; a control that set `sessionDraft.audience` itself would be
    // the silent drift arriving through whichever door was added last, which is
    // exactly how a guard with four callers loses its fifth.
    const doors = {
      "the picker (and the fingerprint menu behind it)": /onAudience: setDraftAudience/,
      "the paste box": /setDraftAudience\(result\.audience\)/,
      "choosing your own key": /setDraftAudience\(\[\.\.\.sessionDraft\.audience, fpr\]\)/,
      "an invite link": /draftAudienceRef\.current\(action\.audience\)/,
    };
    for (const [door, pattern] of Object.entries(doors)) {
      expect(SHELL, door).toMatch(pattern);
    }
    // And nothing sets the draft's audience behind its back: exactly one
    // `setSessionDraft` updater writes `audience`, and it is the one inside
    // `setDraftAudience`, immediately above the loop that carries the
    // placements. A second would be a door that skipped the relabel.
    const writes = SHELL.match(/setSessionDraft\(\(d\) => \(\{[^}]*audience:/g) || [];
    expect(writes.length, "only setDraftAudience may write the audience").toBe(1);
    expect(SHELL).toMatch(
      /setSessionDraft\(\(d\) => \(\{ \.\.\.d, audience: next \}\)\);\s*for \(const edit of edits\)/
    );
  });

  it("never opens on a bare hex prompt", () => {
    // The empty state, in the order the reader can act on: your own key (which
    // the shell adds the moment it is chosen), the peers you have met, a
    // search, and only then the paste box for somebody who was sent something.
    expect(START).toMatch(/Choosing the key you are joining as puts you in the/);
    const order = ["data-session-trusted", "data-session-search", "data-session-paste"];
    const at = order.map((attr) => START.indexOf(attr));
    expect(at.every((i) => i > 0), order.join(" · ")).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
    // And the key choice really is what puts you in the room, so that sentence
    // is not a promise the shell fails to keep. It goes through
    // `setDraftAudience` like every other door: your own key is usually the
    // *lowest*-numbered member and arrives after the person you are meeting, so
    // this is the likeliest renumbering in the product.
    expect(SHELL).toMatch(
      /if \(fpr && !sessionDraft\.audience\.includes\(fpr\)\) \{\s*setDraftAudience\(\[\.\.\.sessionDraft\.audience, fpr\]\)/
    );
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

/* ─────────────────────── attestation, end to end ────────────────────────── */

const ATTEST_ROSTER = { [ADA]: ADA, [GRACE]: GRACE };

/** The manifest two peers of this room would each derive for themselves. */
async function aManifest(source = "bytes deadbeef | out $a") {
  return buildRunManifest({
    title: "notebook",
    recipeSource: source,
    cells: [{ index: 0, recipe: source }],
    peers: ATTEST_ROSTER,
  });
}

describe("attested is a second verdict, and not confirmation", () => {
  it("says nothing at all while there is no manifest to have been seen", () => {
    // "Nobody has been asked" is not "they declined", and a chip that could not
    // tell them apart would report a refusal that never happened.
    expect(attestationVerdict({ attested: [] }, "")).toBe(null);
    expect(attestationReadout(null)).toBe(null);
    expect(attestationReadout({ digest: "" })).toBe(null);
  });

  it("marks a peer against this browser's digest and no other", async () => {
    const manifest = await aManifest();
    const mine = await buildAttestation({ manifest });
    const theirs = await buildAttestation({ manifestSha: "b".repeat(64) });

    const yes = attestationVerdict({ attested: [mine] }, mine.manifest);
    expect(yes.verdict).toBe("attested");
    expect(yes.tone).toBe("brand");
    // The claim is bounded in the badge's own sentence: seen, not timed, and
    // not agreed to.
    expect(yes.why).toMatch(/not when, and not that they will run it/);

    // A peer who signed over a *different* notebook reads as not this one,
    // because that is what it is — this is the drift the badge exists to show.
    const drift = attestationVerdict({ attested: [theirs] }, mine.manifest);
    expect(drift.verdict).toBe("not attested");
    expect(drift.why).toMatch(/the notebook they saw is not the notebook here/);

    const never = attestationVerdict({ attested: [] }, mine.manifest);
    expect(never.why).toMatch(/attesting is theirs to press/);
  });

  it("reports coverage in manifestAttestedBy's own words, caveat included", async () => {
    const manifest = await aManifest();
    const attestation = await buildAttestation({ manifest });

    const short = attestationReadout(
      await manifestAttestedBy(manifest, [{ by: ADA, attestation }])
    );
    expect(short.headline).toMatch(/manifest not attested/);
    expect(short.missing).toEqual([GRACE]);
    expect(short.total).toBe(2);
    expect(short.why).toMatch(/1 of 2 in this notebook have signed nothing/);

    const whole = attestationReadout(
      await manifestAttestedBy(manifest, [
        { by: ADA, attestation },
        { by: GRACE, attestation },
      ])
    );
    expect(whole.headline).toMatch(/manifest attested — 2 attesters/);
    expect(whole.missing).toEqual([]);
    expect(whole.tone).toBe("brand");
    // The caveat is carried out of the result rather than retyped, and it is
    // not optional: a coverage badge without it is the badge overclaiming.
    for (const r of [short, whole]) {
      expect(r.why).toMatch(/never evidence of when/);
      expect(r.why).toMatch(/mutual among the participants/);
    }
  });

  it("says coverage is vacuous rather than drawing a fraction of nobody", async () => {
    // A manifest that names no peers expects nobody, so `ok` can be true with
    // nothing established. `manifestAttestedBy` says so in its second caveat,
    // and a readout that printed only the first would let a vacuous true reach
    // the screen as agreement — with "0/0 attested" beside it.
    const manifest = await buildRunManifest({
      recipeSource: "bytes deadbeef | out $a",
      cells: [{ index: 0, recipe: "bytes deadbeef | out $a" }],
      peers: {},
    });
    const r = attestationReadout(await manifestAttestedBy(manifest, []));
    expect(r.total).toBe(0);
    expect(r.why).toMatch(/coverage is vacuous/);
    // And the widget draws no fraction when there is nothing to divide by.
    expect(LIVE).toMatch(/\{attested\.total \? \(/);
  });

  it("carries an unattributed attestation into the sentence, not just the log", async () => {
    const manifest = await aManifest();
    const attestation = await buildAttestation({ manifest });
    const r = attestationReadout(
      await manifestAttestedBy(manifest, [{ by: ADA, attestation }, { attestation }])
    );
    expect(r.why).toMatch(/1 attestation arrived with no attester/);
  });

  it("goes stale when the notebook moves, rather than staying green", async () => {
    // The digest covers the recipe source, so editing a cell after everyone
    // attested is a room that has attested to a notebook nobody is running.
    const before = await aManifest();
    const attestation = await buildAttestation({ manifest: before });
    const after = await aManifest("bytes deadbeef | encode hex | out $a");
    const r = attestationReadout(
      await manifestAttestedBy(after, [
        { by: ADA, attestation },
        { by: GRACE, attestation },
      ])
    );
    expect(r.headline).toMatch(/manifest not attested/);
    expect(r.missing).toEqual([ADA, GRACE].sort());
  });
});

describe("attestation reaches a person, by the only path there is", () => {
  it("carries it out of the session on the roster and nowhere else", () => {
    // Point 3 of the finding this change answers: `_onDocument` recorded the
    // attestation and emitted the roster, and the projection threw it away. The
    // row carries it now, and there is no second delivery path to disagree with
    // — the session has no `onAttestation` and no `attestersOf`.
    const SESSION = read("../lib/notebook/session.js");
    const ROSTER = read("../lib/notebook/roster.js");
    expect(ROSTER).toMatch(/attested: \[\.\.\.\(peer\?\.attested\?\.values\?\.\(\) \|\| \[\]\)\]/);
    expect(SESSION).not.toMatch(/this\.onAttestation/);
    expect(SESSION).not.toMatch(/attestersOf\(/);
  });

  it("reads it in the hook and renders it in the panel", () => {
    // The chain, asserted at each joint, because this whole area was four
    // layers each assuming the next one was listening.
    expect(HOOK).toMatch(/manifestAttestedBy\(ctx\.manifest, entries\)/);
    expect(HOOK).toMatch(/labelForFingerprint\(roster, String\(row\.fingerprint/);
    expect(SHELL).toMatch(/attestation: nb\.attestation/);
    expect(LIVE).toMatch(/attestationReadout\(attestation\)/);
    expect(LIVE).toMatch(/attestationVerdict\(p, digest\)/);
    expect(LIVE).toContain("data-session-attestation");
  });

  it("sends only from a press, and refuses with a sentence rather than a boolean", () => {
    // `attest.js` refuses to hold a signer for the reason `receipt.js` does, so
    // an attestation minted by a run would be that module one layer out. The
    // press is the whole consent boundary.
    expect(HOOK).toMatch(/session\.publishAttestation\(signed\)/);
    expect(HOOK).toMatch(/signSessionDocument\(attestationToJson\(mine\)\)/);
    expect(SHELL).toMatch(/onAttest: \(\) => \{/);
    expect(SHELL).toMatch(/attestRefusal: nb\.quorumState\.connected/);
    // `disabledReason`, never `disabled` — the refusal and the reason are one
    // value, per `components/ui/refusal.tsx`.
    expect(LIVE).toMatch(/disabledReason=\{attestRefusal\}/);
    expect(LIVE).not.toMatch(/\bdisabled=/);
  });

  it("prints the digest whole, the way a fingerprint is printed whole", () => {
    // There is no press here to reveal the rest, and the digest is what the
    // signature is over — an elision would be a value a reader compares and
    // cannot check.
    expect(LIVE).toMatch(/\{digest\}/);
    expect(LIVE).not.toMatch(/digest\.slice|digest\.substring|…\{/);
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

  it("says what actually crosses, which changed under it", () => {
    // This assertion used to read `toMatch(/never crosses/)`, and it was true
    // when it was written: an offer was checked against the recipient's own
    // copy of the notebook, and the only way to have that copy was to be sent
    // an `#r=` link out of band and paste it. Then the notebook itself began
    // to travel, signed and adopted — and this test went on enforcing the
    // sentence the change had made false, on the one screen whose whole job is
    // to tell somebody what is about to leave their machine.
    //
    // So it is pinned by property now, not by phrase: the sheet has to name
    // the notebook as something that crosses, has to say the crossing is
    // signed, and must not be able to go back to claiming otherwise.
    expect(SHEET).toMatch(/notebook\s+crosses signed/);
    expect(SHEET).not.toMatch(/never crosses/);
    // The half that did not change, and is the reason the first half is safe
    // to say out loud: what crosses is a proposal, not a replacement.
    expect(SHEET).toMatch(/without their say-so/);
  });
});

describe("an empty vault is a different problem from an unmade choice", () => {
  it("does not tell someone with no keys to choose one", () => {
    // The reported bug: Start sat disabled and pressing it did nothing, while
    // the only stated reason was an instruction that cannot be followed when
    // there is nothing in the list to pick.
    const none = startIssues({ audience: [], keyFingerprint: "", keyCount: 0 });
    expect(none.join(" ")).toMatch(/no private key in this browser/i);
    expect(none.join(" ")).not.toMatch(/^Choose the key/m);
    // Names the store that can sign, and says why the other one cannot. The
    // two used to share the `/my-keys` heading and both said "keys"; sending
    // somebody there without distinguishing them is how this was reported a
    // second time, with three account keys on screen and a session insisting
    // there were none. The page split into Published and the Keys tray, so the
    // sentence names those — a refusal that points at a retired page names a
    // state the reader cannot get to.
    expect(none.join(" ")).toMatch(/Your browser vault/);
    expect(none.join(" ")).toMatch(/the ones on Published are public keys on your account and cannot sign/);
  });

  it("still says choose when there is something to choose", () => {
    const some = startIssues({ audience: [], keyFingerprint: "", keyCount: 3 });
    expect(some.join(" ")).toMatch(/Choose the key you are joining as/);
    expect(some.join(" ")).not.toMatch(/no private key in this browser/i);
  });

  it("says nothing about keys once one is picked, either way", () => {
    const fpr = "A".repeat(40);
    for (const keyCount of [0, 3]) {
      const picked = startIssues({ audience: [fpr], keyFingerprint: fpr, keyCount });
      expect(picked.join(" ")).not.toMatch(/no private key|Choose the key/i);
    }
  });

  it("does not say the vault is empty when it is full of keys that cannot sign", () => {
    // The correction that made `keyCount` count only choosable keys has a
    // failure mode of its own: a browser holding three ssh keys, or one expired
    // OpenPGP key, has `keyCount === 0` — and "No private key in this browser"
    // is then a refusal naming a state the reader is not in, said to somebody
    // looking straight at their keys.
    const nothingChoosable = startIssues({
      audience: [],
      keyFingerprint: "",
      keyCount: 0,
      heldCount: 3,
    });
    expect(nothingChoosable.join(" ")).toMatch(/None of the keys in this browser can open a session/);
    expect(nothingChoosable.join(" ")).not.toMatch(/No private key in this browser/);
    // …and it says why, because "cannot" with no reason is the word that ends
    // the question and leaves the reader where they were.
    expect(nothingChoosable.join(" ")).toMatch(/SSH or raw key/);
    expect(nothingChoosable.join(" ")).toMatch(/expired/);
  });

  it("still says the vault is empty when it is", () => {
    const empty = startIssues({ audience: [], keyFingerprint: "", keyCount: 0, heldCount: 0 });
    expect(empty.join(" ")).toMatch(/No private key in this browser/);
  });
});

describe("only a key that can sign is a key you can choose", () => {
  it("keeps pgp and drops the kinds that cannot sign an invite", () => {
    // The vault holds three kinds — `agent.save` stores openssh-key-v1 blocks
    // and bare JWKs beside PGP armor — and all three were offered. Picking one
    // produced a live CryptoKey from `agent.unlock` and then a failure in
    // `resolveGpgPrivateKey`, several steps after the choice was made.
    const rows = [
      { fingerprint: ADA, kind: "pgp" },
      { fingerprint: "SHA256:" + "b".repeat(43), kind: "ssh" },
      { fingerprint: "spki:SHA256:" + "c".repeat(43), kind: "raw" },
    ];
    expect(sessionKeyChoices(rows).map((k) => k.fingerprint)).toEqual([ADA]);
  });

  it("treats a record with no kind as pgp, which is what a legacy row is", () => {
    expect(sessionKeyChoices([{ fingerprint: ADA }])).toHaveLength(1);
  });

  it("drops an expired OpenPGP key, which failed at the same distance", () => {
    // `kind: "pgp"` and unusable: the vault stores no opinion about validity,
    // so an expired key unlocked without complaint and then failed at the
    // signature — the ssh case again, in a different word.
    const now = Date.parse("2026-08-12T12:00:00Z");
    const rows = [
      { fingerprint: ADA, kind: "pgp", expires: "2027-01-01T00:00:00Z" },
      { fingerprint: GRACE, kind: "pgp", expires: "2026-08-01T00:00:00Z" },
    ];
    expect(sessionKeyChoices(rows, now).map((k) => k.fingerprint)).toEqual([ADA]);
  });

  it("keeps a session-only row, whose expires is the session's clock", () => {
    // The five-minute agent TTL rides in the same field. Read as validity it
    // would delete the one key the reader just made by hand from their own
    // chooser, minutes after making it.
    const now = Date.parse("2026-08-12T12:00:00Z");
    const rows = [{ fingerprint: ADA, protection: "session", expires: now - 1000 }];
    expect(sessionKeyChoices(rows, now)).toHaveLength(1);
  });

  it("counts the same rows the picker offers", () => {
    // The count behind "there is nothing to choose" and the list you choose
    // from have to be the same derivation, or an ssh key makes "you have not
    // chosen yet" the answer for somebody with nothing to choose — the original
    // report, one layer down.
    expect(SHELL).toMatch(/sessionKeyChoices\(nb\.vaultKeys\)/);
    expect(SHELL).toMatch(/keyCount: sessionKeys\.length/);
    expect(SHELL).not.toMatch(/keyCount: nb\.vaultKeys\.length/);
  });
});

describe("an open vault envelope is not a key that can sign", () => {
  it("reads the observed armor before the stored intent", () => {
    // `vault.unlockKey` removes the vault's own wrapper and returns armor that
    // may still be S2K-locked. Where the observation disagrees with the stored
    // protection mode, the armor wins: it is what `decryptKey` will be handed.
    expect(keyOwesPassphrase({ protection: "passphrase", locked: false })).toBe(false);
    expect(keyOwesPassphrase({ protection: "device", locked: true })).toBe(true);
  });

  it("falls back to the protection mode for a key nothing has opened", () => {
    expect(keyOwesPassphrase({ protection: "passphrase" })).toBe(true);
    expect(keyOwesPassphrase({ protection: "device" })).toBe(false);
    expect(keyOwesPassphrase({ protection: "passkey" })).toBe(false);
  });

  it("answers undefined rather than guessing, and stays silent on it", () => {
    // A sentence about a passphrase that may not be owed is a refusal naming a
    // state the reader is not in, which is the whole defect being repaired.
    expect(keyOwesPassphrase({ protection: "session" })).toBeUndefined();
    expect(keyOwesPassphrase(null)).toBeUndefined();
    const quiet = startIssues({
      audience: [ADA, GRACE],
      keyFingerprint: ADA,
      keyCount: 1,
      key: { fingerprint: ADA, protection: "session" },
      passphraseBound: false,
    });
    expect(quiet).toEqual([]);
  });

  it("refuses before the press, and names the field that answers it", () => {
    // This is where the reported bug actually ended: Start was enabled, the run
    // wrote both cells, and the failure arrived inside `resolveGpgPrivateKey`
    // in OpenPGP's own words — the refusal furthest from the decision that
    // caused it, about the protection mode this app recommends.
    const issues = startIssues({
      audience: [ADA, GRACE],
      keyFingerprint: ADA,
      keyCount: 1,
      key: { fingerprint: ADA, protection: "passphrase" },
      passphraseBound: false,
    });
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatch(/passphrase-protected/);
    expect(issues[0]).toMatch(/Inputs → Key passphrase/);
  });

  it("clears once the passphrase is bound", () => {
    expect(
      startIssues({
        audience: [ADA, GRACE],
        keyFingerprint: ADA,
        keyCount: 1,
        key: { fingerprint: ADA, protection: "passphrase" },
        passphraseBound: true,
      })
    ).toEqual([]);
  });

  it("blocks a chosen key the picker would no longer offer", () => {
    // Removing a key from the list is not a refusal. The draft holds a
    // fingerprint while the list is re-derived every render, so a key that
    // expires with the sheet open leaves Start available with nothing behind
    // it — the same shape as the original report, arrived at from the other
    // side. The sentence is the tray row's, so both name one state.
    for (const key of [
      { fingerprint: ADA, kind: "ssh" },
      { fingerprint: ADA, kind: "pgp", expires: "2000-01-01T00:00:00Z" },
    ]) {
      const issues = startIssues({
        audience: [ADA, GRACE],
        keyFingerprint: ADA,
        keyCount: 1,
        key,
        passphraseBound: true,
      });
      expect(issues).toHaveLength(1);
      expect(issues[0]).toMatch(/cannot|expired/i);
    }
  });

  it("judges a chosen key only when the caller supplies the row", () => {
    // Every caller that knows nothing about the key passes no `key`, and
    // "absent" is not what that means — it means unasked. Inventing a blocker
    // for it would refuse every draft this function has ever been handed.
    expect(
      startIssues({ audience: [ADA, GRACE], keyFingerprint: ADA, keyCount: 1 })
    ).toEqual([]);
  });

  it("has a field to bind it in, which is the half that was missing", () => {
    // `input-needs.js` has derived `gpgPass` since it was written and
    // `agent.unlock` has always read `inputs.gpg.passphrase`. Nothing rendered
    // a field, so the need was underivable in practice: a reader with no
    // writer. Asserting the panel and the binding together, because either one
    // alone is the same dead end pointing the other way.
    expect(SHELL).toMatch(/notebookNeeds\.has\("gpgPass"\)/);
    expect(SHELL).toMatch(/nb\.setGpgPassphrase/);
    expect(HOOK).toMatch(/passphrase: gpgPassphrase/);
    // A secret in memory goes when Clear session goes.
    expect(HOOK).toMatch(/setGpgPassphrase\(""\)/);
  });
});
