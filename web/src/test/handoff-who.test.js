/**
 * Which peer this browser is — resolved the way the shell resolves it.
 *
 * This is the question every placed run turns on, and the product answered it
 * wrongly from the day it was asked. `useNotebook.handoffWho` searched
 * `quorumState.peers` for its own fingerprint, and those rows are the audience
 * **minus self** — `NotebookSession` skips `fpr === this.myFpr` when it builds
 * the map, deliberately, because a session is never its own peer. The search
 * could not match, so `me` was `""` in every browser, forever.
 *
 * What that cost is larger than one empty string, and the cost is what this
 * file pins:
 *
 *  - every cell planned as somebody else's (`mine: false`), including the ones
 *    the author placed on themselves;
 *  - `planRun` refusing this browser's own key as a peer "no one in this room
 *    answers to", so `plan.ok` was false and `summarizePlan` said the run was
 *    refused;
 *  - `runFrom` therefore building no placement gate at all — its condition is
 *    `me &&` — so a placed notebook ran *every* cell locally, nothing was ever
 *    skipped, and `offerCell` answered "That cell was not left to anybody";
 *  - `waits` empty, because the wait loop only records for `cell.mine`;
 *  - the two browsers digesting **different** `peersSha` into their manifests,
 *    each roster being the other peer and no more;
 *  - and, at the end of all that, `acceptHandoffOffer` refusing `not-mine` with
 *    "this plan does not know which peer this is" — the only branch of it a
 *    real user could reach.
 *
 * `placed-run-arc.e2e.js` was green throughout, because it supplied `me` and a
 * whole-room roster itself instead of asking the product for either. So this
 * file drives the product's own derivation — `roomRoster`, the one function the
 * shell now calls — from the three things the exchange actually hands the shell:
 * the audience, the peer rows (self absent, as they always are), and this
 * browser's fingerprint. The control below builds the same context with `me`
 * unresolved and requires the refusal, so the fix cannot be undone quietly in
 * either direction.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { projectRosterPeers, roomRoster } from "../lib/notebook/roster.js";
import { planRun } from "../lib/toolkit/plan.js";
import { compileRecipe, migrateRecipe } from "../lib/toolkit/recipe.js";
import { manifestDigest } from "../lib/toolkit/manifest.js";
import { handoffContext, offerForSkipped, reviewOffer } from "../lib/toolkit/handoff-shell.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";

const FPR_M = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_O = "91C7E6D5C4B3A29180716253443526170819AABB";
/**
 * Unsorted on purpose.
 *
 * It used to matter to the *answer*: a peer was a position in the canonical
 * audience, so a test passing the list in a different order was testing whether
 * both browsers sorted it the same way. It matters to nothing now, and staying
 * unsorted is the assertion — a derivation that quietly reacquired an ordering
 * dependence would still pass a sorted fixture.
 */
const AUDIENCE = [FPR_O, FPR_M];

/** A peer row's transport state, meshed and both-ways verified. */
const MET = { status: "connected", pgpVerified: true, kcVerified: true };

/**
 * What one browser's exchange holds: the audience, the rows for everybody
 * else, and its own fingerprint.
 *
 * The rows come from `projectRosterPeers` over a map built the way
 * `session.js` builds `this.peers` — every audience member except this one —
 * so the input to the derivation is the input the shell gets and not a
 * convenient literal.
 */
function exchange(selfFpr) {
  const peersMap = new Map(AUDIENCE.filter((f) => f !== selfFpr).map((f) => [f, { ...MET }]));
  const rows = projectRosterPeers(peersMap);
  return { rows, self: selfFpr, ...roomRoster(AUDIENCE, rows.map((r) => r.fingerprint), selfFpr) };
}

/**
 * mara seeds the room, okafor transforms it, mara reads the answer.
 *
 * Written against the keys the derivation hands out rather than against
 * `@mara`/`@okafor`, because that substitution is where the defect hid: a
 * notebook whose peers a test invents is a notebook whose `me` a test can
 * invent too. It reads more directly than it used to — the peers are the two
 * fingerprints at the top of this file, so a reader can see which machine each
 * cell belongs to without holding a numbering in their head, which is most of
 * the point of the change this file was rewritten for.
 */
const NOTEBOOK = `@${FPR_M} publish
bytes deadbeef | encode hex | out $seed

@${FPR_O} publish
in $seed | decode hex | encode base64 | out $b64

@${FPR_M}
in $b64 | decode base64 | encode hex | out $final
`;

/** Run the notebook under a plan, collecting what the gate declined. */
async function runPlaced(ctx) {
  const registry = createSlotRegistry();
  /** @type {import("../lib/toolkit/placement.js").SkippedCell[]} */
  const skipped = [];
  await runRecipe(compileRecipe(migrateRecipe(NOTEBOOK).recipe).ast, {}, {
    slotRegistry: registry,
    placement: { plan: ctx.plan, onSkip: (s) => skipped.push(s) },
  }).catch(() => {
    /* a placed run stops at the cell whose input lives elsewhere — by design */
  });
  return { registry, skipped };
}

describe("which peer this browser is", () => {
  it("is its own key, which the audience has to contain", () => {
    const mara = exchange(FPR_M);
    // The fact that made the old derivation impossible, stated rather than
    // implied: this browser is not among its own peer rows and never will be.
    expect(mara.rows.some((r) => r.fingerprint === FPR_M)).toBe(false);
    expect(mara.rows.map((r) => r.id)).toEqual([FPR_O]);
    // And it is still named, because the *audience* contains it — which is the
    // thing `roomRoster` reads and the peer rows are not.
    expect(mara.me).toBe(FPR_M);
    expect(mara.roster).toEqual({ [FPR_M]: FPR_M, [FPR_O]: FPR_O });
  });

  it("cannot disagree with what the panel draws", () => {
    // One derivation answers both questions, so there is no second one to
    // drift: every row's `id` is this roster's key for that fingerprint, and
    // `me` is a key of the same object.
    for (const self of AUDIENCE) {
      const { rows, roster, me } = exchange(self);
      for (const row of rows) expect(roster[row.id]).toBe(row.fingerprint);
      expect(roster[me]).toBe(self);
    }
  });

  it("gives both machines one roster and two different answers to `me`", () => {
    const mara = exchange(FPR_M);
    const okafor = exchange(FPR_O);
    expect(okafor.roster).toEqual(mara.roster);
    expect([mara.me, okafor.me]).toEqual([FPR_M, FPR_O]);
  });

  it("names nobody for a fingerprint the room was not derived from", () => {
    // A browser the audience does not contain is not in this room, and claiming
    // a place in it would place somebody else's cells here. This is the one
    // assertion that keeps `roomRoster` from collapsing into "return the
    // fingerprint you were given": the mapping is identity, and it is still a
    // *lookup*. `planRun` has a question for exactly this state (`who-am-i`);
    // the empty string is what leaves it standing.
    const stranger = "0000111122223333444455556666777788889999";
    expect(roomRoster(AUDIENCE, [FPR_M, FPR_O], stranger).me).toBe("");
    expect(roomRoster([], [], FPR_M).me).toBe("");
  });

  it("does not change under anybody when a peer is still on their way", () => {
    // The roster is the audience, not the arrivals, so it is the same map
    // before and after the second peer meshes — which is what lets the two
    // sides commit to one `peersSha`.
    const alone = roomRoster(AUDIENCE, [], FPR_M);
    expect(alone).toEqual(roomRoster(AUDIENCE, [FPR_O], FPR_M));
  });
});

describe("a cell placed on this browser's own key", () => {
  it("is this browser's to run", () => {
    const mara = exchange(FPR_M);
    const plan = planRun(compileRecipe(NOTEBOOK), { me: mara.me, roster: mara.roster });
    // No refusal: the header names a key this room contains, and it is ours.
    // The old resolution refused it here — "no one in this room answers to that
    // name" — about the browser doing the asking.
    expect(plan.ok, plan.refusals.map((r) => r.reason).join(", ")).toBe(true);
    expect(plan.me).toBe(FPR_M);
    expect(plan.cells.map((c) => c.mine)).toEqual([true, false, true]);
    // The mirror image on the other machine. The two plans have to agree about
    // cell 1 independently — an offer says nothing about who runs a cell.
    const okafor = exchange(FPR_O);
    const theirs = planRun(compileRecipe(NOTEBOOK), { me: okafor.me, roster: okafor.roster });
    expect(theirs.cells.map((c) => c.mine)).toEqual([false, true, false]);
    // And the plan can now say what this peer is waiting for, which the wait
    // loop records only for cells that are `mine`.
    expect(plan.waits).toEqual([
      { cell: 2, on: 1, peer: FPR_O, slot: "b64", reason: "published-slot" },
    ]);
  });

  it("asks nobody who this is", () => {
    const mara = exchange(FPR_M);
    const plan = planRun(compileRecipe(NOTEBOOK), { me: mara.me, roster: mara.roster });
    expect(plan.asks.map((a) => a.reason)).not.toContain("who-am-i");
  });

  it("is what `runFrom` requires before it builds a gate at all", () => {
    // `runFrom`'s condition, quoted: with no `me` there is no placement, so the
    // gate `placement.js` insists is different from a gate that admits
    // everything was simply never made, and a placed notebook ran every cell
    // here — including the cells belonging to the other machine.
    const mara = exchange(FPR_M);
    expect(Boolean(mara.me && Object.keys(mara.roster).length)).toBe(true);
  });
});

describe("the handoff the resolution gates", () => {
  it("carries a cell to the peer that owns it, and is accepted there", async () => {
    const mara = exchange(FPR_M);
    const okafor = exchange(FPR_O);
    const ctxM = await handoffContext({
      source: NOTEBOOK,
      me: mara.me,
      roster: mara.roster,
      title: "who",
    });
    const ctxO = await handoffContext({
      source: NOTEBOOK,
      me: okafor.me,
      roster: okafor.roster,
      title: "who",
    });

    // One manifest, reached separately. Both rosters are the whole room, so
    // `peersSha` is a digest of the same binding on both machines — with the
    // old resolution each side's roster was the *other* peer and nothing else,
    // and the two digests could not match.
    expect(await manifestDigest(ctxM.manifest)).toBe(await manifestDigest(ctxO.manifest));
    expect(ctxM.manifest.peers).toEqual([FPR_M, FPR_O].sort());

    // mara runs, and the gate declines the cell that is not hers.
    const { registry, skipped } = await runPlaced(ctxM);
    expect(skipped.map((s) => s.cell)).toEqual([1]);
    expect(skipped[0].waitingOn).toBe(FPR_O);

    const built = await offerForSkipped(ctxM, skipped[0], (l) =>
      registry.has(l) ? registry.resolve(l) : null
    );
    expect(built.ok).toBe(true);
    expect(built.peer).toBe(FPR_O);

    // okafor's own plan says cell 1 is his, so the offer is something he can
    // be asked about. `not-mine` is the branch this file exists to stay out of.
    const verdict = await reviewOffer(ctxO, built.json, () => false);
    expect(verdict.refusals.map((r) => r.reason)).not.toContain("not-mine");
    expect(verdict.ok).toBe(true);
    expect(verdict.bindings.map((b) => b.label)).toEqual(["seed"]);
  });

  it("refuses the same offer when nothing has said which peer this is", async () => {
    // The control, and the state the product shipped in. Everything else is
    // held equal — the same notebook, the same whole-room roster, the same
    // manifest — so the refusal is attributable to `me` and to nothing else.
    const mara = exchange(FPR_M);
    const okafor = exchange(FPR_O);
    const ctxM = await handoffContext({
      source: NOTEBOOK,
      me: mara.me,
      roster: mara.roster,
      title: "who",
    });
    const unresolved = await handoffContext({
      source: NOTEBOOK,
      me: "",
      roster: okafor.roster,
      title: "who",
    });
    const { registry, skipped } = await runPlaced(ctxM);
    const built = await offerForSkipped(ctxM, skipped[0], (l) =>
      registry.has(l) ? registry.resolve(l) : null
    );

    const verdict = await reviewOffer(unresolved, built.json, () => false);
    expect(verdict.ok).toBe(false);
    expect(verdict.refusals.map((r) => r.reason)).toContain("not-mine");
    expect(verdict.refusals.find((r) => r.reason === "not-mine").message).toContain(
      "this plan does not know which peer this is"
    );
  });

  it("plans nothing at all from a roster that is missing this browser", () => {
    // The other half of what the old shell handed the planner: `session.peers`
    // projected straight into `{label: fingerprint}`. Every cell is somebody
    // else's, this browser's own label is an unknown peer, and the plan is
    // refused — so the Connections tab's summary read "run refused at cell
    // (roster)" for a notebook that was perfectly well formed.
    const okafor = exchange(FPR_O);
    const peersOnly = Object.fromEntries(okafor.rows.map((r) => [r.id, r.fingerprint]));
    const plan = planRun(compileRecipe(NOTEBOOK), { me: "", roster: peersOnly });
    expect(plan.ok).toBe(false);
    expect(plan.refusals.map((r) => r.reason)).toContain("unknown-peer");
    expect(plan.cells.every((c) => !c.mine)).toBe(true);
    expect(plan.waits).toEqual([]);
    expect(plan.asks.map((a) => a.reason)).toContain("who-am-i");
  });
});

/**
 * The shell's own wiring, read as source.
 *
 * Vitest runs in `node` here and the shell is React, so the hook cannot be
 * called — which is precisely the gap `placed-run-arc.e2e.js` fell through by
 * computing `me` itself. What can be pinned is that the three surfaces which
 * need an answer take it from `roomRoster` and that none of them derives a
 * second one; `dkg-shell.test.js` and `pool-panel.test.js` pin their own
 * wiring the same way, for the same reason.
 */
describe("the shell asks the derivation and does not re-derive it", () => {
  const read = (rel) =>
    readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
  const HOOK = read("../toolkit/useNotebook.ts");
  const SHELL = read("../toolkit/ToolkitShell.tsx");

  it("resolves `me` in one place, from the exchange's own three facts", () => {
    expect(HOOK).toMatch(/import \{ roomRoster \} from "\.\.\/lib\/notebook\/roster\.js"/);
    expect(HOOK).toMatch(
      /handoffWho = useCallback\(\s*\(\) =>\s*roomRoster\(\s*quorumState\.audience[\s\S]{0,200}quorumState\.self/
    );
    // The search that could never match, gone rather than corrected: there is
    // no reading of `peers` that finds self in it.
    expect(HOOK).not.toMatch(/Object\.keys\(roster\)\.find/);
  });

  it("plans the Connections tab with the same answer the run uses", () => {
    expect(SHELL).toMatch(/nb\.handoffWho\(\)/);
    expect(SHELL).toMatch(/planRun\(compileRecipe\(nb\.source\), \{ roster, me \}\)/);
  });

  it("offers this browser's own label as somewhere a cell can go", () => {
    // `peerChoices` used to be built from the peer rows, so the one label a
    // user could never assign a cell to was their own. It is built from a
    // roster now, which contains it.
    expect(SHELL).toMatch(/const \{ roster, me \} = composeWho;/);
    expect(SHELL).toMatch(/\[\.\.\.new Set\(\[\.\.\.Object\.keys\(roster\)/);
  });

  it("offers those labels before anyone has joined, which is the point of them", () => {
    // `handoffWho` is `roomRoster` over `quorumState.audience`, and that list is
    // empty until Start is pressed — so a menu built from it alone was empty at
    // exactly the moment somebody was writing a ceremony to run later, and the
    // only way to place a cell was to type the grammar the menu exists to
    // spare them. The draft audience answers it before there is a session, and
    // it answers with `roomRoster`, so the labels a notebook is composed
    // against are the ones the room will hand out.
    expect(SHELL).toMatch(
      /sessionLive\s*\?\s*nb\.handoffWho\(\)\s*:\s*roomRoster\(sessionDraft\.audience, \[\], sessionDraft\.keyFingerprint\)/
    );
    // No second numbering rule in the shell. `peerLabels` is never imported
    // here — it is reached only through `roomRoster`, which both branches go
    // through — so the labels a cell is assigned to and the labels the room
    // hands out cannot be two derivations that agree today.
    expect(SHELL).not.toMatch(/import[\s\S]{0,80}peerLabels/);
  });
});
