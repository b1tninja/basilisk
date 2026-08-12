/**
 * The DKG has a face, and it does not claim more than it knows.
 *
 * `dkg.run` blocks its cell for up to two minutes and dispatched
 * `basilisk:dkg-progress` to nobody. The panel that would have drawn it sat in
 * the widget catalog describing itself as design-ahead of the op layer. Between
 * them was a data problem: `DkgProgress` reported three numbers, and
 * `DkgPanel`'s central claim is per-participant state on three axes never
 * merged — so the roster could not be drawn without inventing it.
 *
 * The numbers became names first (`dkg-run.test.js` covers that end), and this
 * file covers what the shell then does with them. Two properties, and the
 * second is the one worth having:
 *
 * - the panel is mounted, fed from the exchange's own roster rather than a
 *   second one, and the buttons it would draw are left unrendered because
 *   `dkg.run` has nothing for them to call;
 * - **it never says a share is checked before anything checked it.** A share
 *   that has *arrived* is not a share that *verifies* — `finalize` is what
 *   verifies, at the end — so `verified` is claimed only when the run
 *   completed, and `bad` only for the dealer the refusal named.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canFinalize, dkgPhase, roundProgress } from "../lib/quorum/dkg-session.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

/**
 * Source with comments removed. Prose *about* a button is not a button — the
 * panel argues at length for why there is no Exclude control, and a check that
 * matched the argument as well as the control would forbid explaining itself.
 */
const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const PANEL = read("../toolkit/widgets/DkgPanel.tsx");
const OPS = read("../lib/toolkit/dkg-ops.js");

describe("the panel is wired to the op that drives it", () => {
  it("listens to the event dkg.run actually dispatches", () => {
    // The name is the contract between two modules that share no import, so
    // both ends are read rather than assumed.
    expect(OPS).toMatch(/new CustomEvent\("basilisk:dkg-progress"/);
    expect(SHELL).toMatch(/addEventListener\("basilisk:dkg-progress"/);
    expect(SHELL).toMatch(/removeEventListener\("basilisk:dkg-progress"/);
  });

  it("renders DkgPanel from that state and from the exchange's own roster", () => {
    expect(SHELL).toMatch(/<DkgPanel/);
    expect(SHELL).toMatch(/dkgParticipants\(\s*nb\.quorumState\.peers/);
  });

  it("shows nothing at all until a run has spoken", () => {
    // A permanently-mounted "no DKG" card would be furniture. Absent, not empty.
    expect(SHELL).toMatch(/\{dkgProgress \? \(/);
  });

  it("passes no handlers, so no button renders", () => {
    // The three buttons describe a hand-cranked session; `dkg.run` deals every
    // round and finalizes itself. A rendered button with nothing to call is the
    // defect this repo keeps closing, so the panel is a progress view here.
    const mount = SHELL.slice(SHELL.indexOf("<DkgPanel"), SHELL.indexOf("</section>", SHELL.indexOf("<DkgPanel")));
    for (const handler of ["onStart", "onFinalize", "onRestart"]) {
      expect(mount, `${handler} would draw a button with nothing behind it`).not.toContain(
        handler
      );
    }
  });

  it("says in the panel itself that the buttons await a decision", () => {
    // So the next reader knows they are unrendered on purpose rather than
    // broken, and what would have to be true to render them.
    expect(PANEL).toMatch(/waiting on a decision, not broken/);
    expect(PANEL).toMatch(/no handlers/i);
  });

  it("keeps the eviction button out, and says why", () => {
    // `dkg-session.js`'s argument, which must survive into the surface: a
    // refusal is total, and from every other seat "X dealt badly" and "you are
    // claiming X dealt badly" are the same observation.
    expect(code(PANEL)).not.toMatch(/Exclude/);
    expect(code(SHELL)).not.toMatch(/Exclude/);
    // …and the argument for its absence is present, in the prose the code
    // strip above deliberately ignores.
    expect(PANEL).toMatch(/indistinguishable/);
  });
});

describe("what the shell is entitled to say about a participant", () => {
  /**
   * The shell's own derivation, re-implemented from the source it is pinned
   * against would be a second answer — so this asserts the rules it must obey
   * through `dkg-session.js`, which is the module that owns them.
   */
  const peer = (id, round) => ({ id, fingerprint: id, round, state: "connected", authenticated: true });
  const me = { id: "you", fingerprint: "ME", self: true, round: "verified", state: "connected", authenticated: true };

  it("counts only the others, so a run never looks further along than it is", () => {
    // The rule the derivation depends on: my own contribution is not progress.
    const mid = [me, peer("a", "commitments"), peer("b", "waiting")];
    expect(roundProgress(mid, "commitments")).toMatchObject({ have: 1, need: 2 });
    expect(roundProgress(mid, "verified")).toMatchObject({ have: 0, need: 2 });
  });

  it("will not finalize on shares that merely arrived", () => {
    // Which is why the shell may not draw `verified` mid-run: `share` means the
    // bytes are here, and nothing has checked them against the commitments.
    const arrived = [me, peer("a", "share"), peer("b", "share")];
    expect(canFinalize(arrived)).toBe(false);
    expect(dkgPhase({ participants: arrived, started: true })).toBe("collecting");

    const checked = [me, peer("a", "verified"), peer("b", "verified")];
    expect(canFinalize(checked)).toBe(true);
  });

  it("treats one bad dealer as the end of the whole run", () => {
    // Not a smaller quorum, not a partial key. The phase goes to `refused` on
    // the first bad share however healthy everyone else is.
    const refused = [me, peer("a", "verified"), peer("b", "bad")];
    expect(dkgPhase({ participants: refused, started: true })).toBe("refused");
    expect(canFinalize(refused)).toBe(false);
  });

  it("only claims verified where the shell has a completed run to point at", () => {
    // Pinned as source because it is the one place inventing state would be
    // invisible: the derivation reads `phase === "complete"`, not a count.
    expect(SHELL).toMatch(/progress\.phase === "complete"\s*\?\s*"verified"/);
    expect(SHELL).toMatch(/progress\.phase === "refused" && progress\.dealer === fpr/);
  });
});
