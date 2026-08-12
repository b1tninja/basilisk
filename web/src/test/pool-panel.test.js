/**
 * The ceremony has a face, and it does not call a reveal checked.
 *
 * `entropy.pool` blocks its cell for up to two minutes across two rounds and
 * dispatched `basilisk:entropy-pool` to nobody. This is the surface, built the
 * way `DkgPanel`'s was: the exchange's own roster, plus one axis from the run,
 * and nothing claimed that nothing established.
 *
 * The state that matters is `revealed`. `openEntropyPool` verifies every reveal
 * against its commitment at the *end*, together — so a reveal that has arrived
 * is not one that opens anything. Drawing it as checked would be the same lie
 * as marking a DKG share verified on arrival, and it would be told at the exact
 * moment the ceremony's only defence is the check.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { entropyCommitment, openEntropyPool } from "../lib/toolkit/entropy-pool.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const PANEL = read("../toolkit/widgets/PoolPanel.tsx");
const OPS = read("../lib/toolkit/entropy-pool-ops.js");

describe("the panel is wired to the op that drives it", () => {
  it("listens to the event entropy.pool dispatches", () => {
    expect(OPS).toMatch(/new CustomEvent\("basilisk:entropy-pool"/);
    expect(SHELL).toMatch(/addEventListener\("basilisk:entropy-pool"/);
    expect(SHELL).toMatch(/removeEventListener\("basilisk:entropy-pool"/);
  });

  it("renders from that state and from the exchange's own roster", () => {
    expect(SHELL).toMatch(/<PoolPanel/);
    expect(SHELL).toMatch(/poolParticipants\(\s*nb\.quorumState\.peers/);
    expect(SHELL).toMatch(/\{poolProgress \? \(/);
  });

  it("passes no handlers, so no control renders", () => {
    // Sharper than the DKG's reason: the only control anyone could want —
    // "reveal now" — is an affordance for the one act the protocol forbids.
    const mount = SHELL.slice(SHELL.indexOf("<PoolPanel"), SHELL.indexOf("/>", SHELL.indexOf("<PoolPanel")));
    expect(mount).not.toMatch(/on[A-Z]/);
    expect(PANEL).not.toMatch(/<Button/);
  });

  it("clears with the exchange, because a pool describes one room", () => {
    expect(SHELL).toMatch(/setPoolProgress\(null\)/);
  });
});

describe("what the panel is entitled to say about a participant", () => {
  it("never labels an unchecked reveal as checked", () => {
    // The load-bearing assertion. Both halves: the word, and the absence of a
    // tick on it.
    expect(PANEL).toMatch(/revealed: "revealed, unchecked"/);
    expect(PANEL).toMatch(/verified: "checked"/);
    expect(PANEL).not.toMatch(/revealed: "checked"/);
  });

  it("only reaches verified when the whole round opened", () => {
    // Pinned as source because inventing this state would be invisible: the
    // derivation reads `phase === "complete"`, not a count of reveals.
    expect(SHELL).toMatch(/progress\.phase === "complete"\s*\n?\s*\?\s*"verified"/);
  });

  it("tells a bad reveal apart from a participant who went away", () => {
    // Different events, different states, different colours. Merging them
    // would accuse somebody offline of cheating.
    expect(SHELL).toMatch(/broken\.has\(fpr\)/);
    expect(SHELL).toMatch(/silent\.has\(fpr\)/);
    expect(PANEL).toMatch(/broken: "does not open"/);
    expect(PANEL).toMatch(/silent: "committed, then gone"/);
  });

  it("asks the reader to compare the digest, which is the split-view defence", () => {
    // `pool-run.js` states that it cannot detect a participant who commits
    // differently to different peers, and that the participants can. This is
    // where they read the number to compare.
    expect(PANEL).toMatch(/Read this to the others/);
    expect(PANEL).toMatch(/two different numbers in one room/);
  });
});

describe("the ids the panel marks rows with are carried, not parsed", () => {
  it("names who broke a round on the error itself", async () => {
    // The same rule as `finalize`'s `dealer`: a surface marking the right row
    // must not have to read a sentence to find out which row.
    const reveals = [
      { id: "@mara", nonce: "aabb" },
      { id: "@lin", nonce: "ccdd" },
    ];
    const commitments = Object.fromEntries(
      await Promise.all(reveals.map(async (r) => [r.id, await entropyCommitment(r)]))
    );
    await expect(
      openEntropyPool({
        commitments,
        reveals: [reveals[0], { id: "@lin", nonce: "eeff" }],
      })
    ).rejects.toMatchObject({ broken: ["@lin"] });
  });

  it("names who committed and vanished, separately", async () => {
    const reveals = [
      { id: "@mara", nonce: "aabb" },
      { id: "@lin", nonce: "ccdd" },
    ];
    const commitments = Object.fromEntries(
      await Promise.all(reveals.map(async (r) => [r.id, await entropyCommitment(r)]))
    );
    await expect(
      openEntropyPool({ commitments, reveals: [reveals[0]] })
    ).rejects.toMatchObject({ silent: ["@lin"] });
  });

  it("carries them through to the shell as fingerprints", () => {
    // `entropy-pool-ops.js` maps both lists, so the panel can match the roster
    // without learning that the driver indexes participants differently.
    expect(OPS).toMatch(/broken: \(broken \|\| \[\]\)\.map\(fingerprintOf\)/);
    expect(OPS).toMatch(/silent: \(silent \|\| \[\]\)\.map\(fingerprintOf\)/);
  });
});
