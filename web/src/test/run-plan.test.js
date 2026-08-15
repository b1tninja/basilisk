/**
 * Who runs which cell, decided before anything runs.
 *
 * `planRun` reads a compiled recipe and a roster and answers three questions
 * that used to be answered by starting a run and watching: where does each
 * cell go, what does this peer wait for, and what will not run at all. The
 * third is the one this file spends most of its effort on.
 *
 * **A planner that only produces plans proves nothing.** A pass that assigned
 * every cell to whoever asked would satisfy any test written from the
 * happy-path side, so every refusal below is reached by *constructing the
 * recipe that triggers it* and asserting both the anchor and the sentence.
 * There are five, and each gets a recipe that a careless implementation would
 * have run:
 *
 * - `two-owners` — one pipeline reading two peers' private slots. The headline
 *   refusal, and the reason the pass exists at compile time rather than at run
 *   time: the alternative is a ceremony that halts halfway with a share
 *   already dealt.
 * - `two-owners` again, in its second shape — a header that names a peer the
 *   data says cannot run it. A header is a sentence; a sentence does not move
 *   a key.
 * - `unknown-peer` — a recipe naming somebody the roster does not have, which
 *   is the common case rather than an edge.
 * - `publish-secret` — `publish` on a cell whose `out` is a private half.
 * - `keying-in-mirror` — retired; see the note where its block stood,
 *   reached through a plan rather than sitting unreached.
 *
 * The second theme is the *binding*. `session.js` deals in fingerprints and
 * says in its own doc comment that turning one into a peer label belongs to
 * whoever holds the roster; `attest.js` says the label a signature resolves to
 * is the caller's to supply. This module is the caller, and the trip a roster
 * row now takes — `labelForFingerprint()` per attestation, then
 * `manifestAttestedBy()` over the documents — is asserted end to end here,
 * including the case that matters most: an attestation whose signer the roster
 * cannot name is *carried through unattributed*, never silently dropped.
 *
 * `attesterLabels` used to sit in the middle of that trip and is gone with
 * `attestersOf`, the set-at-a-time input it was written for. Coverage is
 * counted per attestation now, because `manifestAttestedBy` wants a `by`
 * beside each document rather than a list of everyone who signed something.
 */
import { describe, expect, it } from "vitest";
import {
  labelForFingerprint,
  normalizeRoster,
  planRun,
  summarizePlan,
} from "../lib/toolkit/plan.js";
import { buildAttestation, manifestAttestedBy } from "../lib/toolkit/attest.js";
import { buildRunManifest } from "../lib/toolkit/manifest.js";
import {
  compileRecipe,
  parseRecipe,
  recipeChains,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";

const FPR_A = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_B = "91C7E6D5C4B3A29180716253443526170819AABB";
const FPR_C = "0102030405060708090A0B0C0D0E0F1011121314";
const ROSTER = { mara: FPR_A, okafor: FPR_B };

/** @param {string} src @param {*} [opts] */
const plan = (src, opts) => planRun(compileRecipe(src), opts);

/** @param {ReturnType<typeof plan>} p @param {string} reason */
const refusalFor = (p, reason) => p.refusals.find((r) => r.reason === reason);

/** Two peers, each with a private key of their own. The setup half of most cases. */
const TWO_KEYS = `@mara
genkey x25519 | out $kpM

@okafor
genkey x25519 | out $kpO
`;

describe("a recipe that names no peer plans as one runner", () => {
  it("says so, and says why", () => {
    const p = plan("bytes deadbeef | encode hex | out $a\n\nin $a | out $b");
    expect(p.play).toBe("solo");
    expect(p.ok).toBe(true);
    expect(p.cells.every((c) => c.mine && c.runsOn.length === 0)).toBe(true);
    expect(p.cells[0].why).toContain("names no peer");
    expect(p.refusals).toEqual([]);
    expect(p.asks).toEqual([]);
  });

  it("stays one runner even with a roster in the room", () => {
    const p = plan("bytes deadbeef | out $a", { me: FPR_A, roster: ROSTER });
    expect(p.play).toBe("solo");
    expect(p.cells[0].runsOn).toEqual([]);
    expect(p.asks).toEqual([]);
  });
});

describe("placement is derived from where the private value already is", () => {
  const SRC = `${TWO_KEYS}
@mara
in $kpM | :public | out $pubM | publish

ecdh private=$kpM peer=$pubM | out $shared
`;

  it("forces the last cell onto mara without a header saying so", () => {
    const p = plan(SRC, { me: "mara", roster: ROSTER });
    const last = p.cells[p.cells.length - 1];
    expect(last.declared).toBe(false);
    expect(last.forced).toBe(true);
    expect(last.basis).toBe("secret-locality");
    expect(last.runsOn).toEqual(["mara"]);
  });

  it("explains the placement in terms of the slot that caused it", () => {
    const last = plan(SRC, { me: "mara", roster: ROSTER }).cells.at(-1);
    expect(last?.why).toContain("$kpM");
    expect(last?.why).toContain("not published");
    expect(last?.why).toContain("@mara");
  });

  it("records what the cell consumes, with the declaration that made it a read", () => {
    const last = plan(SRC, { me: "mara", roster: ROSTER }).cells.at(-1);
    const kpM = last?.consumes.find((c) => c.label === "kpM");
    expect(kpM).toMatchObject({
      label: "kpM",
      via: "ecdh private=",
      owner: "mara",
      private: true,
      type: "keypair/x25519/private",
    });
    // `slotOf` is the registry's, read rather than restated — this is the
    // declaration `d532a4c` added and the reason this pass could be written.
    expect(kpM?.slotOf).toEqual(["key", "keypair", "bytes", "text"]);
    // A published slot from the same author is not private to anyone.
    expect(last?.consumes.find((c) => c.label === "pubM")).toMatchObject({
      owner: "mara",
      private: false,
    });
  });

  it("counts what was forced against what was chosen", () => {
    const p = plan(SRC, { me: "mara", roster: ROSTER });
    // Two `genkey` cells chose their peer; two cells were pinned by $kpM.
    expect(p.counts).toMatchObject({ chosen: 2, forced: 2, solo: 0 });
    expect(summarizePlan(p)).toContain("placed run");
  });

  it("makes a published slot a wait rather than a placement", () => {
    const p = plan(SRC, { me: "okafor", roster: ROSTER });
    // okafor runs only their own genkey; nothing of theirs reads mara's
    // publication, so there is nothing to wait for.
    expect(p.cells.filter((c) => c.mine).map((c) => c.index)).toEqual([1]);
    expect(p.waits).toEqual([]);

    const consumer = `${SRC}
@okafor
in $pubM | out $sawIt
`;
    const q = plan(consumer, { me: "okafor", roster: ROSTER });
    expect(q.waits).toEqual([
      { cell: 4, on: 2, peer: "mara", slot: "pubM", reason: "published-slot" },
    ]);
  });

  it("never waits on a value that is not published — it refuses the cell instead", () => {
    const p = plan(
      `${TWO_KEYS}
@okafor
in $kpM | out $stolen
`,
      { me: "okafor", roster: ROSTER }
    );
    expect(p.waits).toEqual([]);
    expect(p.ok).toBe(false);
  });
});

describe("refusal · one pipeline, two owners' secrets", () => {
  const SRC = `${TWO_KEYS}
@mara
ecdh private=$kpM peer=$kpO | out $bad
`;

  it("refuses, rather than picking a machine", () => {
    const p = plan(SRC, { me: "mara", roster: ROSTER });
    expect(p.ok).toBe(false);
    expect(refusalFor(p, "two-owners")).toBeTruthy();
  });

  it("anchors the refusal to the cell, and to the cell's header", () => {
    const src = SRC;
    const p = plan(src, { me: "mara", roster: ROSTER });
    const r = refusalFor(p, "two-owners");
    expect(r?.cell).toBe(2);
    expect(r?.path).toBe("cell 2");
    expect(r?.field).toBe("peer");
    // The anchor covers the header line, not step 0's span — the same rule
    // `validateChainHeader` follows, so a complaint about placement lands on
    // the placement.
    expect(src.slice(r?.start, r?.end)).toBe("@mara");
  });

  it("says it is a protocol problem, and names both owners and both slots", () => {
    const r = refusalFor(plan(SRC, { me: "mara", roster: ROSTER }), "two-owners");
    expect(r?.message).toContain("$kpM");
    expect(r?.message).toContain("$kpO");
    expect(r?.message).toContain("@mara");
    expect(r?.message).toContain("@okafor");
    expect(r?.message).toContain("hands over a private key");
    // The remedy is the sentence, not an appendix to it.
    expect(r?.message).toContain("Split the cell");
    expect(r?.message).toContain("dkg.run");
  });

  it("reports it in mismatchLog's vocabulary rather than a third one", () => {
    const r = refusalFor(plan(SRC, { me: "mara", roster: ROSTER }), "two-owners");
    expect(Object.keys(r || {})).toEqual(
      expect.arrayContaining(["path", "field", "expected", "actual"])
    );
    expect(r?.expected).toBe("one owner");
    expect(r?.actual).toBe("mara, okafor");
  });

  it("records no wait for either secret — neither one is ever going to arrive", () => {
    const p = plan(SRC, { me: "mara", roster: ROSTER });
    // The refused cell is mara's, so the wait pass walks it. A private slot
    // read from another cell is exactly the shape of a dependency, and
    // recording it would describe the run *waiting* for okafor to send a
    // private key rather than refusing to ask.
    expect(p.cells[2].mine).toBe(true);
    expect(p.cells[2].consumes.filter((c) => c.private)).toHaveLength(2);
    expect(p.waits).toEqual([]);
  });

  it("still refuses with no roster at all — this is a fact about the recipe", () => {
    const p = plan(SRC);
    expect(p.bound).toBe(false);
    expect(p.ok).toBe(false);
    expect(refusalFor(p, "two-owners")).toBeTruthy();
  });

  it("does not fire when the second key was published", () => {
    const ok = `${TWO_KEYS}
@okafor
in $kpO | :public | out $pubO | publish

@mara
ecdh private=$kpM peer=$pubO | out $shared
`;
    const p = plan(ok, { me: "mara", roster: ROSTER });
    expect(p.refusals).toEqual([]);
    expect(p.cells.at(-1)?.runsOn).toEqual(["mara"]);
  });
});

describe("refusal · a header that says one peer and reads another's", () => {
  const SRC = `${TWO_KEYS}
@okafor
in $kpM | :public | out $pubM
`;

  it("refuses, and the data wins", () => {
    const p = plan(SRC, { me: "okafor", roster: ROSTER });
    const r = refusalFor(p, "two-owners");
    expect(p.ok).toBe(false);
    expect(r?.expected).toBe("mara");
    expect(r?.actual).toBe("okafor");
    // The plan reports where the cell can actually run, not where it was told
    // to — a plan that echoed the header would be describing a run that
    // cannot happen.
    expect(p.cells[2].runsOn).toEqual(["mara"]);
  });

  it("names the remedy on both sides", () => {
    const r = refusalFor(plan(SRC, { me: "okafor", roster: ROSTER }), "two-owners");
    expect(r?.message).toContain("Move the cell to `@mara`");
    // The other side: publish what the cell needs, from the cell that wrote it,
    // named by the `out` a `publish` would stand behind. The remedy has to be
    // performable as written — it used to say `@mara publish`, which is no
    // longer a header this grammar has.
    expect(r?.message).toContain("`publish`");
    expect(r?.message).toContain("out $kpM");
  });
});

describe("refusal · a peer the roster does not have", () => {
  const SRC = `@alice
genkey x25519 | out $kpA
`;

  it("refuses when the roster is present and does not contain them", () => {
    const p = plan(SRC, { me: FPR_A, roster: ROSTER });
    expect(p.ok).toBe(false);
    const r = refusalFor(p, "unknown-peer");
    expect(r?.field).toBe("roster");
    expect(r?.expected).toBe("mara, okafor");
    expect(r?.actual).toBe("alice");
    expect(p.unknownPeers).toEqual(["alice"]);
  });

  it("says the binding is the roster's job, not the recipe's", () => {
    const r = refusalFor(plan(SRC, { me: FPR_A, roster: ROSTER }), "unknown-peer");
    expect(r?.message).toContain("no one in this room answers to that name");
    expect(r?.message).toContain("`@mara`");
    expect(r?.message).toContain("add `@alice` to the roster");
  });

  it("does not refuse when there is no roster — it plans unbound instead", () => {
    const p = plan(SRC, { me: "alice" });
    expect(p.bound).toBe(false);
    expect(p.ok).toBe(true);
    expect(p.unknownPeers).toEqual([]);
    expect(p.cells[0].runsOn).toEqual(["alice"]);
  });

  it("asks who you are when the roster cannot place you", () => {
    const p = plan("@mara\ngenkey x25519 | out $k", { roster: ROSTER });
    expect(p.me).toBe("");
    expect(p.asks.map((a) => a.reason)).toContain("who-am-i");
    expect(p.cells[0].mine).toBe(false);
  });

  it("takes `me` as either a label or a fingerprint", () => {
    const src = "@mara\ngenkey x25519 | out $k";
    expect(plan(src, { me: "mara", roster: ROSTER }).cells[0].mine).toBe(true);
    expect(plan(src, { me: FPR_A, roster: ROSTER }).cells[0].mine).toBe(true);
    expect(plan(src, { me: FPR_B, roster: ROSTER }).cells[0].mine).toBe(false);
  });
});

describe("refusal · publishing what must not leave the machine", () => {
  it("refuses a private half, and names the public one as the fix", () => {
    const p = plan("@mara\ngenkey x25519 | out $kpM | publish", {
      me: "mara",
      roster: ROSTER,
    });
    const r = refusalFor(p, "publish-secret");
    expect(p.ok).toBe(false);
    expect(r?.field).toBe("publish");
    expect(r?.actual).toBe("$kpM (keypair/x25519/private)");
    // The remedy is written the way the notebook writes it: a keypair half is
    // a step, and sending it needs the `publish` that was the whole complaint.
    // A remedy the reader can paste is the point — this one used to name
    // `:public`, which still compiles and is no longer what the cell would
    // come back as.
    expect(r?.message).toContain("$kpM | public | out $pub | publish");
    expect(r?.message).toContain("drop `publish`");
  });

  it("refuses a share, which is the case a ceremony gets wrong", () => {
    const p = plan(
      "@mara\nrandom 32 | sss.split threshold=2 shares=3 | out $shares | publish",
      { me: "mara", roster: ROSTER }
    );
    expect(refusalFor(p, "publish-secret")?.actual).toContain("$shares");
  });

  it("looks inside a tee branch, where the private half usually hides", () => {
    // This one compiles cleanly and reads as an ordinary key export. Both
    // `out`s are secret and both are refused, which is what "a nested `out` is
    // still this cell's output" means — a branch is not a way out of it.
    const p = plan(
      `@mara
genkey ec/p256 | tee {
  - :private | out $priv | publish
} | out $kp | publish`,
      { me: "mara", roster: ROSTER }
    );
    expect(p.refusals.map((r) => r.actual)).toEqual([
      "$priv (key/ec/p256/private)",
      "$kp (keypair/ec/p256/private)",
    ]);
  });

  it("allows the public half through", () => {
    const p = plan(
      `@mara
genkey x25519 | out $kpM

@mara
in $kpM | :public | out $pubM | publish`,
      { me: "mara", roster: ROSTER }
    );
    expect(p.refusals).toEqual([]);
  });

  /**
   * **Every remedy this refusal names has to be one the compiler accepts.**
   *
   * The first one used to be `$x | :public | out $pub` for everything refused,
   * and `:public` is a selector over a *keypair*. A product owner marked a
   * mnemonic share `publish`, did exactly what the refusal told them, and got
   * `selector ":public" requires keypair, got text/mnemonic` — the refusal had
   * sent them to a pipeline that cannot compile, which is worse than sending
   * them nowhere.
   *
   * The property pinned is that one, not either sentence: **the advice appears
   * exactly when following it works.** `follow` writes the notebook a reader
   * gets by doing what they were told and hands it to the compiler, so nothing
   * here is built from the constant the rule reads — `plan.js` gets no vote on
   * whether its own advice compiles.
   */
  const REFUSED = [
    { what: "a keypair", cell: "genkey x25519 | out $x" },
    {
      what: "one mnemonic share",
      cell: "random 32 | sss.split threshold=2 shares=3 | blip39 | at 1 | out $x",
    },
    {
      what: "a whole split",
      cell: "random 32 | sss.split threshold=2 shares=3 | out $x",
    },
    { what: "a projected private half", cell: "genkey ec/p256 | private | out $x" },
    { what: "a master", cell: '"hi" | utf8 | gpg.symencrypt mode=master | out $x' },
  ];

  /** What the compiler says about the notebook the advice would produce. */
  const follow = (cell) =>
    compileRecipe(`@mara\n${cell}\n\n@mara\nin $x | public | out $pub | publish`)
      .validation.errors.map((e) => e.message);

  it.each(REFUSED)("offers the public half for $what only if that compiles", ({ cell }) => {
    const r = refusalFor(
      plan(`@mara\n${cell} | publish`, { me: "mara", roster: ROSTER }),
      "publish-secret"
    );
    expect(r).toBeTruthy();
    expect(r.message.includes("$x | public | out $pub | publish")).toBe(
      follow(cell).length === 0
    );
  });

  it("has cases on both sides of that, or the row above asserts nothing", () => {
    // One table where every row answered the same way would pass whatever the
    // condition was, including no condition at all.
    const compiles = REFUSED.map((r) => follow(r.cell).length === 0);
    expect(compiles.filter(Boolean).length).toBe(1);
    expect(compiles.filter((ok) => !ok).length).toBe(REFUSED.length - 1);
    expect(follow(REFUSED[1].cell)[0]).toContain("requires keypair");
  });

  it("tells a share the true thing instead, and names its peer in full", () => {
    // The owner's own case: a K-of-N split through `blip39`, one share out, a
    // cell headed with a whole fingerprint. What is true about it is not
    // "publish something else" — it is that a share has one holder and the
    // header already named them.
    const p = plan(
      `@${FPR_A}
random 32 | sss.split threshold=2 shares=3 | blip39 | at 1 | out $share | publish`,
      { me: FPR_A, roster: { [FPR_A]: FPR_A } }
    );
    const r = refusalFor(p, "publish-secret");
    expect(r?.message).not.toContain("| public | out");
    expect(r?.message).toContain("one holder's piece of a K-of-N split");
    expect(r?.message).toContain("runs on its peer's own machine");
    // Whole fingerprint wherever it appears, never a prefix of one.
    expect(r?.message).toContain(`@${FPR_A}`);
    // Sentence-cased: it is the only remedy left, so it opens the list. It
    // names the `out` the `publish` stands behind, because that is the edit —
    // "drop `publish` from this cell" was true of a header and is ambiguous
    // about a cell with several `out`s.
    expect(r?.message).toContain("Drop `publish` from after `out $share`.");
  });

  /** One cell, two `out`s, and a `publish` on each. */
  const BOTH = `@mara
random 32 | tee
  - encode hex | out $hex | publish
| sss.split threshold=2 shares=3 | blip39 | at 1 | out $share | publish`;

  it("says which slot it is refusing, and what the cell is", () => {
    // The opening sentence used to reassemble the header from two fields to
    // avoid describing a cell as marked something its author never wrote.
    // There is one thing a header can say now, and the refused slot is named
    // beside it rather than reconstructed from it.
    const r = refusalFor(plan(BOTH, { me: "mara", roster: ROSTER }), "publish-secret");
    expect(r?.message).toContain("Cell 0 is `@mara` and publishes `$share`");
    expect(r?.message).not.toContain("$hex, which is");
  });

  it("reports what leaves as a list, with no boolean beside it to disagree", () => {
    // `PlanCell.publish` used to sit next to `publishes` and was exactly
    // `publishes.length > 0` — a summary of the list that could only agree
    // with it or contradict it. Setting it to `false` outright was caught by
    // nothing in this repo, which is what a redundant field buys. It is gone,
    // and `PlanPanel` reads the list; this is the assertion that the list says
    // enough for it to.
    const p = plan(BOTH.replace(" | out $share | publish", " | out $share"), {
      me: "mara",
      roster: ROSTER,
    });
    expect(p.cells[0].publishes).toEqual(["hex"]);
    expect(p.cells[0].produces).toEqual(["hex", "share"]);
    expect("publish" in p.cells[0]).toBe(false);
    // And a cell that publishes nothing says so with an empty list rather than
    // with a second field.
    const quiet = plan("@mara\nrandom 32 | encode hex | out $hex", {
      me: "mara",
      roster: ROSTER,
    });
    expect(quiet.cells[0].publishes).toEqual([]);
  });

  it("writes out the narrower disclosure rather than eliding it", () => {
    // The elided form asked the reader to solve the refusal before they could
    // take its advice — and on a cell with nothing else to publish there was
    // no advice to solve for at all. Taken literally, what it names now plans.
    const r = refusalFor(plan(BOTH, { me: "mara", roster: ROSTER }), "publish-secret");
    const narrowed = r?.message.match(/`(out \$[^`]+ \| publish)`\)/)?.[1];
    expect(narrowed).toBe("out $hex | publish");
    const fixed = plan(BOTH.replace(" | out $share | publish", " | out $share"), {
      me: "mara",
      roster: ROSTER,
    });
    expect(fixed.refusals).toEqual([]);
    expect(fixed.cells[0].publishes).toEqual(["hex"]);
  });

  it("asks rather than refuses when it cannot see what is in the slot", () => {
    // Reached through the AST rather than a compile result, which is the
    // documented second entry point: the type walk stops at the step it
    // cannot resolve, so `$x` is never typed, and an untyped value is a
    // question rather than a verdict. Fail-closed either way — the run does
    // not proceed on a shrug.
    const { ast } = parseRecipe("@mara\nbytes deadbeef | sss.combine | out $x | publish");
    const p = planRun(ast, { me: "mara", roster: ROSTER });
    expect(p.refusals).toEqual([]);
    const ask = p.asks.find((a) => a.reason === "publish-untyped");
    expect(ask?.cell).toBe(0);
    expect(ask?.question).toContain("could not work out what is in it");
  });
});

/*
 * "refusal · a mirrored run that would seed a key" stood here, exercising the
 * `manifest` option to `planRun` and the `keying-in-mirror` refusal behind it.
 * Both are gone, and the reason belongs where the tests were.
 *
 * The refusal read a manifest's `entropy.mode` and refused a `pool` run
 * containing any op that *draws* keying randomness, on the premise that such an
 * op would be seeded from the pool. Nothing in this build seeds anything from a
 * pool, so `genkey` in a pooled notebook draws from the platform CSPRNG and
 * every peer gets a different key — the refusal was false. It would also have
 * refused every manifest this build produces, because a manifest only says
 * `pool` when a pool was drawn, which needs a room, which needs `quorum.join`,
 * which correctly declares `keying` for the channel's ephemeral ECDH. And no
 * caller ever passed a manifest, so it never ran.
 *
 * The danger was real. It is now checked by value flow in the compiler — a
 * pooled value may not become key material — which is `pooled-value-rule.test.js`.
 */

describe("refusal · a recipe that does not compile has no placement", () => {
  it("says so once, against the recipe rather than a cell", () => {
    const p = plan("in $nope | out $x");
    expect(p.ok).toBe(false);
    expect(p.refusals).toHaveLength(1);
    expect(p.refusals[0]).toMatchObject({ reason: "uncompiled", path: "recipe", cell: -1 });
    expect(p.cells).toEqual([]);
  });
});

describe("what the planner cannot decide, it asks about", () => {
  it("asks whose vault an unplaced boundary op reaches", () => {
    const p = plan(
      `@mara
genkey x25519 | out $k

"hi" | utf8 | agent.sign ${FPR_A} | out $sig`,
      { me: "mara", roster: ROSTER }
    );
    const ask = p.asks.find((a) => a.reason === "vault-locality");
    expect(ask?.cell).toBe(1);
    expect(ask?.question).toContain("agent.sign");
    expect(ask?.question).toContain("whose vault");
    expect(ask?.choices).toEqual(["mara", "okafor"]);
    // An ask is not a refusal: the notebook is still plannable.
    expect(p.ok).toBe(true);
  });

  it("asks about unplaced key generation, because everyone would mint a different one", () => {
    const p = plan(
      `@mara
bytes deadbeef | out $seed

genkey x25519 | out $shared`,
      { me: "mara", roster: ROSTER }
    );
    const ask = p.asks.find((a) => a.reason === "keying-unplaced");
    expect(ask?.cell).toBe(1);
    expect(ask?.question).toContain("genkey");
    expect(ask?.question).toContain("$shared");
    expect(p.ok).toBe(true);
  });

  it("asks nothing once the cell has a header", () => {
    const p = plan(
      `@mara
bytes deadbeef | out $seed

@okafor
genkey x25519 | out $k`,
      { me: "mara", roster: ROSTER }
    );
    expect(p.asks).toEqual([]);
  });
});

describe("the roster is the binding, and it is checked like one", () => {
  it("canonicalises labels and fingerprints both ways", () => {
    const r = normalizeRoster({ mara: "4f2a c1b3 9d8e 7c6a 5b49 3827 1605 f4e3 d2c1 b0a9" });
    expect(r.labels).toEqual(["mara"]);
    expect(r.byLabel.get("mara")).toBe(FPR_A);
    expect(labelForFingerprint({ mara: FPR_A }, FPR_A.toLowerCase())).toBe("mara");
    expect(labelForFingerprint({ mara: FPR_A }, FPR_C)).toBe("");
  });

  it("takes a fingerprint as a peer, on both sides of the binding", () => {
    // The roster is identity-mapped now: a peer *is* a key, so both sides of
    // the pair are the same forty characters. This used to throw — a
    // fingerprint in the peer column was the shape the old rule refused — and
    // it is the ordinary case the product writes.
    const { byLabel, byFpr } = normalizeRoster({ [FPR_A]: FPR_A });
    expect(byLabel.get(FPR_A)).toBe(FPR_A);
    expect(byFpr.get(FPR_A)).toBe(FPR_A);
  });

  it("refuses a part of a key written where a peer belongs", () => {
    // The refusal that survived, applied at the other end of the binding — a
    // roster is assembled from a session, and a session speaks fingerprints, so
    // this is where a short id gets typed by mistake. A suffix names more than
    // one key, so a roster keyed by one binds nothing and the `peersSha`
    // computed over it commits to nothing in particular.
    //
    // Both halves of the asymmetry are exercised: a key id beginning with a
    // letter is a structurally valid *name* and has to be refused by the
    // semantic rule, and one beginning with a digit must reach the same refusal
    // rather than a different complaint about the grammar.
    expect(() => normalizeRoster({ D2C1B0A94F2AC1B3: FPR_A })).toThrow(
      /part of a key rather than a key/
    );
    expect(() => normalizeRoster({ "42C1B0A94F2AC1B3": FPR_A })).toThrow(
      /part of a key rather than a key/
    );
  });

  it("refuses a label with nothing behind it", () => {
    expect(() => normalizeRoster({ mara: "" })).toThrow(/binds nothing/);
  });

  it("refuses the rendezvous wildcard as a participant", () => {
    expect(() => normalizeRoster({ "*": FPR_A })).toThrow(/every participant/);
  });
});

describe("the binding session.js deliberately does not make", () => {
  /**
   * Roster rows as `projectRosterPeers` hands them over, turned into the
   * entries `manifestAttestedBy` takes — which is exactly what `useNotebook`'s
   * coverage effect does, and the only crossing it is allowed to make.
   *
   * @param {{ fingerprint: string, attested: any[] }[]} rows
   */
  function entriesFrom(rows) {
    const out = [];
    for (const row of rows) {
      const by = labelForFingerprint(ROSTER, row.fingerprint);
      for (const attestation of row.attested) {
        out.push(by ? { by, attestation } : { attestation });
      }
    }
    return out;
  }

  it("turns attesting roster rows into the entries manifestAttestedBy wants", async () => {
    const manifest = await buildRunManifest({
      recipeSource: "bytes deadbeef | out $a",
      cells: [{ index: 0, recipe: "bytes deadbeef | out $a" }],
      peers: ROSTER,
    });
    const attestation = await buildAttestation({ manifest });

    const result = await manifestAttestedBy(
      manifest,
      entriesFrom([
        { fingerprint: FPR_A, attested: [attestation] },
        { fingerprint: FPR_B, attested: [attestation] },
      ])
    );
    expect(result.ok).toBe(true);
    expect(result.attested).toEqual(["mara", "okafor"]);
    expect(result.missing).toEqual([]);
  });

  it("carries an attestation it cannot name rather than dropping it", async () => {
    const manifest = await buildRunManifest({
      recipeSource: "bytes deadbeef | out $a",
      cells: [{ index: 0, recipe: "bytes deadbeef | out $a" }],
      peers: ROSTER,
    });
    const attestation = await buildAttestation({ manifest });
    const entries = entriesFrom([
      { fingerprint: FPR_A, attested: [attestation] },
      { fingerprint: FPR_C, attested: [attestation] },
    ]);
    // A signature that was checked and a signer this roster cannot name is a
    // fact worth reporting. It goes on with no `by`, which is what makes the
    // caveat below sayable at all — dropping it would report less than is
    // known, and coverage would silently read as short by one.
    expect(entries.map((e) => e.by)).toEqual(["mara", undefined]);

    const result = await manifestAttestedBy(manifest, entries);
    expect(result.ok).toBe(false);
    expect(result.missing).toEqual(["okafor"]);
    expect(result.caveats.join(" ")).toMatch(/1 attestation arrived with no attester/);
  });

  it("leaves the coverage gap visible when the roster is short", async () => {
    const manifest = await buildRunManifest({
      recipeSource: "bytes deadbeef | out $a",
      cells: [{ index: 0, recipe: "bytes deadbeef | out $a" }],
      peers: ROSTER,
    });
    const attestation = await buildAttestation({ manifest });
    const result = await manifestAttestedBy(
      manifest,
      entriesFrom([{ fingerprint: FPR_A, attested: [attestation] }])
    );
    expect(result.ok).toBe(false);
    expect(result.missing).toEqual(["okafor"]);
  });
});

/**
 * Sealing to a key the room does not name.
 *
 * Nothing refused it and nothing asked about it: a cell could seal every share
 * of a ceremony to a constant fingerprint no participant holds, and the plan
 * came back clean. It is not a *refusal* — an offline archive key or a hardware
 * key not present at the table is exactly the legitimate reason a ceremony has
 * an escrow, and refusing would make that inexpressible. It is the one fact a
 * reader should confirm before shares are dealt, which is `publish-untyped`'s
 * shape, so it joins the asks.
 *
 * The two spellings are one question. `seal to=<fpr>` inside a scatter body and
 * `gpg.encrypt to=fpr:<fpr>` in an ordinary pipeline both address a constant
 * key by fingerprint, and a reader who wrote one meant what the other means.
 */
describe("ask · a constant recipient the room does not name", () => {
  const OUTSIDE = "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333";
  const SEALS = `@mara
random 32 | sss.split 2/2 | blip39 | scatter to=room
  - seal to=${OUTSIDE} | out $sealed
`;

  it("asks, naming the key whole and the room it is not in", () => {
    const p = plan(SEALS, { me: "mara", roster: ROSTER });
    expect(p.refusals).toEqual([]);
    const ask = p.asks.find((a) => a.reason === "seal-outside-room");
    expect(ask?.cell).toBe(0);
    // Whole, grouped, never truncated — the record of which key a ceremony was
    // asked about is no place for half a fingerprint.
    expect(ask.question).toContain("AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333");
    expect(ask.question.replace(/[^0-9A-F]/g, "")).toContain(OUTSIDE);
    // The room, by the labels the roster binds.
    expect(ask.question).toContain("`@mara` and `@okafor`");
    expect(ask.question).toContain(
      "Confirm this is intended — this key is not in the room and will not be " +
        "at the table when shares are dealt."
    );
    // An ask, not a refusal: the plan still runs.
    expect(p.ok).toBe(true);
  });

  it("asks the same of the `gpg.encrypt to=fpr:` spelling", () => {
    const p = plan(`@mara\ninput | gpg.encrypt to=fpr:${OUTSIDE} mode=combined | out $c`, {
      me: "mara",
      roster: ROSTER,
    });
    expect(p.refusals).toEqual([]);
    expect(p.asks.filter((a) => a.reason === "seal-outside-room")).toHaveLength(1);
  });

  it("says nothing when the key is in the room", () => {
    const inside = SEALS.replace(OUTSIDE, FPR_B);
    const p = plan(inside, { me: "mara", roster: ROSTER });
    expect(p.asks.filter((a) => a.reason === "seal-outside-room")).toEqual([]);
  });

  /**
   * Solo use is the normal case and has no audience to compare against. An ask
   * here would fire on every recipe anybody writes alone, which is how an ask
   * stops being read at all.
   */
  it("says nothing with no roster, because there is no room to be outside of", () => {
    const p = plan(SEALS, { me: "mara" });
    expect(p.asks.filter((a) => a.reason === "seal-outside-room")).toEqual([]);
  });

  /**
   * `to=each` is a derivation the room supplies — `scatter` already constrains
   * a body that names anybody else, and a member the audience does not name
   * cannot appear in one. Asking about it would be asking about the room.
   */
  it("says nothing about `to=each`, which names no constant at all", () => {
    const p = plan(SEALS.replace(OUTSIDE, "each"), { me: "mara", roster: ROSTER });
    expect(p.asks.filter((a) => a.reason === "seal-outside-room")).toEqual([]);
  });

  /**
   * A `$slot` resolves at run time from a tray or a keyserver, so this pass
   * cannot say which key it lands on. Guessing at one and printing it would put
   * a fingerprint in front of a reader that the run may never use.
   */
  it("says nothing about a `$slot`, whose key this pass cannot know", () => {
    const p = plan(
      "@mara\ngpg.genkey email=\"k@example.com\" | out $k\n\n@mara\ninput | gpg.encrypt to=$k mode=combined | out $c",
      { me: "mara", roster: ROSTER }
    );
    expect(p.asks.filter((a) => a.reason === "seal-outside-room")).toEqual([]);
  });
});
