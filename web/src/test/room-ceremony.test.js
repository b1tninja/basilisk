/**
 * The split-key ceremony a room generates, checked against the room.
 *
 * This is the first template in the product that is a *function of the
 * audience* rather than a string, so the thing to prove is not that one recipe
 * works — it is that every recipe the product can generate works. There are
 * fifteen of them (rooms of 2 through 16), the largest has 47 cells, and each
 * one has to compile, place every cell on somebody, and refuse nothing, from
 * the point of view of every member in turn.
 *
 * ## Why a generator at all
 *
 * Because the cell count depends on the room and nothing in the language can
 * vary a recipient per iteration: `foreach` declares `params: []` so it has no
 * `to=` to change between rounds, and `tee`'s `-` lines concatenate a stem
 * rather than branching to different addressees. `refuses the shapes a fixed
 * template would have taken` below is that claim as a test rather than as a
 * paragraph, because it is the premise the whole module rests on.
 *
 * ## The three findings this file pins
 *
 * 1. **Two holders cannot both write `out $share`.** The compiler reads the
 *    whole notebook, not the part that runs here, so two cells placed on two
 *    different machines still collide — `Duplicate out slot $share`. The shape
 *    that was handed to me had exactly that in it and does not compile. Pinned
 *    twice: the naive spelling is asserted to fail, and the generated one to
 *    pass, so a future "simplification" back to one slot name fails loudly.
 * 2. **A peer cannot be a placeholder in a step param**, and the way it fails
 *    is worse than a compile error: on `quorum.send`, whose recipient is
 *    positional, `to=@holder1` parses cleanly and is kept as a literal — a cell
 *    that compiles, runs, and addresses nobody. On `quorum.recv` the same
 *    spelling does not lex at all. Either way there is no mutator for a step
 *    param, so resolution-after-the-fact has nothing to resolve with and the
 *    audience has to come first.
 * 3. **`$set | at 1 | out $mine` does not make a slot.** A selected share
 *    carries `meta.shareIndex`, and `slot-registry.register` diverts any such
 *    value into `slotsByIndex` and returns *before* `slotsByLabel.set` — so the
 *    cell reports `ok`, draws a tile, and the next cell to read `$mine` fails
 *    with "unknown slot (register earlier with out $mine)", naming a remedy that
 *    had already been performed. It was found by running the ceremony across two
 *    browsers, not here, which is the whole argument for the e2e; this file
 *    pins the shape that avoids it.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  DEALER_BASED,
  MAX_ROOM,
  NO_REDUNDANCY_AT_TWO,
  canonicalCeremonyText,
  ceremonyQuorum,
  roomCeremony,
  roomCeremonyIssues,
  roomCeremonySummary,
} from "../lib/toolkit/room-ceremony.js";
import { compileRecipe, recipeChains, serializeRecipe } from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { planRun } from "../lib/toolkit/plan.js";

/** Distinct whole fingerprints, as many as a room can hold and one more. */
const fpr = (n) => n.toString(16).toUpperCase().padStart(4, "0").repeat(10).slice(0, 40);
const room = (n) => Array.from({ length: n }, (_, i) => fpr(i + 1));

/** Every room the product can open a ceremony for. */
const SIZES = Array.from({ length: MAX_ROOM - 1 }, (_, i) => i + 2);

/** The ceremony for a room of `n`, dealt by the first member. */
const ceremonyFor = (n) => roomCeremony({ audience: room(n), self: fpr(1) });

describe("the quorum a room implies", () => {
  it("spends one share per person and requires a majority of them", () => {
    for (const n of SIZES) {
      const { shares, threshold } = ceremonyQuorum(n);
      expect(shares, `a room of ${n} should make ${n} shares`).toBe(n);
      // The property, not the formula. `floor(n/2)+1` is one way to spell a
      // majority; what is being promised is that any two qualifying sets
      // overlap, and that is exactly `2K > N`. A `2/4` would satisfy the
      // formula's shape and fail this, which is the point — two disjoint pairs
      // could each rebuild the secret and neither would know.
      expect(2 * threshold, `${threshold}-of-${n} is not a majority`).toBeGreaterThan(shares);
      // And it is the *smallest* majority: a threshold higher than it needs to
      // be costs availability for nothing.
      expect(2 * (threshold - 1)).toBeLessThanOrEqual(shares);
      expect(threshold).toBeLessThanOrEqual(shares);
    }
  });

  it("gives a room of two the 2-of-2 that has no redundancy, and says so", () => {
    expect(ceremonyQuorum(2)).toEqual({ shares: 2, threshold: 2 });
    const two = roomCeremonySummary(ceremonyFor(2));
    expect(two).toContain(NO_REDUNDANCY_AT_TWO);
    // Not said about a room where it is untrue. A three-person room is 2-of-3
    // and one lost share is survivable, so printing the warning there would be
    // a sentence naming a state the reader is not in.
    expect(roomCeremonySummary(ceremonyFor(3))).not.toContain(NO_REDUNDANCY_AT_TWO);
  });
});

describe("every notebook the product can generate", () => {
  it("compiles, for every room size", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      expect(c.issues, `a room of ${n} refused`).toEqual([]);
      const { validation } = compileRecipe(c.text);
      expect(
        validation.errors.map((e) => e.message),
        `the ${c.threshold}-of-${c.shares} ceremony does not compile`
      ).toEqual([]);
    }
  });

  it("places every cell on somebody, from every member's point of view", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const members = room(n);
      const compiled = compileRecipe(c.text);
      const roster = Object.fromEntries(members.map((m) => [m, m]));
      for (const me of members) {
        const plan = planRun(compiled, { roster, me });
        expect(plan.refusals, `${me} is refused a ${n}-person ceremony`).toEqual([]);
        // No asks either. An ask is the planner stopping to have a question
        // answered, and a ceremony that opened with a question would be the
        // chicken-and-egg back in a different costume.
        expect(plan.asks).toEqual([]);
        expect(plan.ok).toBe(true);
        expect(
          [...new Set(plan.cells.map((cell) => cell.kind))],
          `not every cell in a ${n}-person ceremony is placed`
        ).toEqual(["placed"]);
        expect(plan.unknownPeers ?? []).toEqual([]);
      }
    }
  });

  it("writes the cells the room implies, and no others", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const members = room(n);
      const dealer = fpr(1);
      const holders = members.slice(1);
      // The split, one send each, one receive each, the returns from everybody
      // but the recoverer, and the one gather. Written out rather than as a
      // formula, so a change in shape has to be re-derived here. There is no
      // "keep share 1" cell — see the test below for why there cannot be.
      expect(c.cells).toHaveLength(1 + holders.length * 2 + (n - 1) + 1);
      expect(c.dealer).toBe(dealer);
      // The recoverer is a holder, never the dealer: the dealer already saw the
      // secret, so a dealer who recovers it has demonstrated nothing.
      expect(holders).toContain(c.recoverer);
      expect(c.recoverer).not.toBe(dealer);
      for (const cell of c.cells) expect(members).toContain(cell.peer);
      // Exactly one receiving cell per holder, and every one of them on the
      // holder themselves.
      const receiving = c.cells.filter((cell) => cell.recipe.startsWith("quorum.recv from="));
      expect(receiving.map((cell) => cell.peer).sort()).toEqual([...holders].sort());
      // Exactly one send per holder, all of them the dealer's.
      const dealing = c.cells.filter(
        (cell) => cell.phase === "deal" && cell.recipe.startsWith("$set | at ")
      );
      expect(dealing).toHaveLength(holders.length);
      for (const cell of dealing) {
        expect(cell.peer).toBe(dealer);
        expect(cell.recipe).toContain("quorum.send");
      }
    }
  });

  it("gives every holder their own slot, because the compiler reads the whole notebook", () => {
    // **The finding.** Two holders both writing `out $share` is the shape that
    // was handed to me, and it does not compile: the two cells run on two
    // machines and live in one document, and validation is over the document.
    const naive = [
      `@${fpr(1)}`,
      "random 32 | sss.split threshold=2 shares=3 | blip39 | out $set",
      "",
      `@${fpr(2)}`,
      `quorum.recv from=${fpr(1)} | out $share`,
      "",
      `@${fpr(3)}`,
      `quorum.recv from=${fpr(1)} | out $share`,
    ].join("\n");
    expect(compileRecipe(naive).validation.errors.map((e) => e.message)).toContain(
      "Duplicate out slot $share"
    );
    // And the generated one does not have that shape. Asserted as an absence of
    // duplicates rather than as a spelling, so renaming the slots is free and
    // colliding them is not.
    const c = ceremonyFor(4);
    const outs = [...c.text.matchAll(/\bout \$([\w-]+)/g)].map((m) => m[1]);
    expect(new Set(outs).size, `two cells write the same slot: ${outs.join(", ")}`).toBe(
      outs.length
    );
  });

  it("never names a selected share, because a named selected share is not a slot", () => {
    // The finding that cost a two-browser run. `at` stamps `meta.shareIndex`,
    // and `register` diverts on it — so `out $mine` after a selection writes a
    // tile and no slot, and the failure surfaces one cell later as
    // `in $mine: unknown slot`. Pinned at the registry rather than at the
    // recipe, because that is where the divert lives and where a fix would
    // land.
    const registry = createSlotRegistry();
    registry.register("$mine", { type: "text", data: "one share", meta: { shareIndex: 1 } });
    expect(() => registry.resolve("$mine")).toThrow(/unknown slot/);
    // Without the stamp the same call does register a label, so the divert is
    // what does it rather than the name being rejected.
    registry.register("$plain", { type: "text", data: "not a share", meta: {} });
    expect(registry.resolve("$plain").data).toBe("not a share");
    // So the generator selects a share only where the selection is consumed on
    // the spot — into `quorum.send` — and never into an `out`.
    for (const n of SIZES) {
      for (const cell of ceremonyFor(n).cells) {
        if (/\bat \d+\b/.test(cell.recipe)) {
          expect(cell.recipe, "a selected share is being written to a slot").not.toMatch(
            /\bat \d+ \| out /
          );
        }
      }
    }
  });

  it("refuses the shapes a fixed template would have taken", () => {
    // Why this is a generator, as evidence rather than as a claim in a comment.
    //
    // **A placeholder in a step param is worse than a compile error.** The
    // obvious design — author the notebook once against `@holderN`, resolve the
    // names when the audience arrives — fails in two different ways depending
    // on which verb it is written on, and neither of them is the failure you
    // would design for. `quorum.send` takes a *positional* recipient, so a
    // placeholder parses cleanly and is kept as a literal string: a cell that
    // compiles, runs, and addresses nobody.
    const sendish = compileRecipe(
      "random 32 | sss.split threshold=2 shares=2 | blip39 | out $set\n\n$set | at 2 | quorum.send to=@holder1"
    );
    expect(sendish.validation.errors).toEqual([]);
    expect(serializeRecipe(recipeChains(sendish.ast))).toContain('quorum.send "@holder1"');
    // `quorum.recv`'s `from=` has no positional form, so the same placeholder
    // written against a real key does not lex at all — `@2222…` is read as a
    // number. A notebook holding both verbs would therefore be half broken and
    // half silently wrong, in the window between being authored and being
    // resolved.
    expect(
      compileRecipe(`quorum.recv from=@${fpr(2)} | out $x`).validation.errors.length
    ).toBeGreaterThan(0);
    // And there is no mutator for a step param anywhere in the product:
    // `setCellPeer` rewrites headers, and `to=`/`from=` are not headers. So
    // resolution-after-the-fact has nothing to resolve with, and the audience
    // has to come first.
    //
    // `foreach` is the other half of the argument: it declares no params, so it
    // cannot be handed a different recipient per round however the loop is
    // written. That is why the cell count has to come from the room.
    const spec = getStep("foreach");
    expect(spec.params ?? []).toEqual([]);
  });
});

describe("the secret, and what is written down about it", () => {
  it("never writes the master to a slot on any machine", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const split = c.cells[0];
      // The split cell's `out`s are the digest and the share set. The 32 bytes
      // themselves go from `random` into `sss.split` and are never named, so
      // there is no slot, no tile and no receipt entry holding them.
      expect([...split.recipe.matchAll(/\bout \$([\w-]+)/g)].map((m) => m[1])).toEqual([
        "expected",
        "set",
      ]);
      expect(split.recipe).toContain("digest");
      // `$set` is every share and it is the dealer's; a `publish` on it would be
      // the whole secret leaving by a header instead of by a verb.
      expect(c.text).not.toContain("publish");
    }
  });

  it("carries the quorum in the text, where two peers will digest it", () => {
    // `ade4043`: `sss.split threshold=2 shares=3` used to round-trip to bare
    // `sss.split`, so the security property was absent from what the two ends
    // compare. A generated notebook is the case where that would be least
    // visible, since nobody typed the numbers.
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      expect(c.text).toContain(`sss.split threshold=${c.threshold} shares=${c.shares}`);
    }
  });

  it("says it is a dealer-based split and not distributed key generation", () => {
    const summary = roomCeremonySummary(ceremonyFor(5));
    expect(summary).toContain(DEALER_BASED);
    // The correction names the weaker property and the verb that has the
    // stronger one, because a reader who is only told "this is not DKG" has
    // been given a warning with nothing on the other side of it.
    expect(DEALER_BASED).toContain("dealer-based");
    expect(DEALER_BASED).toContain("dkg.run");
    expect(DEALER_BASED).toMatch(/not distributed key generation/i);
    // And the summary states the majority property rather than only the number,
    // so a reader tempted to lower it knows what it buys.
    expect(summary.join(" ")).toContain("majority");
  });
});

describe("recovery is part of the template", () => {
  it("recombines on a machine that never held the secret", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const gather = c.cells.at(-1);
      expect(gather.phase).toBe("recover");
      expect(gather.peer).toBe(c.recoverer);
      expect(gather.peer).not.toBe(c.dealer);
      expect(gather.recipe).toContain("sss.combine");
      // `shares` is the collector, reading the pipe and the slot `with=` names.
      // Without it the holder is sent to a paste tray for values they are
      // already holding, which is what `dc5d7cb` fixed.
      expect(gather.recipe).toContain("shares with=$share-1");
      expect(gather.recipe).toContain("out $secret");
      // And a digest of what came back, so the recovery can be checked against
      // the dealer's `$expected` without either machine showing the secret.
      expect(gather.recipe).toContain("out $recovered");
    }
  });

  it("asks for exactly one short of the threshold, because the recoverer holds one", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const gather = c.cells.at(-1);
      const asked = /quorum\.recv count=(\d+)/.exec(gather.recipe);
      // `count=1` is the param's default and the serializer drops it, so the
      // one-short-of-two case has no `count=` in the text at all. That is the
      // same number said in fewer characters, and it is asserted as such rather
      // than being allowed to look like an omission.
      const count = asked ? Number(asked[1]) : 1;
      expect(count + 1, `${c.threshold}-of-${c.shares} gathers the wrong number`).toBe(
        c.threshold
      );
      // No `from=` anywhere in it. Any majority may rebuild the secret, so
      // naming which holders those are would be a smaller promise than the
      // split makes — and it has to be asked of the whole cell rather than of
      // the string `quorum.recv from=`, because `count=` sits between the two
      // and a narrower check let a `from=` through in mutation.
      expect(gather.recipe, "the gather names who may answer").not.toContain("from=");
    }
  });

  it("gives everybody but the recoverer a way to hand their share back", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const returns = c.cells.filter(
        (cell) => cell.phase === "recover" && cell.recipe.includes("quorum.send")
      );
      expect(returns).toHaveLength(n - 1);
      expect(returns.map((cell) => cell.peer)).not.toContain(c.recoverer);
      // Enough of them to reach the threshold even if the dealer is the only
      // one who answers — which is the two-person room, where they are.
      expect(returns.length).toBeGreaterThanOrEqual(c.threshold - 1);
      for (const cell of returns) expect(cell.recipe).toContain(c.recoverer);
    }
  });
});

describe("the refusals name the number that is actually true", () => {
  it("will not write a ceremony for a room bigger than sss.split can serve", () => {
    const over = roomCeremonyIssues({ audience: room(17), self: fpr(1) });
    expect(over).toHaveLength(1);
    // The count, the bound, and how many to remove — all three, because a
    // refusal that says "too many" leaves the reader counting.
    expect(over[0]).toContain("17 shares");
    expect(over[0]).toContain("at most 16");
    expect(over[0]).toContain("Remove 1 person");
    expect(roomCeremonyIssues({ audience: room(20), self: fpr(1) })[0]).toContain(
      "Remove 4 people"
    );
    // And it refuses at the picker rather than at compile: nothing is generated
    // for a room this size, so no notebook is written and then declined.
    expect(roomCeremony({ audience: room(17), self: fpr(1) }).cells).toEqual([]);
    expect(roomCeremony({ audience: room(17), self: fpr(1) }).text).toBe("");
  });

  it("names which of the two lists is wrong when there is nobody to deal to", () => {
    expect(roomCeremonyIssues({ audience: [fpr(1)], self: fpr(1) })[0]).toContain(
      "one key in it — yours"
    );
    expect(roomCeremonyIssues({ audience: [], self: "" }).join(" ")).toContain(
      "Choose the key you are joining as"
    );
    // Pickable above and removable below, so the two lists can disagree. The
    // refusal says which one to fix rather than saying the room is invalid.
    const stray = roomCeremonyIssues({ audience: room(3), self: fpr(9) });
    expect(stray.join(" ")).toContain("not one of the keys in the room");
  });

  it("de-duplicates the room rather than dealing one person two shares", () => {
    const dup = roomCeremony({ audience: [fpr(1), fpr(2), fpr(2)], self: fpr(1) });
    expect(dup.shares).toBe(2);
    expect(dup.issues).toEqual([]);
  });
});

describe("the text is the text the notebook will hold", () => {
  it("is already canonical, so the preview cannot differ from the editor", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      // A fixed point of the serializer, which is what `recipe-roundtrip` asks
      // of every preset. It matters more here: this text is *shown* to the
      // reader before it is loaded, and a preview in a different spelling from
      // the notebook would be a second opinion about what they are agreeing to.
      expect(canonicalCeremonyText(c.text)).toBe(c.text);
      // And every cell body round-trips on its own, which is what `setCellPeer`
      // will re-serialize each of them through.
      const chains = recipeChains(compileRecipe(c.text).ast);
      expect(serializeRecipe(chains)).toBe(c.text);
      expect(chains.map((chain) => chain.peer)).toEqual(c.cells.map((cell) => cell.peer));
    }
  });

  it("never shortens a fingerprint, in a header or in a param", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      expect(c.text).not.toContain("…");
      // Every member's whole key is in the text, and the two grammatical
      // positions a peer appears in both carry all forty characters. A prefix
      // would still work at run time, which is exactly why it is worth pinning
      // that nothing shortened one.
      for (const member of room(n)) expect(c.text).toContain(member);
      // Every run of hex long enough to be a key id is a whole key. Asserted
      // over the text rather than per member, because the failure this guards
      // against is a *serializer* shortening one, and a check that looked for
      // each member's prefix would pass on a text that had dropped a member
      // entirely.
      for (const run of c.text.match(/[0-9A-F]{16,}/g) || []) {
        expect(run, `a shortened key id is in the recipe: ${run}`).toHaveLength(40);
      }
    }
  });
});

/* ─────────────────────────── the wiring, as source ──────────────────────────
 *
 * The hook and the shell are React and this suite runs in node, so what can be
 * pinned here is that the generator has a caller and that the caller reaches the
 * notebook the way every other header-writer does. The behaviour is driven in
 * `placed-journey.e2e.js`, across two browsers, end to end.
 *
 * `ask who consumes this` is the question these three answer: a generator with
 * no press behind it would be a finished feature nobody can reach, which is the
 * state `quorum.send` itself was in until this change.
 */
describe("somebody presses it", () => {
  const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
  const SHELL = read("../toolkit/ToolkitShell.tsx");
  const PANEL = read("../toolkit/widgets/SessionStart.tsx");

  it("is generated from the draft audience and nothing else", () => {
    expect(SHELL).toMatch(/from "\.\.\/lib\/toolkit\/room-ceremony\.js"/);
    expect(SHELL).toMatch(
      /roomCeremony\(\{\s*audience: sessionDraft\.audience,\s*self: sessionDraft\.keyFingerprint,\s*\}\)/
    );
  });

  it("writes the headers through the mutator CellAssign presses", () => {
    // Bodies through the loader, headers through `setCellPeer`. No `@peer` is
    // spelled by this path, so `serializeChain` stays the only thing in the app
    // that writes one.
    const at = SHELL.indexOf("const writeRoomCeremony");
    const body = SHELL.slice(at, SHELL.indexOf("}, [draftCeremony", at));
    expect(body).toContain("nb.loadRecipeText(draftCeremony.title, bodies)");
    expect(body).toMatch(/nb\.setCellPeer\(i, c\.peer\)/);
    expect(body, "the generator's cell bodies must not carry headers").not.toContain("@");
  });

  it("hands the panel the sentences and the refusals together", () => {
    expect(SHELL).toContain("summary: roomCeremonySummary(draftCeremony)");
    expect(SHELL).toContain("issues: draftCeremony.issues");
    expect(SHELL).toContain("onWrite: writeRoomCeremony");
    // Inert through `disabledReason`, never `disabled` — the rule the whole
    // product is held to, and the one that makes a refusal readable.
    const at = PANEL.indexOf("data-room-ceremony");
    const block = PANEL.slice(at, PANEL.indexOf("<InviteCard", at));
    expect(block).toContain("disabledReason={");
    expect(block).not.toMatch(/\bdisabled=\{/);
    expect(block).toContain("data-room-ceremony-recipe");
    expect(block).toContain("aria-live=\"polite\"");
  });

  it("draws every field the generator produces, so none of them is dead weight", () => {
    // The audit question this repo keeps having to ask. `why` and `phase` are
    // written per cell by `roomCeremony`, and a field with no consumer is a
    // finished feature nobody can reach — the exact defect class the ceremony
    // verbs were in before this change.
    const at = PANEL.indexOf("data-room-ceremony");
    const block = PANEL.slice(at, PANEL.indexOf("<InviteCard", at));
    expect(block).toContain("data-room-ceremony-phase");
    expect(block).toContain("c.why");
    expect(SHELL).toContain("phase: c.phase, why: c.why");
    // Both phases are drawn, and every cell the generator writes belongs to one
    // of them — so the reading beside the recipe accounts for the whole
    // notebook rather than most of it.
    for (const n of SIZES) {
      const phases = new Set(ceremonyFor(n).cells.map((c) => c.phase));
      expect([...phases].sort()).toEqual(["deal", "recover"]);
      for (const cell of ceremonyFor(n).cells) {
        expect(cell.why.length, "a generated cell explains itself as nothing").toBeGreaterThan(
          20
        );
      }
    }
  });
});
