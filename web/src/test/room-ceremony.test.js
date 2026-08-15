/**
 * The split-key ceremony a room generates, checked against the room.
 *
 * This is the first template in the product that is a *function of the
 * audience* rather than a string, so the thing to prove is not that one recipe
 * works — it is that every recipe the product can generate works. There are
 * fifteen of them (rooms of 2 through 16), and each one has to compile, place
 * every cell on somebody, and refuse nothing, from the point of view of every
 * member in turn.
 *
 * ## The notebook is the deal and nothing else
 *
 * This file used to pin the other shape: return cells, a gather with a
 * thirty-minute wait, phase labels — a deal and its recovery in one document.
 * The dealer-absent e2e proved what that costs (`runFrom` walks to the end, so
 * the press that deals also returns the dealer's share; findings 1a and 5a),
 * and LANGUAGE.md's "two agreements, two notebooks" settled the direction:
 * recovery is generated at recovery time by `room-recovery.js`, and
 * `room-recovery.test.js` is where its properties now live. The pins below
 * that used to hold the recovery in this notebook are turned over into pins
 * that it is *absent* — a return cell or a gather reappearing here would be
 * the one-press hazard coming back.
 *
 * ## Why a generator at all
 *
 * Because the receive-cell count depends on the room, and a `@peer` header
 * addresses a whole fingerprint — `refuses the shapes a fixed template would
 * have taken` below is that claim as a test rather than as a paragraph.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  DEALER_BASED,
  DEALER_KEEPS_ONE,
  MAX_ROOM,
  NO_REDUNDANCY_AT_TWO,
  RECOVERY_IS_ITS_OWN_NOTEBOOK,
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

  it("writes one deal cell and one receive per holder, and nothing else", () => {
    // **Turned over from the eight-cell shape.** The count used to be
    // `1 + holders*2 + (n-1) + 1` — sends, receives, returns and a gather —
    // and the returns and the gather were the recovery living in the deal's
    // document, which is finding 1a's mechanism. `scatter` folded the sends
    // into the split cell, and the recovery is a separate notebook now, so a
    // room of n is exactly n cells: the deal, and n-1 deliveries.
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const members = room(n);
      const dealer = fpr(1);
      const holders = members.slice(1);
      expect(c.cells).toHaveLength(n);
      expect(c.dealer).toBe(dealer);
      expect(c.cells[0].peer).toBe(dealer);
      // The deal cell deals over the room's derivation, in the canonical
      // spelling — the destinations are in the text, and none is chosen.
      expect(c.cells[0].recipe).toContain(`sss.split ${c.threshold}/${c.shares}`);
      expect(c.cells[0].recipe).toContain("scatter to=room");
      expect(c.cells[0].recipe).toContain("send to=each | out $share");
      // Exactly one receiving cell per holder, every one on the holder.
      const receiving = c.cells.filter((cell) => cell.recipe.startsWith("quorum.recv from="));
      expect(receiving.map((cell) => cell.peer).sort()).toEqual([...holders].sort());
      expect(receiving).toHaveLength(n - 1);
      for (const cell of receiving) expect(cell.recipe).toContain(`from=${dealer}`);
    }
  });

  it("contains no recovery — no return cell, no gather, no armed wait", () => {
    // **The turned-over pins of findings 1a and 5a.** The dealer's return
    // cell (`$set | at 1 | quorum.send`) is what made the deal's one press
    // also a recovery; the gather with its thirty-minute `wait=` sat armed in
    // a notebook that might not be run for years; and the phase labels named
    // a distinction no control could honour. All three are retired *by
    // absence*: recovery is `room-recovery.js`'s notebook, written at
    // recovery time by the quorum doing it. Any of these strings reappearing
    // here is the single-notebook shape coming back.
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      expect(c.text, "a gather is armed in the deal notebook").not.toContain("sss.combine");
      expect(c.text, "a recovery wait is armed in the deal notebook").not.toContain("wait=");
      expect(c.text, "a cell selects a share back out of a set").not.toMatch(
        /\bat \d+\b|\[\d+\]/
      );
      for (const cell of c.cells) {
        expect(cell, "a cell carries a phase — the labels are retired").not.toHaveProperty(
          "phase"
        );
      }
      // And the object no longer nominates a recoverer: who recombines is
      // decided by whoever actually recovers, when they do.
      expect(c).not.toHaveProperty("recoverer");
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
    // colliding them is not. The dealer's own `$share` is in the count: it is
    // a slot like the others and must collide with nothing.
    const c = ceremonyFor(4);
    const outs = [...c.text.matchAll(/\bout \$([\w-]+)/g)].map((m) => m[1]);
    expect(new Set(outs).size, `two cells write the same slot: ${outs.join(", ")}`).toBe(
      outs.length
    );
  });

  it("numbers each holder's slot by the pairing that will fill it", () => {
    // **Finding 5b, carried into the scatter shape.** `scatter` deals share i
    // to member i in canonical audience order — sorted, derived, chosen by
    // nobody — so the receive slot on the member at canonical position i must
    // say i, or a person comparing a slot against a printed card that says
    // "share 3 of 3" cannot tell whether they were dealt the wrong one. The
    // test fingerprints sort in list order, so position is index + 1.
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const members = room(n);
      for (const cell of c.cells.slice(1)) {
        const pos = members.indexOf(cell.peer) + 1;
        expect(
          cell.recipe,
          `${cell.peer} (position ${pos}) receives into the wrong slot`
        ).toContain(`out $share-${pos}`);
        expect(cell.why).toContain(`share ${pos}`);
      }
      // The dealer's own number appears nowhere: their share is the unnumbered
      // `$share` the deal cell binds — the one share that was never received —
      // and the dealer is position 1 here.
      expect(c.text, "a slot was numbered for the dealer's own share").not.toMatch(
        /\$share-1\b/
      );
    }
  });

  it("keeps exactly one share on the dealer — the revealable $set is unconstructable", () => {
    // **Finding 4a, turned over.** The dealer used to keep every share in a
    // revealable `$set` with nothing on any screen saying to delete it — a
    // 2-of-3 that was a 1-of-1 until somebody remembered. Under the pair-aware
    // form the shares flow through the scatter body without stopping: the
    // delivered pairs' pipes end at `send`, and the one `out` in the body
    // binds the single pair that stays, this machine's own. No slot in the
    // text can hold the set, because no step in the text retains it.
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      expect(c.text, "the whole set reached a slot").not.toContain("$set");
      const dealt = c.cells[0].recipe;
      // The only outs on the deal cell are the digest and the dealer's own
      // share — asserted as the exact list so a third `out` has to argue here.
      expect([...dealt.matchAll(/\bout \$([\w-]+)/g)].map((m) => m[1])).toEqual([
        "expected",
        "share",
      ]);
    }
    // And the picker says the property out loud, as this module's own copy.
    expect(roomCeremonySummary(ceremonyFor(3))).toContain(DEALER_KEEPS_ONE);
    expect(DEALER_KEEPS_ONE).toContain("exactly one share");
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
    // `setCellPeer` rewrites headers, and `from=` is not a header. So
    // resolution-after-the-fact has nothing to resolve with, and the audience
    // has to come first.
    //
    // `foreach` is the other half of the argument: it declares no params, so it
    // cannot be handed a different recipient per round however the loop is
    // written. `scatter` is that loop *with* the recipient — derived from the
    // room, never written — which is exactly why the deal collapsed into it.
    const spec = getStep("foreach");
    expect(spec.params ?? []).toEqual([]);
  });

  it("still binds a label whatever the value carries — the registry divert stays gone", () => {
    // The finding that cost a two-browser run, kept pinned at the registry:
    // `register` used to divert any share-stamped value into `slotsByIndex`
    // and return before `slotsByLabel.set`, so an `out` reported ok and the
    // next cell failed with "unknown slot", naming a remedy already performed.
    // The deal cell's `out $share` binds a share-stamped value on every run
    // now, so this pin matters more than it did, not less.
    const registry = createSlotRegistry();
    registry.register("$share", { type: "text", data: "one share", meta: { shareIndex: 1 } });
    expect(registry.resolve("$share").data).toBe("one share");
    registry.register("$plain", { type: "text", data: "not a share", meta: {} });
    expect(registry.resolve("$plain").data).toBe("not a share");
  });
});

describe("the secret, and what is written down about it", () => {
  it("never writes the master to a slot on any machine", () => {
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      const split = c.cells[0];
      // The 32 bytes go from `random` into `sss.split` and are never named:
      // no slot, no tile, no receipt entry holds them. Only the digest is
      // written down, so a recovery can be checked without showing the secret.
      expect(split.recipe).toContain("random 32 | tee");
      expect(split.recipe).toContain("digest sha-256 | encode hex | out $expected");
      // Never `publish`: a value leaves this machine because a verb said so,
      // and the verb is `send to=each`, addressed by the derived pairing.
      expect(c.text).not.toContain("publish");
    }
  });

  it("carries the quorum in the text, where two peers will digest it", () => {
    // `ade4043`: `sss.split threshold=2 shares=3` used to round-trip to bare
    // `sss.split`, so the security property was absent from what the two ends
    // compare. A generated notebook is the case where that would be least
    // visible, since nobody typed the numbers. The canonical spelling is the
    // verb's object now (`sss.split 2/3`); the property pinned is unchanged —
    // both numbers are in the text the two ends digest.
    for (const n of SIZES) {
      const c = ceremonyFor(n);
      expect(c.text).toContain(`sss.split ${c.threshold}/${c.shares}`);
    }
  });

  it("says it is a dealer-based split, and that recovery is its own notebook", () => {
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
    // The two-notebooks sentence is on the panel where the deal is offered:
    // a reader who writes the deal must not go looking for the recovery cells
    // the old shape taught them to expect.
    expect(summary).toContain(RECOVERY_IS_ITS_OWN_NOTEBOOK);
    expect(RECOVERY_IS_ITS_OWN_NOTEBOOK).toContain("separate agreement");
    expect(RECOVERY_IS_ITS_OWN_NOTEBOOK).toContain("header");
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
 * the ceremony e2e suites, across real browsers, end to end.
 *
 * `ask who consumes this` is the question these answer: a generator with no
 * press behind it would be a finished feature nobody can reach, which is the
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

  it("draws each cell's why, and no phase — the labels one press cannot honour are gone", () => {
    // **Finding 5a's UI half, turned over.** The panel printed "Dealing — run
    // once, together" and "Recovering — run when the secret is wanted back"
    // over one contiguous run — doctrine with no mechanism. The deal notebook
    // has one occasion now, so there is nothing to phase: the panel draws the
    // per-cell `why` lines and must not grow the labels back without a
    // control that can honour them.
    const at = PANEL.indexOf("data-room-ceremony");
    const block = PANEL.slice(at, PANEL.indexOf("<InviteCard", at));
    expect(block).toContain("c.why");
    expect(block).not.toContain("data-room-ceremony-phase");
    expect(block).not.toContain("Recovering — run when the secret is wanted back");
    expect(SHELL).not.toContain("phase: c.phase");
    for (const n of SIZES) {
      for (const cell of ceremonyFor(n).cells) {
        expect(cell.why.length, "a generated cell explains itself as nothing").toBeGreaterThan(
          20
        );
      }
    }
  });
});
