/**
 * `scatter` with the pair-aware `seal` / `send` (LANGUAGE.md, "`scatter` /
 * `gather` are the room's plural") — the text-level half: canonical spelling,
 * sugar convergence, the compile-time refusals, and the plan-time count check.
 *
 * What is pinned and why:
 *
 * - **The canonical text spells every destination.** `scatter to=room` /
 *   `- seal to=each` is a fixed point of `serializeRecipe`, and the bare
 *   forms (`scatter`, `seal`, `send` inside a body) are input sugar that
 *   converges on it — principle 5, the same trade `split 3` makes. A
 *   destination that survived parsing but not serialization would be a
 *   second dialect.
 * - **`room` and `each` name derivations, never people.** A fingerprint on
 *   `scatter to=` would *choose* the pairing, and the pairing must never be
 *   chosen (`peersSha` commits to the set, not the order) — while a constant
 *   fingerprint on the body's verb is legal and means every share to that
 *   one key, visibly different from `to=each` rather than differing by an
 *   absence.
 * - **`to=each` outside a scatter body refuses at compile**, naming the
 *   state that is true: there is no pair here. That covers the pair verbs
 *   themselves, the reserved words on `quorum.send` / `gpg.encrypt`, and a
 *   `foreach` body — whose item is index/share, not a member.
 * - **The count refusal is plan-time when the count is.** `sss.split K/N`
 *   keeps N in the text (`serialize: "always"`), `blip39` carries the
 *   `length` refinement, and `planRun` holds the roster — so a mismatch is
 *   refused before anything runs, naming both numbers. The run-time half
 *   lives in the engine (`scatter-deal.test.js`).
 */
import { describe, expect, it } from "vitest";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { planRun } from "../lib/toolkit/plan.js";

const FPR_A = "A1".repeat(20);
const FPR_B = "B2".repeat(20);
const FPR_C = "C3".repeat(20);

const CANONICAL = `random 32 | sss.split 2/3 | blip39.encode | scatter to=room
  - seal to=each | out $sealed | publish`;

/** Compile expecting no errors; hand back the canonical text. */
const canonical = (src) => {
  const c = compileRecipe(src);
  expect(c.validation.errors, src).toEqual([]);
  return serializeRecipe(c.ast);
};

/** Compile expecting errors; hand back their messages joined. */
const refusal = (src) => {
  const c = compileRecipe(src);
  const msgs = c.validation.errors.map((e) => e.message);
  expect(msgs.length, `expected a refusal for: ${src}`).toBeGreaterThan(0);
  return msgs.join(" ");
};

describe("canonical text and sugar convergence", () => {
  it("the canonical deal is a fixed point of serializeRecipe", () => {
    const noPublish = CANONICAL.replace(" | publish", "");
    expect(canonical(noPublish)).toBe(noPublish);
    // With the header the `publish` needs, the full canonical example holds.
    const placed = `@${FPR_A}\n${CANONICAL}`;
    expect(canonical(placed)).toBe(placed);
  });

  it("bare scatter / seal are input sugar converging on the canonical", () => {
    expect(canonical("random 32 | split 2/3 | words | scatter\n  - seal | out $sealed")).toBe(
      "random 32 | sss.split 2/3 | blip39.encode | scatter to=room\n  - seal to=each | out $sealed"
    );
  });

  it("bare send gains its pair position inside a body — sugar for send to=each", () => {
    const text = canonical("random 32 | split 2/3 | words | scatter\n  - send");
    expect(text).toContain("scatter to=room");
    expect(text).toContain("- send to=each");
    expect(text).toBe(canonical("random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - send to=each"));
  });

  it("outside a body, send is still quorum.send's narrower spelling", () => {
    expect(canonical(`"hi" | send ${FPR_A} | out $sent`)).toContain(
      `quorum.send ${FPR_A}`
    );
    expect(refusal('"hi" | send')).toContain("`send` names no recipient");
  });

  it("a constant fingerprint on the body's verb is legal and visibly different from each", () => {
    const text = canonical(
      `random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - seal to=${FPR_A} | out $x`
    );
    expect(text).toContain(`seal to=${FPR_A}`);
    expect(text).not.toContain("to=each");
  });

  it(":key / :value project the pair with foreach :items' own vocabulary", () => {
    const text = canonical(
      "random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - :value | digest sha-256 | out $d"
    );
    expect(text).toContain("- :value | digest sha-256 | out $d");
    // A payload-taking step fed the whole pair type-refuses, which is what
    // makes the projection discoverable rather than optional-and-forgotten.
    expect(
      refusal("random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - digest sha-256 | out $d")
    ).toContain("item");
  });

  it("the compact form round-trips through its own parser", () => {
    const c = compileRecipe(CANONICAL.replace(" | publish", ""));
    expect(c.validation.errors).toEqual([]);
    const compact = serializeRecipe(c.ast, { compact: true });
    const back = compileRecipe(compact);
    expect(back.validation.errors, compact).toEqual([]);
    expect(serializeRecipe(back.ast)).toBe(CANONICAL.replace(" | publish", ""));
  });
});

describe("the pair exists only where a scatter hands one", () => {
  it("seal on the stem refuses, naming the state", () => {
    expect(refusal('"hi" | seal | out $x')).toContain(
      "reads the pair a scatter hands it, and there is no scatter here"
    );
  });

  it("seal inside a foreach body refuses — that item is not a member", () => {
    expect(
      refusal("random 32 | sss.split 2/3 | blip39 | foreach\n  - seal to=each")
    ).toContain("there is no scatter here");
  });

  it("to=each on quorum.send outside a body refuses, and the remedy is the pair verb", () => {
    const msg = refusal('"hi" | quorum.send to=each');
    expect(msg).toContain("there is no scatter here");
    // The remedy must be performable: `- quorum.send to=each` would itself
    // refuse, so the sentence names `send`, the verb that reads the pair.
    expect(msg).not.toContain("- quorum.send to=each");
    expect(msg).toContain("`- send to=each");
  });

  it("to=each on gpg.encrypt refuses outside and inside a body", () => {
    expect(refusal('"hi" | gpg.encrypt to=each')).toContain(
      "there is no scatter here"
    );
    const inside = refusal(
      "random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - :value | gpg.encrypt to=each"
    );
    expect(inside).toContain("`seal`");
    expect(inside).toContain("gpg.encrypt mode=combined");
  });

  it("room is reserved in recipient position too", () => {
    expect(refusal('"hi" | gpg.encrypt to=room')).toContain("reserved word");
    expect(refusal('"hi" | quorum.send to=room')).toContain("reserved word");
  });
});

describe("scatter's own refusals", () => {
  it("to= accepts only room — a fingerprint would choose the pairing", () => {
    const msg = refusal(
      `random 32 | sss.split 2/3 | blip39 | scatter to=${FPR_A}\n  - seal to=each`
    );
    expect(msg).toContain("names a derivation, not a choice");
    expect(msg).toContain("`- seal to=<fingerprint>`");
  });

  it("a second body line refuses as foreach's does", () => {
    expect(
      refusal(
        "random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - seal to=each\n  - out $x"
      )
    ).toContain("scatter already has its body on the line above");
  });

  it("a partial fingerprint on a pair verb refuses — a suffix names more than one key", () => {
    const msg = refusal(
      "random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - seal to=AABBCCDD"
    );
    expect(msg).toContain("part of a key");
    expect(msg).toContain("whole fingerprint");
  });

  it("scatter requires a collection and a body", () => {
    expect(refusal('"hi" | scatter to=room\n  - seal to=each')).toContain(
      "scatter requires a collection"
    );
    expect(refusal("random 32 | sss.split 2/3 | blip39 | scatter to=room | out $x")).toContain(
      "scatter requires a body"
    );
  });
});

describe("the plan-time count refusal", () => {
  const deal = (quorum) => `@${FPR_A}
random 32 | sss.split ${quorum} | blip39.encode | scatter to=room
  - seal to=each | out $sealed | publish`;

  it("a statically known share count that is not the roster size refuses, naming both numbers", () => {
    const plan = planRun(compileRecipe(deal("2/3")), {
      me: FPR_A,
      roster: { [FPR_A]: FPR_A, [FPR_B]: FPR_B },
    });
    expect(plan.ok).toBe(false);
    const hit = plan.refusals.find((r) => r.reason === "scatter-count");
    expect(hit).toBeTruthy();
    expect(hit.message).toContain("3 shares");
    expect(hit.message).toContain("room of 2 members");
    expect(hit.message).toContain("canonical audience order");
  });

  it("a share count that matches the roster plans clean", () => {
    const plan = planRun(compileRecipe(deal("2/3")), {
      me: FPR_A,
      roster: { [FPR_A]: FPR_A, [FPR_B]: FPR_B, [FPR_C]: FPR_C },
    });
    expect(plan.refusals).toEqual([]);
    expect(plan.ok).toBe(true);
  });

  it("with no roster the count is the run's question, not the plan's", () => {
    // Unbound plans know nothing about the room; claiming a mismatch would
    // be inventing an audience. The engine refuses at run instead.
    const plan = planRun(compileRecipe(deal("2/3")), {});
    expect(plan.refusals.filter((r) => r.reason === "scatter-count")).toEqual([]);
  });
});

describe("output types stay statically known", () => {
  it("scatter's tip is a bundle carrying the collection's stated count", () => {
    const src = `random 32 | sss.split 2/3 | blip39 | scatter to=room
  - seal to=each | out $sealed

$sealed | out $again`;
    // `$sealed` binds once, to a bundle of every pair's value — the foreach
    // rule, reused: reading it back must compile.
    expect(canonical(src)).toContain("$sealed");
  });

  it("an out after send to=each types the slot as the value, not a bundle", () => {
    // The carve-out's compile half, with its consumer: `send to=each` retains
    // exactly one pair's payload — this machine's own share — so `$share` is a
    // mnemonic, and a later cell may pipe it into `quorum.send`. Typed as a
    // bundle (the rule for every other body out) that read-back would refuse
    // with a type mismatch, which is exactly what the recovery notebook's
    // dealer-contributor cell does with this slot on the deal's machine.
    const src = `random 32 | sss.split 2/3 | blip39 | scatter to=room
  - send to=each | out $share

$share | quorum.send ${FPR_A} | out $sent`;
    expect(canonical(src)).toContain("$share | quorum.send");
  });

  it("nothing follows a constant-recipient send — every payload left", () => {
    // `send to=<fingerprint>` delivers every pair's payload to that one key,
    // so the body pipe after it holds nothing on this machine — and a step
    // written there refuses at compile, naming the state and the spelling
    // that does retain a value. (A constant that is this session's *own* key
    // refuses at run instead: keeping every payload would rebuild the whole
    // set on one machine, the revealable-$set hazard out of a spelling.)
    const msg = refusal(
      `random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - send to=${FPR_A} | out $x`
    );
    expect(msg).toContain("Nothing follows `send to=<fingerprint>`");
    expect(msg).toContain("`send to=each` keeps this machine's own share");
  });
});
