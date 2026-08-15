/**
 * `shares` as a collector — the step that makes a delivered share spendable.
 *
 * Before this, the language had no in-recipe path from a received mnemonic back
 * to a share set. `quorum.recv count=1` emits `text/opaque`, nothing casts text
 * to `shares`, and the one spelling that *did* compile — `shares | blip39 -d |
 * sss.combine`, which is what the op's own doc recommends — was a source with
 * `input: "none"` standing mid-pipeline, so it discarded whatever was piped
 * into it without a word and then refused to run for want of a paste panel. On
 * a machine holding two shares of the split, in slots the notebook had just
 * written.
 *
 * These are the layer tests. The journey (`placed-journey.e2e.js` step 12) is
 * where the same thing is walked on a holder's screen with shares that crossed
 * a room, because a node test of the collector proves the collector and not the
 * ceremony — which is how `placed-run-arc.e2e.js` hid a defect for the whole
 * life of the product.
 */
import { describe, expect, it } from "vitest";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe, registryIssues, serializeRecipe } from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";
import { stepInputNeeds } from "../lib/toolkit/input-needs.js";
import { typeOf } from "../lib/toolkit/types.js";
import { decodeMnemonic, formatSetId } from "../lib/slip39/blip39.js";
import { combineShares } from "../lib/slip39/slip39.js";

/** Three mnemonics of one 2-of-3 split, as a run of the language produces them. */
async function deal() {
  const { ast, validation } = compileRecipe(
    "random 32 | sss.split threshold=2 shares=3 | blip39 | foreach\n  - out $share"
  );
  expect(validation.errors.map((e) => e.message)).toEqual([]);
  const arts = await runRecipe(ast);
  const shares = arts.filter((a) => a.shareIndex).map((a) => String(a.content));
  expect(shares).toHaveLength(3);
  return shares;
}

/** The hex the dealer's own shares recombine to, computed outside the engine. */
async function secretHex(mnemonics) {
  const raw = await combineShares(mnemonics);
  return Array.from(raw)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("a received mnemonic can be spent", () => {
  it("collects two shares named by slot and recovers the secret", async () => {
    const dealt = await deal();
    const want = await secretHex([dealt[1], dealt[2]]);

    // Exactly the shape a holder is left in by a room: two mnemonics that
    // arrived as text, in two named slots, and no share set anywhere. The
    // literals stand in for `quorum.recv` — the delivery itself is the
    // journey's assertion, and what is under test here is the recovery.
    const { ast, validation } = compileRecipe(
      [
        `"${dealt[1]}" | out $share`,
        `"${dealt[2]}" | out $late`,
        "$share | shares with=$late | blip39 -d | sss.combine | encode hex | out $secret",
      ].join("\n\n")
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    const arts = await runRecipe(ast);
    const secret = arts.find((a) => /secret/i.test(a.label || a.filename || ""));
    expect(secret?.content).toBe(want);
  }, 30_000);

  it("collects a bundle, which is the shape quorum.recv count= hands back", async () => {
    // `foreach` and `quorum.recv count=` build the same value — `{ type:
    // "bundle", data: { parts, count } }` with a `text` part each — so this
    // drives the collector's plural branch through the real engine without
    // standing a room up. The room's own end of it is the journey's.
    const { ast, validation } = compileRecipe(
      [
        "random 32 | sss.split threshold=2 shares=3 | blip39 | out $set",
        "$set | at 1:2 | foreach\n  - text\n| shares | blip39 -d | sss.combine | encode hex | out $secret",
      ].join("\n\n")
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    const arts = await runRecipe(ast);
    const secret = arts.find((a) => /secret/i.test(a.label || a.filename || ""));
    expect(secret?.content).toMatch(/^[0-9a-f]{64}$/);
  }, 30_000);
});

describe("the pipeline value is no longer thrown away", () => {
  it("refuses a piped value the collector cannot fold in, naming the loss", () => {
    const { validation } = compileRecipe("random 32 | shares | blip39 -d | sss.combine");
    const said = validation.errors.map((e) => e.message).join(" · ");
    expect(said, "a source in the middle of a pipeline still eats the value silently").not.toBe(
      ""
    );
    expect(said).toContain('"shares" collects text or bundle');
    // The word that matters: this used to compile, and the 32 bytes went
    // nowhere. A refusal that only said "type mismatch" would not tell a
    // reader what had been happening to their value.
    expect(said).toContain("thrown away");
  });

  it("still lets a bare `shares` head a pipeline", () => {
    const { validation } = compileRecipe("shares | blip39 -d | sss.combine | out $secret");
    expect(validation.errors.map((e) => e.message)).toEqual([]);
  });

  it("leaves every other source free to re-root a chain", () => {
    // The corpus idiom, and the reason `collects` is declared per step rather
    // than made a rule about sources: `genkey` mid-chain discards on purpose,
    // and two of the shipped templates are written that way.
    const { validation } = compileRecipe(
      "genkey aes/256 | out $kek\ngenkey aes/256 | out $cek"
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
  });
});

describe("the two new declarations are policed", () => {
  // Invented steps, not shipped ones: a check that can only be asked about ops
  // the registry already holds cannot show it would catch the next one.
  const base = {
    name: "invented",
    kind: "source",
    toolbox: "sss",
    doc: "d",
    input: "none",
    output: "shares",
    entropy: "none",
  };

  it("refuses collects on anything but a source", () => {
    expect(registryIssues([{ ...base, kind: "transform", input: "text", collects: ["text"] }])).toEqual([
      'invented: collects is for sources — a transform declares its pipeline input with input/overloads',
    ]);
  });

  it("refuses collects listing none, which is always accepted anyway", () => {
    expect(registryIssues([{ ...base, collects: ["none", "text"] }])).toEqual([
      'invented: collects must not list "none" — an empty pipe is always accepted',
    ]);
  });

  it("refuses a whenInput guard that can never lift the tray", () => {
    // The silent half of a wrong declaration: the panel simply stays, so a
    // guard omitting `none` reads as a working feature that never fires.
    expect(
      registryIssues([
        { ...base, unresolvedInputs: [{ panel: "shares", whenInput: ["text"] }] },
      ])
    ).toEqual([
      'invented: unresolvedInputs whenInput must include "none" — a step with nothing piped in has only the tray left',
    ]);
  });

  it("passes the declaration `shares` actually ships", () => {
    expect(registryIssues()).toEqual([]);
  });
});

describe("with= is checked before anything runs", () => {
  it("refuses a slot that cannot hold a mnemonic, and names what it wanted", () => {
    const { validation } = compileRecipe(
      "genkey ec/p256 | out $kp\n\nshares with=$kp | blip39 -d | sss.combine"
    );
    const said = validation.errors.map((e) => e.message).join(" · ");
    // Named for what it carries, not for the two unrelated bases the
    // declaration lists — "text or bundle" reads as a type puzzle, and the
    // reader is looking for the thing they were sent.
    expect(said).toContain("cannot supply share mnemonics");
  });

  it("survives the round trip a shared notebook makes", () => {
    // `with=` is the whole of what a recovery cell says about which values it
    // means, so a serializer that dropped it would leave the two ends digesting
    // a recipe that reads as "collect from the tray" — the language design's
    // opening complaint, one op along.
    const src = "$share | shares with=$late | blip39 -d | sss.combine | out $secret";
    const { ast } = compileRecipe(`"x" | out $share\n\n"y" | out $late\n\n${src}`);
    expect(serializeRecipe(ast)).toContain("shares with=$late");
  });

  it("refuses a slot nothing registers", () => {
    const { validation } = compileRecipe("shares with=$nowhere | blip39 -d | sss.combine");
    expect(validation.errors.map((e) => e.message).join(" · ")).toContain("unknown slot");
  });
});

describe("a mnemonic that does not decode", () => {
  it("is still the checksum's complaint, not the collector's", async () => {
    // The collector reads headers to tell shares apart, and reading a header
    // means decoding one. It must not become a second place that reports a bad
    // mnemonic: `decodeShareSet` says so in words about checksums, and moving
    // that message would move it somewhere worse.
    const { ast, validation } = compileRecipe(
      '"not a mnemonic at all" | shares | blip39 -d | sss.combine | out $secret'
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    await expect(runRecipe(ast)).rejects.toThrow(/Mnemonic too short/);
    await expect(runRecipe(ast)).rejects.not.toThrow(/^shares:/);
  }, 30_000);
});

describe("the tray is only asked for when the recipe named nothing", () => {
  const spec = getStep("shares");

  it("asks for it on a bare `shares`", () => {
    expect(stepInputNeeds({ name: "shares", params: {} }, spec, typeOf("none"))).toEqual([
      "shares",
    ]);
  });

  it("does not ask once with= names a slot", () => {
    expect(
      stepInputNeeds({ name: "shares", params: { with: "$late" } }, spec, typeOf("none"))
    ).toEqual([]);
  });

  it("does not ask once the pipe supplies one", () => {
    expect(stepInputNeeds({ name: "shares", params: {} }, spec, typeOf("text"))).toEqual([]);
    expect(stepInputNeeds({ name: "shares", params: {} }, spec, typeOf("bundle"))).toEqual([]);
  });

  it("asks when nobody said what is arriving", () => {
    // The drawer's tool card has no pipeline around it. Advertising a tray that
    // turns out to be unnecessary is the smaller error of the two.
    expect(stepInputNeeds({ name: "shares", params: {} }, spec)).toEqual(["shares"]);
  });
});

describe("two collected shares that are the same share", () => {
  it("is refused by number and by set, not by a division by zero", async () => {
    const dealt = await deal();
    const header = decodeMnemonic(dealt[1]);
    const { ast, validation } = compileRecipe(
      [
        `"${dealt[1]}" | out $share`,
        `"${dealt[1]}" | out $again`,
        "$share | shares with=$again | blip39 -d | sss.combine | out $secret",
      ].join("\n\n")
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    // The set id as `formatSetId` spells it — four upper-case hex digits —
    // rather than the raw fifteen bits. "set 969" was a number that appeared on
    // no other surface in the product, so a reader given it could not compare
    // it with the `set XXXX` the check panel prints or the one
    // `decodeShareSet`'s own refusal names.
    await expect(runRecipe(ast)).rejects.toThrow(
      new RegExp(`same share — number ${header.index} of set ${formatSetId(header.id)}`)
    );
    // Where each of them came from, because that is the only thing the reader
    // can act on: two slots, and one of them holds the wrong value.
    await expect(runRecipe(ast)).rejects.toThrow(/with=\$again/);
    // And not the message it used to be. `interpolate` divides by `xi ^ xj`,
    // zero for two copies of one point, and hands back "GF division by zero"
    // from three steps downstream — a sentence about finite fields for a
    // mistake about which slot held what.
    await expect(runRecipe(ast)).rejects.not.toThrow(/division by zero/i);
  }, 30_000);

  it("still recombines when two different shares arrive in either order", async () => {
    const dealt = await deal();
    const want = await secretHex([dealt[0], dealt[2]]);
    // The answer to `quorum.recv` matching by arrival order: a mnemonic carries
    // its own share index, so which slot caught which message cannot change the
    // secret. Both orders are driven because that is the whole claim.
    for (const [first, second] of [
      [dealt[0], dealt[2]],
      [dealt[2], dealt[0]],
    ]) {
      const { ast, validation } = compileRecipe(
        [
          `"${first}" | out $share`,
          `"${second}" | out $late`,
          "$share | shares with=$late | blip39 -d | sss.combine | encode hex | out $secret",
        ].join("\n\n")
      );
      expect(validation.errors.map((e) => e.message)).toEqual([]);
      const arts = await runRecipe(ast);
      expect(arts.find((a) => /secret/i.test(a.label || a.filename || ""))?.content).toBe(
        want
      );
    }
  }, 60_000);
});
