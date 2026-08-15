/**
 * Serializing a recipe must produce text that parses back.
 *
 * `serializeStep` is not a debug convenience — the chip flow re-serializes on
 * every mutation and "Copy link" serializes to build the share URL. So a value
 * that survives compiling but not the round trip does not merely look wrong:
 * editing a chip near it, or sharing the notebook, hands back text that will
 * not parse.
 *
 * The sweep below is the real test. `file.read accept=.pem` was the op's *own
 * documented example* and it round-tripped to `Unexpected "."` — nothing
 * checked that the examples we ship to users actually survive, so a whole class
 * of positional-quoting bugs had no gate. Asserting over the registry's own
 * `Example:` strings means the next op to add one is covered the day it lands.
 */
import { describe, expect, it } from "vitest";
import { PRESETS, compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { STEPS } from "../lib/toolkit/registry.js";
import {
  TOOLKIT_HASH_MAX_LEN,
  compactRecipeText,
  decodeSharePayload,
  encodeSharePayload,
  expandShareRecipe,
  hashForRecipe,
} from "../lib/toolkit/fragment.js";

/**
 * Serialize twice. The second pass's text is the fixed point, when there is one.
 *
 * The property both blocks at the bottom of this file are about is stronger
 * than "it parses back": **serialize ∘ parse is idempotent**. Anything that
 * moves on the *second* pass moves on every pass, so it drifts a little each
 * time a chip is clicked or a link is opened, and two peers who reached the
 * same notebook by different routes hold two different texts.
 * @param {string} src
 */
const settle = (src) => {
  const once = compileRecipe(src);
  expect(once.validation.errors, `fixture should compile: ${src}`).toEqual([]);
  const first = serializeRecipe(once.ast);
  const again = compileRecipe(first);
  expect(again.validation.errors, `serialized text should compile: ${first}`).toEqual([]);
  return { first, second: serializeRecipe(again.ast) };
};

/** Compile → serialize → compile, returning the second pass's errors. */
const roundTrip = (src) => {
  const first = compileRecipe(src);
  expect(first.validation.errors, `fixture should compile: ${src}`).toEqual([]);
  const text = serializeRecipe({ chains: first.ast.chains });
  return { text, errors: compileRecipe(text).validation.errors.map((e) => e.message) };
};

/** The `Example: \`…\`` recipe out of an op's doc string, when it has one. */
const exampleOf = (spec) => {
  const m = /Example:\s*`([^`]+)`/.exec(String(spec.doc || ""));
  return m ? m[1].trim() : null;
};

/**
 * Only the examples that stand alone.
 *
 * Roughly half are deliberately fragments — `input | ssh.sign key=$id` names a
 * slot an earlier cell registers, and `hkp.filter` continues a search. Those
 * cannot compile by themselves, and *making* them compile would mean rewriting
 * doc strings to suit a test, which is the tail wagging the dog. The round trip
 * is a property of serialization, so the self-contained half exercises it just
 * as well.
 */
const standalone = STEPS.map((s) => [s.name, exampleOf(s)])
  .filter(([, ex]) => ex)
  .filter(([, ex]) => {
    try {
      return compileRecipe(ex).validation.errors.length === 0;
    } catch {
      return false;
    }
  });

describe("every self-contained documented Example: survives a round trip", () => {
  it("finds examples to check, so the sweep cannot pass by being empty", () => {
    // A floor, not the exact count: ops get added, and a sweep that has to be
    // re-pinned on every addition gets re-pinned without being read.
    expect(standalone.length).toBeGreaterThan(20);
  });

  for (const [name, src] of standalone) {
    it(`${name}: ${src}`, () => {
      const { text, errors } = roundTrip(src);
      expect(errors, `re-parsing \`${text}\` failed`).toEqual([]);
    });
  }
});

describe("a positional value the parser cannot read bare is quoted", () => {
  it("keeps file.read accept=.pem parseable — the reported case", () => {
    const { text, errors } = roundTrip("file.read accept=.pem | inspect");
    expect(text).toContain('".pem"');
    expect(errors).toEqual([]);
  });

  it("leaves ordinary positionals unquoted, so recipes stay readable", () => {
    // The fix must not quote everything: `genkey ec/p256` reads as itself, and
    // turning it into `genkey "ec/p256"` would churn every saved recipe and
    // every share link for no gain.
    const { text } = roundTrip("genkey ec/p256 | export pkcs8 | pem");
    expect(text).toContain("genkey ec/p256");
    expect(text).not.toContain('"ec/p256"');
  });

  it("still quotes for whitespace, pipe and =, as it did before", () => {
    const { text, errors } = roundTrip('hkp.search "john doe"');
    expect(text).toContain('"john doe"');
    expect(errors).toEqual([]);
  });

  it("quotes a delimiter in the middle of an otherwise ordinary value", () => {
    // The shipped blocker. Every fixture above that contained a comma also
    // *began* with a character the leading-character rule already quoted for
    // (`.p12,.pfx`), so the comma was never the thing being tested — the value
    // was rescued on the way in and the middle of it was never exercised. A
    // value starting with a letter or digit takes the bare path, and the comma
    // then ends the token and leaves the rest where the grammar wants a new
    // argument: `Unexpected "," · Unexpected "<next>"`.
    for (const v of ["a,b", "9F2A,D772", "one,two,three"]) {
      const { text, errors } = roundTrip(`hkp.search ${JSON.stringify(v)}`);
      expect(text, `${v} serialized bare`).toContain(JSON.stringify(v));
      expect(errors, `${v} round-tripped to ${text}`).toEqual([]);
    }
  });

  it("decides by the parser's alphabet, not by a list of known-bad characters", () => {
    // The predicate this replaced was a denylist and had been patched twice —
    // once for space/pipe/`=`, once for the leading character — and still had
    // no comma in it. Sweeping every ASCII punctuation mark is the only way to
    // assert the *rule* rather than the last three symptoms of breaking it.
    const bad = [];
    for (let c = 0x21; c < 0x7f; c += 1) {
      const ch = String.fromCharCode(c);
      const v = `a${ch}b`;
      // The fixture has to be spellable before the round trip means anything.
      // `readString` implements no escape, so a value holding *both* quote
      // characters cannot be written in this grammar at all — `quoteArg` picks
      // the quote the value does not contain, which covers each one alone. The
      // both-at-once case is a missing language feature, named in `quoteArg`,
      // and it is excluded here rather than silently passing.
      const src = `hkp.search ${ch === '"' ? `'${v}'` : JSON.stringify(v)}`;
      if (compileRecipe(src).validation.errors.length) {
        bad.push(`fixture unspellable: ${src}`);
        continue;
      }
      const { text, errors } = roundTrip(src);
      if (errors.length) bad.push(`${JSON.stringify(v)} -> ${text}: ${errors.join(" · ")}`);
    }
    expect(bad).toEqual([]);
  });

  it("spells an embedded double quote with the other quote", () => {
    // `JSON.stringify` emitted `\"`, and `readString` scans to the next quote
    // rather than honouring an escape — so the value came back cut at the
    // backslash with the rest left as loose tokens.
    const { text, errors } = roundTrip(`hkp.search 'say "hi"'`);
    expect(text).toContain(`'say "hi"'`);
    expect(errors).toEqual([]);
  });

  it("covers the whole class, not just a leading dot", () => {
    // Asserted through the parser rather than against a character blacklist:
    // the rule is "the argument loop dispatches on letter, digit or @", and a
    // blacklist would miss the next character nobody thought of.
    for (const accept of [".pem", ".p12,.pfx", "-weird", "+plus"]) {
      const { text, errors } = roundTrip(`file.read accept=${JSON.stringify(accept)}`);
      expect(errors, `accept=${accept} round-tripped to ${text}`).toEqual([]);
    }
  });
});

/* ─────────────────────────── the compact form ───────────────────────────── */

/**
 * The compact form is the one that travels.
 *
 * `hashForRecipe` is the only production caller of `serializeRecipe(…, {
 * compact: true })`, through `compactRecipeText`, and it is what "Copy link"
 * puts in a `#r=` fragment. So a compact spelling that does not parse back is
 * not a cosmetic defect: a person shares a notebook that was fine, and the
 * recipient opens a parse error.
 *
 * It was one, for every notebook containing a `tee` or `foreach` body of more
 * than one step. The one-line brace form joined the body's items with a space
 * — `tee{ - digest sha-256 - encode hex - out $a }` — and a step's argument
 * loop runs to `|`, `}`, `#` or end of line, so it swallowed the `-` that was
 * meant to start the next item. `aes-gcm -d` is why the parser cannot simply
 * stop at a hyphen: a leading `-` is a real argument token.
 *
 * The sweep below is the guard. It is over `PRESETS` rather than over a fixture
 * list because the presets are the shapes we ship and the ones a person is
 * most likely to press Copy link on — and because the defect went unnoticed for
 * exactly as long as nothing swept them.
 */
/**
 * Compact → encode → decode → expand: the path a shared notebook actually
 * takes, and the only one worth asserting. `~` is the compact chain separator
 * and the *parser* has never known about it — `expandShareRecipe` turns it back
 * into a blank line — so a sweep that compiled the compact text directly would
 * fail on every multi-cell preset for a reason no user can hit.
 * @param {string} src
 */
const throughLink = (src) =>
  expandShareRecipe(decodeSharePayload(encodeSharePayload(compactRecipeText(src))));

describe("every preset survives the compact round trip", () => {
  const compiled = PRESETS.map((p) => [p.id, p.recipe, compileRecipe(p.recipe)])
    .filter(([, , c]) => c.validation.ok);

  it("finds presets to check, so the sweep cannot pass by being empty", () => {
    expect(compiled.length).toBeGreaterThan(20);
  });

  it("includes presets with nested bodies, which is the shape that broke", () => {
    const nested = compiled.filter(([, recipe]) => /\n\s*-\s/.test(String(recipe)));
    expect(nested.length).toBeGreaterThan(5);
  });

  for (const [id, recipe] of compiled) {
    it(`${id} re-parses from its compact spelling`, () => {
      const text = throughLink(recipe);
      const back = compileRecipe(text);
      expect(
        back.validation.errors.map((e) => e.message),
        `compact spelling of ${id} did not parse:\n${text}`
      ).toEqual([]);
      // …and says the same thing. A form that parsed to a *different* pipeline
      // would pass the check above and still lose the recipe.
      expect(serializeRecipe(back.ast), id).toBe(
        serializeRecipe(compileRecipe(recipe).ast)
      );
    });
  }
});

describe("a compact payload survives the `#r=` link it exists for", () => {
  it("keeps a multi-cell notebook multi-cell", () => {
    // The chain separator and the body form interact: `expandShareRecipe`
    // reads a payload with no raw newline as `~`-separated and one with
    // newlines as already blank-line separated. A notebook whose body cannot
    // be flattened onto one line has to pick the second, or its cells merge.
    const src =
      "genkey ec/p256 | tee\n  - :public | export spki | pem | out $pub\n  - :private | export pkcs8 | out $priv\n\nin $pub | inspect";
    const back = compileRecipe(throughLink(src));
    expect(back.validation.errors).toEqual([]);
    expect(back.ast.chains).toHaveLength(2);
    expect(serializeRecipe(back.ast)).toBe(serializeRecipe(compileRecipe(src).ast));
  });

  it("hands back a cell that digests as the one that was shared", () => {
    // The reason the compact form stopped re-spelling bodies, rather than only
    // stopping where it failed to parse. `serializeRecipe({ chains: [chain] })`
    // is what `handoff.js` digests a cell with, and what a manifest records —
    // so two spellings of one body are two digests, and two peers holding the
    // same notebook by different routes refuse each other with `cell-mismatch`.
    const brace = "random 32 | foreach { - out $share }";
    const indent = "random 32 | foreach\n  - out $share";
    const cellText = (src) =>
      serializeRecipe({ chains: [compileRecipe(src).ast.chains[0]] });
    // The two spellings genuinely differ, which is what makes the trip matter.
    expect(cellText(brace)).not.toBe(cellText(indent));
    for (const src of [brace, indent]) {
      expect(cellText(throughLink(src)), src).toBe(cellText(src));
    }
  });

  it("still uses `~` when every cell fits on one line", () => {
    // The short spelling is the point of the compact form, and the notebooks
    // that can use it are the majority. Losing it for every recipe would be a
    // fix that cost more than the bug.
    const compact = compactRecipeText("random 32 | out $a\n\nin $a | encode hex");
    expect(compact).toContain("~");
    expect(compact).not.toContain("\n");
  });

  it("costs length, and the budget says how much is left", () => {
    // Keeping a body's own form makes some links longer, which is the whole
    // price of the fix and the number worth watching. Two ceilings: the
    // fragment budget `hashForRecipe` enforces, and the 2953 bytes a QR holds
    // — `ShareSheet` falls back to a file above it, so exceeding it is a
    // different flow rather than a failure, but it is still a cliff.
    const lengths = PRESETS.map((p) => [p.id, hashForRecipe(p.recipe)])
      .filter(([, h]) => h.ok)
      .map(([id, h]) => [String(id), h.hash.length]);
    expect(lengths.length).toBeGreaterThan(20);
    const worst = lengths.reduce((a, b) => (b[1] > a[1] ? b : a));
    // A ceiling with room in it, not the exact number — re-pinning this on
    // every preset that gets added is how a budget check stops being read.
    expect(worst[1], `longest preset link is ${worst[0]}`).toBeLessThan(1000);
    expect(worst[1]).toBeLessThan(TOOLKIT_HASH_MAX_LEN);
  });

  it("is never longer than the pretty text it came from", () => {
    // The property that says compact is still doing its job. It is not a
    // tautology once a body stops being flattened: what is left of the
    // minification is the stem, and this asserts the stem still pays for the
    // newlines the body keeps.
    for (const p of PRESETS) {
      const c = compileRecipe(p.recipe);
      if (!c.validation.ok) continue;
      const compact = compactRecipeText(p.recipe);
      expect(compact.length, p.id).toBeLessThanOrEqual(serializeRecipe(c.ast).length);
    }
  });
});

/* ──────────────────────────── comments survive ───────────────────────────── */

/**
 * A recipe travels to somebody who did not write it — over a wire since
 * `a47f630`, and in a link before that. The `#` comment is the one feature
 * aimed squarely at that reader, and `serializeRecipe` destroyed it at exactly
 * the moment the recipe left: `# deal 2-of-3 to the room` parsed, compiled,
 * ran, and was gone from every copy anybody else saw.
 *
 * A comment attaches to the **cell**, which is the unit everything else here
 * already uses, and comes back as full lines at the top of it. The assertions
 * are on that rule and on idempotence, not on where in a cell a comment
 * happened to be typed — `serializeChainSteps` collapses a multi-line stem into
 * one line, so there is no line inside a cell for a comment to sit above, and
 * "it comes back exactly where it was" is a property this grammar cannot have.
 */
describe("a comment survives serialization", () => {
  it("keeps the comment the reported case lost", () => {
    const { first } = settle(
      "# deal 2-of-3 to the room\nrandom 32 | sss.split threshold=2 shares=3 | out $set"
    );
    expect(first).toContain("# deal 2-of-3 to the room");
  });

  it("promotes a trailing comment instead of dropping it", () => {
    // `random 32 | out $a  # keep` parses today and lost the comment. It comes
    // back as a line of its own: the cell is the unit, so a comment written at
    // the end of a step line is the same cell's comment as one written above
    // it, and there is one spelling for both.
    const { first } = settle("random 32 | out $a  # keep");
    expect(first).toBe("# keep\nrandom 32 | out $a");
  });

  it("keeps each cell's comment with that cell", () => {
    const { first } = settle(
      "# first\nrandom 32 | out $a\n\n# second\n$a | encode hex | out $b"
    );
    expect(first.split(/\n\s*\n/)).toEqual([
      "# first\nrandom 32 | out $a",
      "# second\n$a | encode hex | out $b",
    ]);
  });

  it("puts a cell's comment above its header, not between header and steps", () => {
    // The header is the subject of the sentence the comment introduces, and a
    // comment between the two would separate the header from the pipeline it
    // heads. It also has to stay parseable: `@peer` is only read at the head of
    // a chain, and a comment line does not end one.
    const { first } = settle("@mara\n# who gets what\nrandom 32 | out $a | publish");
    expect(first).toBe("# who gets what\n@mara\nrandom 32 | out $a | publish");
  });

  it("is idempotent for every place a comment can be written", () => {
    // Idempotence is the property; the list is the grammar's comment positions.
    // A comment inside a body is hoisted to the top of its cell on the first
    // pass and stays put on every pass after — which is what makes "hoisted" a
    // normalisation rather than a drift.
    const forms = [
      "# above\nrandom 32 | out $a",
      "random 32 | out $a # trailing",
      "random 32 | out $a\n# between the stem and the end\n| encode hex",
      "genkey ec/p256 | tee\n  # inside an indent body\n  - :public | export spki | pem | out $pub\n| export pkcs8 | pem | out $priv",
      "random 32 | sss.split | blip39 | foreach { # inside a brace body\n  - out $share }",
      "#no space after the hash\nrandom 32 | out $a",
      "random 32 | out $a\n\n# after the last cell",
    ];
    for (const src of forms) {
      const { first, second } = settle(src);
      expect(second, `not a fixed point: ${src}`).toBe(first);
      expect(first, `comment lost: ${src}`).toMatch(/^#/m);
    }
  });

  it("carries the comment through the `#r=` link, because the digest does", () => {
    // Dropping comments from the compact form would be cheaper in URL
    // characters and would reintroduce the defect one layer down: a cell that
    // came back from a link without its comment digests differently from the
    // cell that was shared, which is the `cell-mismatch` two peers refuse each
    // other with. The `~` chain separator gives way to a blank line here, which
    // `expandShareRecipe` already reads correctly.
    const src =
      "# a note for whoever opens this\nrandom 32 | out $a\n\n$a | encode hex | out $b";
    const back = compileRecipe(throughLink(src));
    expect(back.validation.errors).toEqual([]);
    expect(back.ast.chains).toHaveLength(2);
    expect(serializeRecipe(back.ast)).toBe(serializeRecipe(compileRecipe(src).ast));
    expect(serializeRecipe(back.ast)).toContain("# a note for whoever opens this");
  });

  it("changes the cell digest, which is the behavioural decision this makes", () => {
    // Not a side effect. Two peers compare `serializeRecipe({ chains: [chain] })`
    // per cell and digest the whole source into the manifest, so once comments
    // survive, two notebooks differing only in a comment are two agreements and
    // every offer between them is refused. That is right — the text is the
    // agreement, and a comment is part of what a person read before agreeing —
    // but it is a change in what "the same notebook" means, so it is pinned
    // here rather than left to be met as a `cell-mismatch` in the field.
    const cellText = (src) =>
      serializeRecipe({ chains: [compileRecipe(src).ast.chains[0]] });
    expect(cellText("# mine\nrandom 32 | out $a")).not.toBe(
      cellText("# yours\nrandom 32 | out $a")
    );
    expect(cellText("random 32 | out $a")).toBe(cellText("random 32 | out $a"));
  });
});

/* ─────────────────────── the quorum is in the text ───────────────────────── */

/**
 * `sss.split threshold=2 shares=3` serialized to bare `sss.split`, because
 * `serializeStep` drops a named param equal to its default. The quorum — the
 * whole security property — was therefore absent from the text a reader reads,
 * from the text two peers compare, and from the manifest they digest, and a
 * 2-of-3 and a 2-of-16 were the same recipe with only the second written down.
 *
 * `serialize: "always"` was the narrow half of `LANGUAGE.md`'s principle 4;
 * the designed half is now in: **the quorum is the verb's object**, and
 * `sss.split`'s canonical spelling is the fraction (`sss.split 2/3`), where
 * neither number can be defaulted away at all. The assertions below stay on
 * the *property* — the numbers are in the text, and every spelling of the
 * same split converges on one text — with the canonical characters pinned per
 * verb, because the two verbs now spell it differently: `vss.split` keeps the
 * named pair until the fraction is argued for it too.
 */
describe("a split's quorum is in the text it serializes to", () => {
  it("writes K and N even when both are the registry's defaults", () => {
    const sss = settle("random 32 | sss.split threshold=2 shares=3 | out $set");
    expect(sss.first).toContain("sss.split 2/3");
    const vss = settle("random 32 | vss.split threshold=2 shares=3 | out $set");
    expect(vss.first).toContain("vss.split threshold=2 shares=3");
  });

  it("converges: every spelling of one split serializes to one text", () => {
    // The property principle 5 claims. The abbreviated forms — defaults left
    // off, or the majority form `sss.split 3` — are input forms only; the
    // canonical text is complete, so every spelling of the same split must
    // land on the same characters — a stronger assertion than each of them
    // merely surviving.
    const spellings = [
      "random 32 | sss.split | out $set",
      "random 32 | sss.split threshold=2 | out $set",
      "random 32 | sss.split shares=3 | out $set",
      "random 32 | sss.split threshold=2 shares=3 | out $set",
      "random 32 | sss.split 2/3 | out $set",
      "random 32 | sss.split 3 | out $set",
    ].map((src) => settle(src).first);
    expect(new Set(spellings).size, JSON.stringify(spellings)).toBe(1);
    expect(spellings[0]).toContain("sss.split 2/3");

    const vss = [
      "random 32 | vss.split | out $set",
      "random 32 | vss.split threshold=2 | out $set",
      "random 32 | vss.split shares=3 | out $set",
      "random 32 | vss.split threshold=2 shares=3 | out $set",
    ].map((src) => settle(src).first);
    expect(new Set(vss).size, JSON.stringify(vss)).toBe(1);
    expect(vss[0]).toContain("threshold=2 shares=3");
  });

  it("says how many participants a dkg.run needs to reconstruct", () => {
    // Same argument, different verb: `threshold` is what any of the room can
    // later use to rebuild the group key, so it is the one number a participant
    // is agreeing to when they join.
    const { first } = settle("dkg.run threshold=2 | out $dkg");
    expect(first).toContain("dkg.run threshold=2");
  });

  it("leaves an inert default droppable, so the text does not fill with noise", () => {
    // The counterweight, and the reason this was not swept across the registry.
    // `verify soft=false` and `aes-gcm tagLength=128` are the safe end of a
    // binary and a maximum: the value that differs from them always serializes
    // already, so absence is not hiding a choice anybody made. Writing them out
    // would cost every recipe readability and buy nothing.
    const { first } = settle(
      'genkey aes/256 | out $k\n\n"hi" | utf8 | aes-gcm key=$k | out $ct'
    );
    expect(first).not.toContain("tagLength");
    expect(first).not.toContain("soft=");
  });

  it("keeps the quorum through the `#r=` link", () => {
    const src = "random 32 | sss.split threshold=2 shares=3 | out $set";
    const back = compileRecipe(throughLink(src));
    expect(back.validation.errors).toEqual([]);
    expect(serializeRecipe(back.ast)).toContain("sss.split 2/3");
  });
});
