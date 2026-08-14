/**
 * Nested list bodies (flat stem) for tee / foreach — docs/RECIPE.md.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  compileRecipe,
  parseRecipe,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

/**
 * The rule has to be legible in the normative doc, not only enforced in the
 * parser. Its absence there is what made the old behaviour an incantation:
 * `tee`'s only documented example used selectors on both lines, so a reader had
 * no way to learn that a line *without* one did something else. `\r\n` is
 * normalised because a Windows checkout rewrites the file — the same trap
 * `run-plan-differential.test.js` documents.
 */
const RECIPE_MD = readFileSync(
  fileURLToPath(new URL("../../../docs/RECIPE.md", import.meta.url)),
  "utf8"
).replace(/\r\n/g, "\n");

describe("nested list recipe syntax", () => {
  it("parses foreach indented list body", () => {
    const src = `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const fe = ast.steps.find((s) => s.name === "foreach");
    expect(fe.body?.map((b) => b.name)).toEqual(["out"]);
    expect(ast.steps.filter((s) => s.name === "out")).toHaveLength(0);
  });

  // This case used to be written over three `-` lines, and the three lines ran
  // as one pipeline because a line without a selector was concatenated into a
  // shared body. It is written on one line now for the reason the pass exists:
  // three lines are three branches, and `export spki | pem | out $public` is
  // one chain. The old spelling is pinned as three branches two tests below.
  it("parses tee body then continues stem with |", () => {
    const src = `genkey ec/p256 | tee
  - export spki | pem | out $public
| export pkcs8 | pem`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(ast.steps.map((s) => s.name)).toEqual([
      "genkey",
      "tee",
      "export",
      "pem",
    ]);
    expect(ast.steps[1].branches).toHaveLength(1);
    expect(ast.steps[1].branches[0].selector).toBeUndefined();
    expect(ast.steps[1].branches[0].body.map((b) => b.name)).toEqual([
      "export",
      "pem",
      "out",
    ]);
  });

  // The rule, stated as a count: `-` characters in, branches out. Asserted over
  // the mixed case as well, because the old parser kept selector lines and bare
  // lines in two different places and so could not have preserved their order.
  it("makes one branch of every `-` line, selector or not, in order", () => {
    const src = `genkey ec/p256 | tee
  - export spki
  - pem
  - out $public`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(
      ast.steps[1].branches.map((b) => b.body.map((s) => s.name).join("|"))
    ).toEqual(["export", "pem", "out"]);

    const mixed = parseRecipe(`genkey ec/p256 | tee
  - :public | export spki
  - inspect
  - :private | inspect`);
    expect(mixed.errors).toEqual([]);
    // Named by what each branch *starts with*, because a keypair half is a
    // step now: `- :public | export spki` and `- public | export spki` fold to
    // the same branch, running on a clone of the stem with `public` as its
    // first step. `member` is empty on all three, and the middle one is the
    // case that shows the count is still three.
    expect(
      mixed.ast.steps[1].branches.map((b) => b.body.map((x) => x.name).join("|"))
    ).toEqual(["select|export", "inspect", "select|inspect"]);
    expect(mixed.ast.steps[1].branches.map((b) => b.member)).toEqual(["", "", ""]);
  });

  // Order survives the round trip. It did not before: an unselected line lived
  // in `body` and a selector line in `branches`, and `serializeRecipe` wrote
  // every body line before every branch line — so this exact text came back
  // with its two lines swapped, and a notebook shared by link read differently
  // from the one that was written.
  it("keeps branch order through serialize", () => {
    const src = `genkey ec/p256 | tee
  - public | export spki
  - out $x`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(serializeRecipe(ast)).toBe(src);
  });

  describe("the doc shows the rule it is the normative statement of", () => {
    it("says a `-` line is a branch, in the tee section", () => {
      const tee = RECIPE_MD.slice(
        RECIPE_MD.indexOf("### `tee`"),
        RECIPE_MD.indexOf("### `foreach`")
      );
      expect(tee).toMatch(/each `-` line is one branch/i);
      // The whole defect was that the documented example only showed the
      // selector form, so the section has to show the other one too.
      expect(tee).toMatch(/^\s*- encode hex \| out \$hex$/m);
    });

    it("shows a foreach body as one line and says why", () => {
      const fe = RECIPE_MD.slice(
        RECIPE_MD.indexOf("### `foreach`"),
        RECIPE_MD.indexOf("### `peek`")
      );
      expect(fe).toMatch(/one.{0,4}`- ` line/i);
    });

    // Each `-` line in every `tee` fence is a whole pipeline, because that is
    // now what one is. A fence that split a chain over lines would be teaching
    // the reader the thing the parser stopped doing — and a fence is what gets
    // copied.
    it("never splits a branch across `-` lines in any fence", () => {
      const fences = [...RECIPE_MD.matchAll(/```[a-z]*\n([\s\S]*?)```/g)].map(
        (m) => m[1]
      );
      expect(fences.length).toBeGreaterThan(5);
      for (const f of fences) {
        if (!/\btee\b/.test(f)) continue;
        for (const line of f.split("\n")) {
          const m = /^\s+- (.+)$/.exec(line);
          if (!m || m[1].startsWith("#")) continue;
          // A branch line ends in something that emits or inspects; a bare
          // fragment like `- pem` is a chain that lost its neighbours.
          expect(m[1], `fence branch line: ${line}`).toMatch(
            /\b(out|inspect|qr|publish|peek)\b/
          );
        }
      }
    });
  });

  it("parses brace tee body", () => {
    const src = `genkey ec/p256 | tee {
  - private | inspect
  - public | export spki | out $pub
} | export pkcs8 | pem`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const tee = ast.steps.find((s) => s.name === "tee");
    expect(tee.bodyForm).toBe("brace");
    expect(
      tee.branches?.map((b) => String(b.body[0].params.selector))
    ).toEqual([":private", ":public"]);
  });

  // The compact `#r=` form folds a brace body onto one line, and that fold is
  // the concatenation bug spelled backwards: `tee{ - a|b }` is one branch, so
  // two lines must not be folded into it. This is what a shared link carries.
  it("never folds two branches onto one compact line", () => {
    const two = parseRecipe(`random 32 | tee {
  - encode hex | out $hex
  - digest sha-256 | out $digest
}`);
    expect(two.errors).toEqual([]);
    const compact = serializeRecipe(two.ast, { compact: true });
    expect(compact).toContain("\n");
    const back = parseRecipe(compact);
    expect(back.errors).toEqual([]);
    expect(back.ast.steps[1].branches).toHaveLength(2);

    const one = parseRecipe(`random 32 | tee { - encode hex | out $hex }`);
    expect(one.errors).toEqual([]);
    expect(serializeRecipe(one.ast, { compact: true })).toBe(
      "random 32|tee{ - encode hex|out $hex }"
    );
  });

  // parse → serialize → parse → serialize, over the shapes this pass touches.
  // `c33bc16` made this the property that matters, and the branch/body split is
  // exactly where a serializer can lose or invent a `-`.
  it.each([
    "genkey ec/p256 | tee\n  - :public | export spki | pem | out $public\n| export pkcs8 | pem | out $private",
    "random 32 | tee\n  - encode hex | out $hex\n  - digest sha-256 | out $digest\n| base64 | out $secret",
    "random 32 | tee\n  - :public | inspect auto\n  - encode hex | out $hex",
    "random 32 | tee {\n  - encode hex | out $hex\n  - digest sha-256 | out $digest\n}",
    "random 16 | sss.split threshold=2 shares=3 | blip39 | foreach :items\n  - :value | encode hex | out $share",
  ])("is a serialize fixed point: %s", (src) => {
    for (const opts of [{}, { compact: true }]) {
      const once = serializeRecipe(parseRecipe(src).ast, opts);
      const twice = serializeRecipe(parseRecipe(once).ast, opts);
      expect(twice).toBe(once);
      expect(parseRecipe(once).errors).toEqual([]);
    }
  });

  // `foreach` is the one block where a `-` line is not a branch, because the
  // loop has nowhere to fan out to: the item's value threads through the body
  // and comes back. So a second line is refused rather than concatenated —
  // the alternative would be `tee`'s old silence under a different keyword.
  describe("a foreach body is one line", () => {
    it("refuses a second `- ` line and says a body is already there", () => {
      const { errors } = parseRecipe(
        `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach
  - inspect
  - out $share`
      );
      const msg = errors.map((e) => e.message).join(" | ");
      expect(msg).toMatch(/foreach already has its body/i);
      // The remedy has to be one the author can carry out on the text in front
      // of them — the refusal names `|`, and `|` is what the parser accepts.
      expect(msg).toMatch(/join the steps with/i);
      const joined = parseRecipe(
        `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach
  - inspect | out $share`
      );
      expect(joined.errors).toEqual([]);
      expect(
        joined.ast.steps.find((s) => s.name === "foreach").body.map((s) => s.name)
      ).toEqual(["inspect", "out"]);
    });

    it("serializes a multi-step loop body onto one line", () => {
      const src = `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach
  - inspect | out $share`;
      const { ast, errors } = parseRecipe(src);
      expect(errors).toEqual([]);
      expect(serializeRecipe(ast).split("\n").slice(1)).toEqual([
        "  - inspect auto | out $share",
      ]);
    });

    it("keeps a projected loop body on its selector line", () => {
      const src = `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach :items
  - :value | encode hex | out $share`;
      const { ast, errors } = parseRecipe(src);
      expect(errors).toEqual([]);
      expect(serializeRecipe(ast).split("\n").slice(1)).toEqual([
        "  - :value | encode hex | out $share",
      ]);
    });
  });

  it("round-trips nested foreach via serialize", () => {
    const src = `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    const out = serializeRecipe(ast);
    expect(out).toContain("foreach\n");
    expect(out).toMatch(/-\s+out/);
    const again = parseRecipe(out);
    expect(again.errors).toEqual([]);
    expect(again.ast.steps.find((s) => s.name === "foreach")?.body?.[0].name).toBe(
      "out"
    );
  });

  it("blank line after indented foreach starts a new chain", () => {
    const src = `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share

shares | blip39 -d | sss.combine | base64 | out $secret`;
    const { ast, errors } = parseRecipe(src);
    expect(errors).toEqual([]);
    expect(ast.chains.length).toBe(2);
    expect(ast.chains[1].steps[0].name).toBe("shares");
    expect(compileRecipe(src).validation.ok).toBe(true);
  });

  it("rejects flat foreach without body", () => {
    const { validation } = compileRecipe(
      "random 16 | sss.split threshold=2 shares=3 | blip39 | foreach | out $share"
    );
    expect(validation.ok).toBe(false);
    expect(
      validation.errors.some((e) => /foreach requires a body|Unexpected/i.test(e.message))
    ).toBe(true);
  });

  it("parses at and [n] alias", () => {
    const a = parseRecipe(
      "random 16 | sss.split threshold=2 shares=3 | blip39 | at 1 | out $s"
    );
    expect(a.errors).toEqual([]);
    expect(a.ast.steps.some((s) => s.name === "at")).toBe(true);
    expect(a.ast.steps.find((s) => s.name === "at")?.params.selector).toBe("1");

    const b = parseRecipe(
      "random 16 | sss.split threshold=2 shares=3 | blip39 | [2] | out $s"
    );
    expect(b.errors).toEqual([]);
    expect(b.ast.steps.find((s) => s.name === "at")?.params.selector).toBe("2");
  });

  it("rejects orphan indented list", () => {
    const { errors } = parseRecipe("genkey ec/p256\n  - export pkcs8");
    expect(
      errors.some((e) => /Unexpected indent|Unexpected indented|nest/i.test(e.message))
    ).toBe(true);
  });

  it("rejects tabs", () => {
    const { errors } = parseRecipe("genkey ec/p256 | foreach\n\t- out");
    expect(errors.some((e) => /Tabs/i.test(e.message))).toBe(true);
  });

  it("rejects bare merge", () => {
    const { errors } = parseRecipe(
      "random 16 | sss.split threshold=2 shares=3 | blip39 | merge"
    );
    expect(errors.some((e) => /not used|dedent/i.test(e.message))).toBe(true);
  });

  it("runs nested foreach body", async () => {
    const { ast, validation } = compileRecipe(
      `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.filter((a) => a.role === "share").length).toBe(3);
  }, 30_000);

  it("foreach :items projects :value", async () => {
    const { ast, validation } = compileRecipe(
      `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach :items
  - :value | out $share`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.filter((a) => a.role === "share").length).toBe(3);
  }, 30_000);

  it("at 1 selects a single share", async () => {
    const { ast, validation } = compileRecipe(
      "random 16 | sss.split threshold=2 shares=3 | blip39 | at 1 | out $one"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.length).toBeGreaterThanOrEqual(1);
    expect(arts[0].content.split(/\s+/).length).toBeGreaterThan(5);
  }, 30_000);

  // `- export spki` and `- out $pub` were two lines meaning one chain, and the
  // `$pub` they wrote held the SPKI. On two lines they are two branches and
  // `$pub` holds the keypair — a different artifact under the same label — so
  // the chain is spelled with the `|` that was always meant.
  it("an unselected branch emits its side out without consuming the stem", async () => {
    const { ast, validation } = compileRecipe(
      `genkey ec/p256 | tee
  - export spki | out $pub
| export pkcs8 | pem | out $priv`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const names = arts.map((a) => a.filename || a.label).join(" ");
    expect(names).toMatch(/pub/i);
    expect(names).toMatch(/priv/i);
  }, 30_000);

  // The defect, run. Two branches over one stem write two *independent*
  // artifacts: `$b` is the hex of the random bytes. Concatenated, `$b` was the
  // hex of the digest — the same recipe, the same labels, a different secret
  // under `$b`, and nothing on the page to say so.
  it("runs unselected branches independently of each other", async () => {
    const { ast, validation } = compileRecipe(
      `random 32 | tee
  - digest sha-256 | encode hex | out $a
  - encode hex | out $b
| encode hex | out $stem`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const by = (n) =>
      arts.find((a) => (a.filename || a.label || "").includes(n))?.content;
    expect(by("b")).toBe(by("stem"));
    expect(by("a")).not.toBe(by("stem"));
  }, 30_000);

  it("folds the prefixes that are steps, and keeps the ones that are not", () => {
    // Where the line is drawn, and why it is drawn there rather than anywhere
    // else. A keypair half is a step, so a branch that opens with one opens
    // with a step and the prefix grammar is not a second way to say it.
    //
    // `[n]` and `:key` / `:value` are steps in the stem too, so the same
    // argument reaches them and folding them would change nothing a run can
    // see — it would change what the builder draws as a branch's *identity*,
    // which is its own pass. Asserted rather than left to the comment: folding
    // them as well passed every other test in this repo, which is exactly the
    // state in which a boundary quietly moves.
    const { ast, errors } = parseRecipe(`random 32 | sss.split threshold=2 shares=3 | tee
  - [1] | out $one
  - blip39 | out $words`);
    expect(errors).toEqual([]);
    const tee = ast.steps.find((s) => s.name === "tee");
    expect(tee.branches[0].selector).toBe("[1]");
    expect(tee.branches[0].body.map((s) => s.name)).toEqual(["out"]);
    expect(tee.branches[1].selector).toBeUndefined();
    // And it comes back out as the prefix it was written as.
    expect(serializeRecipe(ast)).toContain("- [1] | out $one");
  });

  it("parses a projecting branch as a branch whose first step projects", () => {
    // Both spellings, one AST. The colon form is still read — a link written
    // before the change has to open — and it produces exactly what the bare
    // word produces, which is what stops the two persisting side by side.
    for (const src of [
      `genkey ec/p256 | tee
  - :private | inspect
  - :public | export spki | out $pub`,
      `genkey ec/p256 | tee
  - private | inspect
  - public | export spki | out $pub`,
    ]) {
      const { ast, errors } = parseRecipe(src);
      expect(errors, src).toEqual([]);
      const tee = ast.steps.find((s) => s.name === "tee");
      expect(tee.branches?.map((b) => b.member), src).toEqual(["", ""]);
      expect(tee.branches?.[0].body.map((b) => b.name), src).toEqual([
        "select",
        "inspect",
      ]);
      expect(tee.branches?.[0].body[0].params.selector, src).toBe(":private");
      expect(tee.branches?.[1].body.map((b) => b.name), src).toEqual([
        "select",
        "export",
        "out",
      ]);
    }
  });

  // `type: key(?:pair)?` accepted both halves of the thing it was meant to
  // tell apart: a branch handed the whole keypair instead of the projected
  // private key passed it either way, so the projection could stop happening
  // without this noticing. It is `key` and never `keypair` — that one word is
  // the difference between the branch seeing a member and seeing the stem.
  it("runs :private selector branch inspect without consuming stem", async () => {
    const { ast, validation } = compileRecipe(
      `genkey ec/p256 | tee
  - :private | inspect
| export pkcs8 | pem | out $priv`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const side = arts.find((a) => /^type: /m.test(a.content));
    expect(side.content).toMatch(/^type: key$/m);
    expect(side.content).toMatch(/^which: private$/m);
    expect(arts.some((a) => /BEGIN PRIVATE KEY/i.test(a.content))).toBe(true);
  }, 30_000);

  // The other half of the same fact, and the reason the two arms of the
  // projection have to stay apart: with a selector the branch sees a member,
  // without one it sees the stem. Asserted in one run so neither arm can be
  // collapsed into the other without a failure.
  it("projects with a selector and clones without one, in the same tee", async () => {
    const { ast, validation } = compileRecipe(
      `genkey ec/p256 | tee
  - :public | inspect
  - inspect
| export pkcs8 | pem | out $priv`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const readouts = arts
      .map((a) => a.content)
      .filter((c) => /^type: /m.test(c));
    expect(readouts).toHaveLength(2);
    expect(readouts[0]).toMatch(/^type: key$/m);
    expect(readouts[0]).toMatch(/^which: public$/m);
    expect(readouts[1]).toMatch(/^type: keypair$/m);
  }, 30_000);

  // A selector still has to be typed, and the no-selector arm must not become
  // the way out of that. `:public` over bytes has no keypair to project and is
  // refused before the run — by naming what is actually on the stem.
  it("still refuses a selector the stem cannot be projected through", () => {
    const { validation } = compileRecipe(`random 32 | tee
  - :public | inspect`);
    expect(validation.ok).toBe(false);
    expect(validation.errors.map((e) => e.message).join(" ")).toMatch(
      /selector ":public" requires keypair, got bytes/
    );
    // …and the same line without the selector is fine, because a branch with
    // no selector asks nothing of the stem's shape.
    expect(
      compileRecipe(`random 32 | tee\n  - inspect`).validation.ok
    ).toBe(true);
  });

  it("rejects unknown selectors", () => {
    const { errors } = parseRecipe(`genkey ec/p256 | tee
  - :foo | inspect`);
    expect(errors.some((e) => /Unknown selector/i.test(e.message))).toBe(true);
  });

  it("rejects legacy dot members", () => {
    const { errors } = parseRecipe(`genkey ec/p256 | tee
  - .public | export spki`);
    expect(
      errors.some((e) => /Member selectors use :public/i.test(e.message))
    ).toBe(true);
  });

  it("rejects empty tee (use peek)", () => {
    const { validation } = compileRecipe("genkey ec/p256 | tee | export pkcs8 | pem");
    expect(validation.ok).toBe(false);
    expect(validation.errors.some((e) => /tee requires a body|peek/i.test(e.message))).toBe(
      true
    );
  });

  it("peek emits side inspect without consuming stem", async () => {
    const { ast, validation } = compileRecipe(
      "genkey ec/p256 | peek kp | export pkcs8 | pem | out $priv"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.some((a) => /peek:|inspect/i.test(a.label || a.filename || ""))).toBe(
      true
    );
    expect(arts.some((a) => /BEGIN PRIVATE KEY/i.test(a.content))).toBe(true);
  }, 30_000);
});
