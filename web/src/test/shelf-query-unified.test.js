/**
 * One query, one answer: the shelf's op search has a single producer.
 *
 * Two filters used to cut the shelf's op list for one query, and they did not
 * agree. `useNotebook`'s `filteredOps` matched **name / doc / toolbox**;
 * `OpsShelf`'s `grouped` matched **name / doc / label**. Both ran — the hook
 * narrows, the shell passes the result down as `ops`, the shelf narrows again
 * with the same string — so the search that shipped was the *intersection* of
 * two predicates, narrower than either author wrote.
 *
 * Measured over the real registry before the change (132 steps; a corpus of
 * 1342 queries built from every op name, every dotted name segment, every
 * toolbox id and every word of every doc):
 *
 *   - 13 queries lost ops to the intersection, 114 op-matches in total;
 *   - the loss was entirely one-directional — in 1342 queries the shelf's
 *     predicate never found one op the hook's missed — because **no step in
 *     the registry carries a `label`** (0 of 132), so its third field could
 *     only ever discard what `toolbox` had admitted;
 *   - `flow` was the worst case: 9 ops matched, the shelf discarded all 9, and
 *     the query rendered an empty shelf underneath a section header that
 *     prints the word "Flow".
 *
 * `opsMatchingQuery` is now the only thing that decides this, on the union of
 * the six fields, and both sites call it. What is pinned below is the union
 * (one assertion per field, each of which fails if that field is dropped), the
 * conjugate-row lifting `3ef6526` added, and the structural claim that there
 * is one producer rather than two that happen to agree today.
 *
 * Two of the six were added by a later pass, after their own measurement over
 * the same corpus (rebuilt by the recipe above; it comes to 1423 queries when
 * every one- and two-character doc token is kept, which is close to but not
 * identical with the 1342 the first pass counted, so treat the two totals as
 * separate measurements of the same registry rather than one number):
 *
 *   - **the toolbox's printed label** — 8 queries change, +51 op-matches, none
 *     lost. Fourteen of the fifteen headers are the toolbox id in different
 *     casing, so `toolbox` already covered them by accident; `io` prints
 *     "Input / output" and matched nothing, and `sss` prints "SSS / BLIP39".
 *   - **`aliases`** — 2 queries change, +2 op-matches, both `blip39`, reached
 *     by `words` and `word`. `sss.split`'s `split` alias adds nothing, because
 *     its own name contains the word.
 *
 * Isolating each field is the point of the assertions below and it got harder
 * with the label in: a query that is a toolbox *id* now matches through the
 * label as well for fourteen of the fifteen, so `flow` no longer fails when
 * `toolbox` is deleted. `io` is the one id its own label does not contain, and
 * it is what holds that field down.
 *
 * The component is rendered for real with `react-dom/server`, the way
 * `shelf-search-name.test.js` does, so what is asserted is what a query
 * actually puts on the shelf — not what the source says it would.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  TOOLBOX_META,
  listDrawerRows,
  listSteps,
  toolboxLabel,
} from "../lib/toolkit/registry.js";
import { opsMatchingQuery } from "../toolkit/useNotebook";
import { OpsShelf } from "../toolkit/widgets/OpsShelf.tsx";
import { TooltipProvider } from "../components/ui/tooltip.tsx";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
/** Source with comments stripped — the structural claims are about code. */
const code = (rel) =>
  read(rel)
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");
const SHELF_SRC = code("../toolkit/widgets/OpsShelf.tsx");
const HOOK_SRC = code("../toolkit/useNotebook.ts");

const ALL = listSteps();
const NAMES = new Set(ALL.map((s) => s.name));

// The `TooltipProvider` is the shell's, not this test's invention: a conjugate
// row hangs its ToolCard off a Radix tooltip, which throws without one.
const render = (props) =>
  renderToStaticMarkup(
    React.createElement(
      TooltipProvider,
      null,
      React.createElement(OpsShelf, {
        ops: ALL,
        filter: "",
        onFilter: () => {},
        onAppend: () => {},
        ...props,
      })
    )
  );

/**
 * Every op name the rendered shelf offers, read off the accessible names its
 * controls actually carry: a solo row's `+` announces `NAME — add to the
 * recipe`, and each handle of a conjugate row announces its own op (with
 * `, unavailable: …` appended when the caret refuses it). Reading the controls
 * rather than the `<code>` column is deliberate — a pair row prints only the
 * last dotted segment in the column, so the column cannot tell `sss.split`
 * from `vss.split`.
 */
function shelfOps(html) {
  const found = new Set();
  for (const [, raw] of html.matchAll(/aria-label="([^"]*)"/g)) {
    const name = raw.replace(/ — add to the recipe$/, "").replace(/, unavailable:.*$/, "");
    if (NAMES.has(name)) found.add(name);
  }
  return found;
}

/** The ops a query puts on the shelf, sorted. */
const shownFor = (filter, ops) => [...shelfOps(render({ filter, ...(ops ? { ops } : {}) }))].sort();

describe("the shelf's op query has one producer", () => {
  it("is measuring the registry these numbers were taken from", () => {
    // Every count below is a fact about this registry. If it has moved far
    // enough that these are stale, the assertions under them are about a
    // different corpus and should be re-measured rather than trusted.
    expect(ALL.length).toBeGreaterThan(100);
    expect(ALL.filter((s) => s.toolbox === "flow").map((s) => s.name)).toEqual([
      "foreach",
      "scatter",
      "lit",
      "in",
      "select",
      "as",
      "inspect",
      "tee",
      "peek",
    ]);
    // The reason the `label` assertion further down has to be synthetic, and
    // the reason the old shelf predicate could only ever subtract.
    expect(
      ALL.filter((s) => s.label).map((s) => s.name),
      "a step now carries a label — the label case can be measured for real"
    ).toEqual([]);
    // Two steps declare an alias, and the measured worth of the field is one
    // of the two: `sss.split`'s own name contains `split`, so only `words`
    // reaches an op nothing else does. A third alias landing here is a reason
    // to re-measure, not to trust the number in the header.
    expect(
      ALL.filter((s) => s.aliases?.length).map((s) => [s.name, s.aliases]),
      "the alias inventory moved — the +2 in the header is about this list"
    ).toEqual([
      ["sss.split", ["split"]],
      ["blip39", ["words"]],
    ]);
    // The one header whose printed words are not its own id, which is the
    // whole reason `toolboxLabel` is in the predicate — and the one id its
    // own label does not contain, which is what still isolates `toolbox`.
    expect(toolboxLabel("io")).toBe("Input / output");
    expect(
      Object.keys(TOOLBOX_META).filter(
        (id) => !TOOLBOX_META[id].label.toLowerCase().includes(id.toLowerCase())
      ),
      "a second header stopped printing its own id, or `io` started"
    ).toEqual(["io"]);
    expect(toolboxLabel("nope"), "an unknown toolbox must read as no label").toBe("");
  });

  describe("admits the union of the six fields a reader can see", () => {
    it("matches the op's own name", () => {
      // `recipients.merge` and not `genkey`: `genkey`'s own doc quotes the
      // word `genkey` in its example, so a name query for it is satisfied by
      // the doc field and would keep passing with `name` deleted. Nineteen
      // ops in this registry are reachable through their name alone; this is
      // one, and dropping the field takes the query to nothing.
      expect(opsMatchingQuery(ALL, "recipients.merge").map((s) => s.name)).toEqual([
        "recipients.merge",
      ]);
      expect(shownFor("recipients.merge")).toEqual(["recipients.merge"]);
    });

    it("matches the doc the card and the tooltip print", () => {
      // "generate" is in no op name and in no toolbox id — it reaches these
      // rows through `doc` alone.
      const byDoc = opsMatchingQuery(ALL, "generate").map((s) => s.name);
      for (const op of ["genkey", "passphrase", "gpg.genkey", "age.keygen"]) {
        expect(byDoc, `"generate" no longer reaches ${op} through its doc`).toContain(op);
      }
      expect(shownFor("generate")).toContain("age.keygen");
    });

    it("matches the toolbox printed on the section header above the row", () => {
      // The field the shelf's own predicate lacked, and the whole of the
      // measured loss. No `flow` op has "flow" in its name or its doc, so a
      // name/doc/label search returns nothing at all for it — an empty shelf
      // under a header reading "Flow".
      const byToolbox = opsMatchingQuery(ALL, "flow").map((s) => s.name);
      expect(byToolbox.length, "`flow` reaches no op at all").toBe(9);
      const shown = shownFor("flow");
      // `lit` is kitOnly and is reached through the footer bar, not the tree.
      expect(shown).toEqual(["as", "foreach", "in", "inspect", "peek", "scatter", "select", "tee"]);
    });

    it("matches the toolbox id even where the header spells it differently", () => {
      // `flow` above no longer isolates this field: the header prints "Flow",
      // so deleting `toolbox` leaves the query passing through `toolboxLabel`
      // and the assertion says nothing about the line it was written for.
      // `io` is the one id in the registry that its own label does not
      // contain — "Input / output" has no "io" in it — so this is the query
      // that fails when the `toolbox` reading goes.
      const byId = opsMatchingQuery(ALL, "io").map((s) => s.name);
      // Measured: 13 ops in the `io` toolbox spell "io" in neither their name
      // nor their doc, and reach the query through the field alone. Two of
      // them, named rather than counted, because a count passes on a page that
      // found thirteen of something else.
      for (const op of ["qr.scan", "clipboard.read", "file.save", "publish"]) {
        expect(byId, `"io" no longer reaches ${op} through its toolbox id`).toContain(op);
      }
    });

    it("matches the words the section header actually prints", () => {
      // The gap the id left. Fourteen headers are the id in another casing and
      // are covered by accident; "Input / output" is not, and typing what the
      // header says found **nothing at all** — 0 ops before this field, the
      // `flow` defect one toolbox over.
      const byLabel = opsMatchingQuery(ALL, "input / output").map((s) => s.name).sort();
      const io = ALL.filter((s) => s.toolbox === "io").map((s) => s.name).sort();
      expect(io.length, "the io toolbox is empty — this measures nothing").toBe(20);
      // Exactly the ops under that header: the query is the header, so
      // anything more would be dragging in a toolbox the reader did not point
      // at and anything less is the gap still open. (Equality is the honest
      // assertion and not a lucky one — a conjugate partner outside `io` would
      // legitimately break it, and that is a re-measurement, not a regression.)
      expect(byLabel, "typing the header no longer selects its own rows").toEqual(io);
      expect(shownFor("input / output")).toContain("qr.scan");
      // The second header that says something its id does not. `sss` prints
      // "SSS / BLIP39", and these two are under it without the word anywhere
      // in their own name or doc.
      const byBlip = opsMatchingQuery(ALL, "blip39").map((s) => s.name);
      for (const op of ["vss.verify", "dkg.run"]) {
        expect(byBlip, `"blip39" no longer reaches ${op} through its header`).toContain(op);
      }
    });

    it("matches a second spelling the parser takes and the card prints", () => {
      // `blip39` declares `aliases: ["words"]`. The parser has always accepted
      // `words`, `ToolCard` prints an "Aliases:" row on every non-compact card
      // — which is the card `OpsTile` opens off a pair row, and `blip39` draws
      // one — and no filter has ever matched it: a verb this product takes and
      // then could not find. Measured: the field changes 2 queries in the
      // whole corpus and admits 2 op-matches, both this op.
      //
      // `words` and not `split`: `sss.split`'s alias is a substring of its own
      // name, so a `split` query is satisfied by `name` and would keep passing
      // with `aliases` deleted — the `genkey`/`doc` trap the previous pass
      // left a note about.
      expect(opsMatchingQuery(ALL, "words").map((s) => s.name)).toEqual([
        // `vss.commitments` is here through its doc, and was before this
        // field; `blip39` is the one the alias adds.
        "vss.commitments",
        "blip39",
      ]);
    });

    it("matches a step's UI label, the day a step declares one", () => {
      // No step does today (asserted above), so this is the one case that has
      // to be exercised on ops of our own. `ToolCard` renders `op.label ||
      // op.name`, so a label is a word on screen: a search that could not find
      // it would be printing something unfindable, which is the defect
      // `pairRowMatches` was written for one layer down.
      const ops = [
        { name: "zzz.one", doc: "nothing", toolbox: "io", label: "Shred" },
        { name: "zzz.two", doc: "nothing", toolbox: "io" },
      ];
      expect(opsMatchingQuery(ops, "shred").map((o) => o.name)).toEqual(["zzz.one"]);
    });

    it("is case-insensitive on every field, including the name", () => {
      expect(opsMatchingQuery(ALL, "  GenKey  ").map((s) => s.name)).toContain("genkey");
      expect(opsMatchingQuery(ALL, "FLOW").map((s) => s.name)).toContain("foreach");
      // The hook's half compared `s.name.includes(q)` — the raw name against
      // an already lower-cased query. That is right for exactly as long as
      // every op name is lower case, which is a fact about today's registry
      // (measured: 0 of 132 carry an upper-case character) and not a rule
      // anything enforces. So, like the label, the case has to be put on ops
      // of our own: restoring the old spelling passes every assertion over the
      // real registry and fails this one.
      expect(opsMatchingQuery([{ name: "ZZZ.One" }], "zzz").map((o) => o.name)).toEqual([
        "ZZZ.One",
      ]);
    });

    it("returns everything, unchanged, for an empty query", () => {
      expect(opsMatchingQuery(ALL, "")).toBe(ALL);
      expect(opsMatchingQuery(ALL, "   ")).toBe(ALL);
    });
  });

  describe("keeps a conjugate pair row findable by either direction", () => {
    // `3ef6526`: `listDrawerRows` draws a pair once, on the forward op, and
    // drops every step carrying `conjugateOf` — so a match on the reverse half
    // alone reaches no row unless the test is lifted onto the row. The lifting
    // now lives inside `opsMatchingQuery`, which is the only reason it cannot
    // be remembered at one call site and forgotten at the other.
    it("finds the row from the reverse half's name", () => {
      expect(shownFor("unwrap"), "`unwrap` reaches no wrap row").toEqual(
        expect.arrayContaining(["wrap", "unwrap"])
      );
      expect(shownFor("symdecrypt"), "`symdecrypt` reaches no row").toEqual(
        expect.arrayContaining(["gpg.symencrypt", "gpg.symdecrypt"])
      );
      expect(shownFor("gpg.decrypt"), "`gpg.decrypt` reaches no row").toEqual(
        expect.arrayContaining(["gpg.encrypt", "gpg.decrypt"])
      );
    });

    /**
     * The five queries `ops-pair-row.e2e.js` types into the built shelf, and
     * the rows each leaves — asserted here, over `listDrawerRows`, because
     * that spec runs against `dist/` and a change to the predicate cannot be
     * scored against it without a rebuild. Four of its five assertions are
     * `toContain` and would survive an extra row; the fifth is
     * `toEqual([])` on `gpg.genkey` and would not, which is the one this
     * mirrors most closely.
     */
    it("leaves the e2e's five queries drawing exactly the rows it pins", () => {
      const pairsFor = (q) =>
        listDrawerRows(opsMatchingQuery(ALL, q))
          .filter((r) => r.type === "pair")
          .map((r) => (r.decodeTwin ? `${r.forward.name}|decode` : `${r.forward.name}|${r.reverse.name}`));
      expect(pairsFor("gpg.encrypt")).toContain("gpg.encrypt|gpg.decrypt");
      expect(pairsFor("gpg.decrypt")).toEqual(["gpg.encrypt|gpg.decrypt"]);
      expect(pairsFor("symdecrypt")).toContain("gpg.symencrypt|gpg.symdecrypt");
      expect(pairsFor("unwrap")).toContain("wrap|unwrap");
      // The e2e's control, in the form it asserts it: not "no `gpg` row" but
      // no conjugate row at all.
      expect(pairsFor("gpg.genkey"), "a solo query dragged a pair row in").toEqual([]);
    });

    it("does not let a solo query drag a pair row in behind it", () => {
      // The control, and what stops "follow the conjugate" from becoming
      // "match everything". `ops-pair-row.e2e.js` pins the same claim on the
      // built bundle.
      const shown = shownFor("gpg.genkey");
      expect(shown).toContain("gpg.genkey");
      for (const op of ["gpg.encrypt", "gpg.decrypt", "gpg.symencrypt", "gpg.symdecrypt"]) {
        expect(shown, `"gpg.genkey" dragged ${op} onto the shelf`).not.toContain(op);
      }
    });
  });

  describe("cannot be narrowed a second time on the way to the screen", () => {
    /**
     * The 13 queries that measurably lost ops to the intersection, plus two
     * controls. The shell hands the shelf a list this same query has already
     * narrowed, so the shelf's own pass must admit exactly what it is given —
     * anything else and the two filters are disagreeing again, quietly.
     */
    const QUERIES = [
      "bcrypt",
      "webcrypto",
      "webrtc",
      "io",
      "crypto",
      "flow",
      "low",
      "encoding",
      "rtc",
      "sss",
      "enc",
      "in",
      "hkp",
      "genkey",
      "base64",
    ];

    it("shows the same ops whether or not the list arrived pre-narrowed", () => {
      const disagreed = [];
      for (const q of QUERIES) {
        const whole = shownFor(q);
        const narrowed = shownFor(q, opsMatchingQuery(ALL, q));
        // An empty shelf agrees with an empty shelf, which would satisfy the
        // comparison without saying anything. Every one of these queries has
        // matches, and that is part of the claim.
        if (!whole.length) disagreed.push(`${q}: renders nothing`);
        else if (whole.join() !== narrowed.join()) {
          disagreed.push(
            `${q}: whole=${whole.length} pre-narrowed=${narrowed.length} lost ${whole
              .filter((n) => !narrowed.includes(n))
              .join(" ")}`
          );
        }
      }
      expect(disagreed, `a second pass changed the answer:\n  ${disagreed.join("\n  ")}`).toEqual(
        []
      );
    });

    it("keeps the decision in one function, called from both places", () => {
      // The behavioural tests above cannot see a *second* producer that
      // happens to agree on today's registry — that is exactly the shape this
      // change removes, and it is a fact about the code. `filteredOps` cannot
      // be exercised here at all (it is inside a hook, and the unit
      // environment is `node`), so this is where its half is held down.
      expect(
        SHELF_SRC.match(/opsMatchingQuery/g) || [],
        "the shelf stopped calling the one producer, or calls it twice"
      ).toHaveLength(2); // the import, and the one call
      expect(
        SHELF_SRC,
        "the shelf is lifting the query onto rows itself again"
      ).not.toMatch(/pairRowMatches/);
      expect(
        HOOK_SRC.match(/opsMatchingQuery/g) || [],
        "the hook should declare the producer once and call it once"
      ).toHaveLength(2);
      expect(
        HOOK_SRC.match(/pairRowMatches\(/g) || [],
        "a second place in the hook lifts the query onto rows"
      ).toHaveLength(1);
      // The six field tests, written once. A seventh `.includes(q)` in this
      // file is either a field nobody documented or a second predicate
      // growing back beside the first.
      expect(
        HOOK_SRC.match(/\.includes\(q\)/g) || [],
        "the hook tests a number of fields the producer does not declare"
      ).toHaveLength(6);
    });
  });
});
