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
 * the four fields, and both sites call it. What is pinned below is the union
 * (one assertion per field, each of which fails if that field is dropped), the
 * conjugate-row lifting `3ef6526` added, and the structural claim that there
 * is one producer rather than two that happen to agree today.
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
import { listSteps } from "../lib/toolkit/registry.js";
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
  });

  describe("admits the union of the four fields a reader can see", () => {
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
      // The four field tests, written once. A fifth `.includes(q)` in this
      // file is either a fifth field nobody documented or a second predicate
      // growing back beside the first.
      expect(
        HOOK_SRC.match(/\.includes\(q\)/g) || [],
        "the hook tests a number of fields the producer does not declare"
      ).toHaveLength(4);
    });
  });
});
