/**
 * A `pending` gap is a control only where a press has somewhere to go.
 *
 * `InsertGap` rendered a `<button>` in both of its branches. Four of its five
 * call sites spread `bindGap`/`stemGap` and pass all four handlers; the fifth —
 * the armed-branch caret in `RecipeChipFlow` — passes no `onClick` at all, and
 * so shipped a focusable, button-announced marker that answered Enter with
 * nothing. That is the defect this repo keeps finding, in its smallest form.
 *
 * Two claims, and the split between them is the whole change:
 *
 * - the **unwired** pending gap renders a named, unfocusable `<span>` that is
 *   still the drop target, and
 * - the **wired** pending gap is still a `<button>`, because pressing it is not
 *   a no-op (`onGap` re-focuses the cell the caret is in, which is what repairs
 *   the shelf's caret banner when `focusedCell` has moved out from under
 *   `pendingInsert`) and because both branches rendering the same element type
 *   is what keeps a keyboard user's focus alive across the press.
 *
 * The components are rendered for real with `react-dom/server`, and the two
 * assertions that markup cannot carry — that the drop handlers and the `data-*`
 * passthrough survived the element swap — read the element `InsertGap` returns,
 * which is a pure function of its props. No source text is scanned here.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { InsertGap } from "../toolkit/widgets/InsertGap.tsx";
import { RecipeChipFlow } from "../toolkit/widgets/RecipeChipFlow.tsx";

const html = (props) => renderToStaticMarkup(React.createElement(InsertGap, props));

/** A tee stem with nothing under it — the state a branch is armed from. */
const TEE = [
  {
    step: { name: "tee", label: "tee" },
    hasNest: true,
    nestKind: "tee",
    branches: [],
    body: [],
  },
];

const flow = (props) =>
  renderToStaticMarkup(
    React.createElement(RecipeChipFlow, {
      cell: 0,
      stems: TEE,
      onSelect: () => {},
      onGap: () => {},
      onBranchHit: () => {},
      onReorder: () => {},
      onCancelArmed: () => {},
      ...props,
    })
  );

describe("the pending caret, where nothing answers a press", () => {
  it("is a span and not a button", () => {
    const out = html({ pending: true, label: "Insert first step in :public" });
    expect(out).not.toMatch(/<button/);
    expect(out).toMatch(/^<span /);
  });

  it("takes no tab stop and claims no widget role", () => {
    const out = html({ pending: true, label: "Insert first step in :public" });
    // The two signals that made the old marker read as a control. `role="note"`
    // is a document role, not a widget one, and nothing here is focusable.
    expect(out).not.toMatch(/tabindex/i);
    expect(out).not.toMatch(/role="button"/);
    expect(out).toMatch(/role="note"/);
  });

  it("is still named — the marker was not merely hidden", () => {
    const out = html({ pending: true, label: "Insert first step in :public" });
    expect(out).toMatch(/aria-label="Insert first step in :public — insert position"/);
    expect(out).not.toMatch(/aria-hidden="true"[^>]*class="cell-recipe-gap-caret"/);
    // The bar and the word HERE stay hidden: they are the drawing, and the name
    // above is what says what the drawing means.
    expect(out).toMatch(/class="cell-recipe-gap-caret-bar" aria-hidden/);
    expect(out).toMatch(/HERE/);
  });

  it("still draws as the caret", () => {
    const out = html({ pending: true, label: "x", className: "extra" });
    expect(out).toMatch(/class="cell-recipe-gap-caret extra"/);
  });

  it("is still the drop target, and still carries its data-* passthrough", () => {
    const onDragOver = () => {};
    const onDragLeave = () => {};
    const onDrop = () => {};
    const el = InsertGap({
      pending: true,
      label: "Insert first step in :public",
      onDragOver,
      onDragLeave,
      onDrop,
      "data-cell": 3,
      "data-gap-stem": 1,
    });
    expect(el.type).toBe("span");
    // Identity, not presence: a spread that dropped `shared` would still leave
    // an element with the right tag and the wrong wiring.
    expect(el.props.onDragOver).toBe(onDragOver);
    expect(el.props.onDragLeave).toBe(onDragLeave);
    expect(el.props.onDrop).toBe(onDrop);
    expect(el.props["data-gap-insert"]).toBe("1");
    expect(el.props["data-cell"]).toBe(3);
    expect(el.props["data-gap-stem"]).toBe(1);
  });
});

describe("the pending caret, where a press does something", () => {
  it("is still a button", () => {
    const out = html({ pending: true, label: "Insert step here", onClick: () => {} });
    expect(out).toMatch(/^<button type="button"/);
    expect(out).toMatch(/class="cell-recipe-gap-caret"/);
    expect(out).toMatch(/aria-label="Insert step here — insert position"/);
  });

  it("is the same element type as the gap it was pressed from", () => {
    // Why this matters and is not decoration: React updates a node in place
    // when the type is unchanged, so focus survives the press that aims the
    // caret. A span here would unmount the focused button and drop the reader
    // at the top of the page for having used the keyboard.
    const click = () => {};
    expect(InsertGap({ onClick: click }).type).toBe("button");
    expect(InsertGap({ pending: true, onClick: click }).type).toBe("button");
  });

  it("leaves the ordinary + gap alone", () => {
    const out = html({ label: "Insert step here", onClick: () => {} });
    expect(out).toMatch(/^<button type="button"/);
    expect(out).toMatch(/class="cell-recipe-gap-add"/);
    expect(out).toMatch(/aria-label="Insert step here"/);
  });

  it("leaves a gap being dragged over alone, pending or not", () => {
    // A drop hover outranks `pending` and renders the + with its drop-active
    // accent, which is a control again — *where the + would be pressable*.
    const out = html({ label: "Drop here", active: true, pending: true, onClick: () => {} });
    expect(out).toMatch(/^<button type="button"/);
    expect(out).toMatch(/cell-recipe-gap-drop-active/);
  });
});

describe("a drag over the marker, which cannot become a pressable +", () => {
  /**
   * The `+` takeover exists to say "this gap will take the drop", and it is
   * worth changing shape for because the `+` it hands back is a control. On a
   * gap with no `onClick` it is not: the old `pending && !active` fell through
   * to a dead `+` button, so the armed caret was shipped with no drop accent at
   * all rather than that. The condition is now `pending && !(active && onClick)`
   * and the marker accents in place.
   */
  const marker = { pending: true, active: true, label: "Insert first step in :public" };

  it("stays a span rather than falling through to a dead +", () => {
    const out = html(marker);
    expect(out).not.toMatch(/<button/);
    expect(out).toMatch(/^<span /);
    expect(out).not.toMatch(/cell-recipe-gap-add/);
  });

  it("takes the accent in place, and only while the drag is over it", () => {
    expect(html(marker)).toMatch(
      /class="cell-recipe-gap-caret cell-recipe-gap-caret-drop-active"/
    );
    expect(html({ ...marker, active: false })).toMatch(/class="cell-recipe-gap-caret"/);
    expect(html({ ...marker, active: false })).not.toMatch(/drop-active/);
  });

  it("keeps its name and its inertness under the drag", () => {
    const out = html(marker);
    expect(out).toMatch(/role="note"/);
    expect(out).toMatch(/aria-label="Insert first step in :public — insert position"/);
    expect(out).not.toMatch(/tabindex/i);
  });

  it("does not change element type when the drag arrives or leaves", () => {
    // Not the focus argument the wired four make — this one is about the drop
    // itself. Unmounting the element the pointer is over mid-drag cancels it.
    expect(InsertGap({ pending: true }).type).toBe("span");
    expect(InsertGap({ pending: true, active: true }).type).toBe("span");
    expect(InsertGap({ pending: true, active: true, onDrop: () => {} }).type).toBe("span");
  });

  it("still carries the accent class through className, not an inline style", () => {
    const el = InsertGap({ ...marker, className: "extra" });
    expect(el.props.style).toBeUndefined();
    expect(el.props.className).toBe(
      "cell-recipe-gap-caret cell-recipe-gap-caret-drop-active extra"
    );
  });
});

describe("the stylesheet, which was still painting the marker as a control", () => {
  /**
   * Source-scanned rather than driven, because the browser that would answer
   * this behaviourally is the one this suite does not have. The claim is narrow
   * and exact: the shared class must not carry `cursor: pointer`, and the
   * element that answers a press must.
   *
   * A Tailwind utility could not have fixed this — `toolkit.css` imports
   * tailwind and then `site.css` unlayered, so `site.css` beats
   * `@layer utilities` and an inline `cursor-default` would have lost.
   */
  const css = readFileSync(
    fileURLToPath(new URL("../css/site.css", import.meta.url)),
    "utf8"
  ).replace(/\/\*[\s\S]*?\*\//g, "");
  /**
   * Declarations by exact selector list. `[^{}]` on both halves keeps a nested
   * at-rule from matching as one — the engine simply starts again inside it —
   * and a comment can no longer stand in for a declaration, since the strip
   * above ran first.
   */
  const RULES = new Map(
    [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => [m[1].trim(), m[2]])
  );
  const rule = (sel) => RULES.get(sel) ?? null;

  it("does not give the shared caret class a pointer cursor", () => {
    const base = rule(".cell-recipe-gap-caret");
    expect(base, "the `.cell-recipe-gap-caret` rule moved").toBeTruthy();
    expect(base).not.toMatch(/cursor:\s*pointer/);
    // `default` and not the UA's `auto`: the caret's own text would otherwise
    // draw an I-beam, offering selectable prose in place of a control.
    expect(base).toMatch(/cursor:\s*default/);
  });

  it("gives the pointer back to the element that answers a press", () => {
    expect(rule("button.cell-recipe-gap-caret")).toMatch(/cursor:\s*pointer/);
  });

  it("draws the marker's drop accent, which no component may inline", () => {
    const accent = rule(".cell-recipe-gap-caret.cell-recipe-gap-caret-drop-active");
    expect(accent, "the marker's drop accent has no rule to draw it").toBeTruthy();
    expect(accent).toMatch(/var\(--caret\)/);
  });
});

describe("the catalogue, which showed only the states with a press", () => {
  /**
   * `/toolkit-widgets` §insertgap is the design surface for this component, and
   * all four of its swatches passed `onClick` — so the two states this work
   * created had no drawing anywhere a designer looks. The catalogue can only
   * show them by *omitting* the handler, because that is the fact the component
   * keys on; there is no variant name to pass.
   *
   * Scanned as source for the reason `artifact-kinds-table.test.js` states one
   * layer over: the page mounts itself, so it cannot be imported into a node
   * run. `handler-wiring.test.js` deliberately does not count this file as a
   * caller — that is about whether the *product* wires a handler, and is not in
   * tension with requiring the catalogue to omit one here.
   */
  const catalog = readFileSync(
    fileURLToPath(new URL("../pages/toolkit-widgets.tsx", import.meta.url)),
    "utf8"
  );
  /**
   * The attribute list of each `<InsertGap … />`.
   *
   * Scanned rather than matched with `[^>]*`, which stops at the first `>` —
   * and `onClick={() => {}}` carries one, so a naive pattern silently skips
   * exactly the swatches this is here to tell apart. Depth counts `{}` so the
   * `/>` that ends the tag is the one outside every expression.
   */
  const swatches = [];
  for (const m of catalog.matchAll(/<InsertGap\b/g)) {
    let depth = 0;
    let i = m.index + m[0].length;
    for (; i < catalog.length; i++) {
      if (catalog[i] === "{") depth++;
      else if (catalog[i] === "}") depth--;
      else if (depth === 0 && catalog[i] === "/" && catalog[i + 1] === ">") break;
    }
    // A JSX comment inside the opening tag sits where an attribute would, so a
    // swatch could otherwise be "unwired" by a sentence about being unwired.
    swatches.push(
      catalog.slice(m.index + m[0].length, i).replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, " ")
    );
  }

  it("finds the section it thinks it is reading", () => {
    expect(swatches.length).toBeGreaterThanOrEqual(4);
  });

  it("draws the inert marker", () => {
    const inert = swatches.filter((s) => /\bpending\b/.test(s) && !/onClick/.test(s));
    expect(inert, "no swatch shows a pending gap with nothing to press").not.toHaveLength(0);
    expect(inert.some((s) => !/\bactive\b/.test(s)), "the resting marker").toBe(true);
    expect(inert.some((s) => /\bactive\b/.test(s)), "the marker under a drag").toBe(true);
  });
});

describe("the five call sites, through RecipeChipFlow", () => {
  it("renders the armed branch's caret as a marker", () => {
    const out = flow({ armedBranch: { stem: 0, selector: ":public" } });
    const row = /<div class="cell-recipe-indent-line"[^>]*data-armed-branch[\s\S]*?<\/div>\s*<\/div>/.exec(
      out
    );
    expect(row, "the armed row is not where this test thinks it is").toBeTruthy();
    expect(row[0]).toMatch(/<span class="cell-recipe-gap-caret" role="note"/);
    expect(row[0]).not.toMatch(/<button[^>]*cell-recipe-gap-caret/);
    // The row still holds exactly one button — the × that cancels the arming,
    // which is where the behaviour the caret never had actually lives.
    expect(row[0].match(/<button/g) || []).toHaveLength(1);
  });

  it("keeps the aimed stem gap pressable", () => {
    const out = flow({ activeGap: { cell: 0, stem: 0 } });
    expect(out).toMatch(/<button type="button" class="cell-recipe-gap-caret"/);
    expect(out).not.toMatch(/role="note"/);
  });

  it("keeps the aimed nested gap pressable", () => {
    const out = flow({
      stems: [
        {
          step: { name: "foreach", label: "foreach" },
          hasNest: true,
          nestKind: "foreach",
          branches: [],
          body: [],
        },
      ],
      activeGap: { cell: 0, stem: 0, branch: null, body: 0 },
    });
    expect(out).toMatch(/<button type="button" class="cell-recipe-gap-caret"/);
    expect(out).not.toMatch(/role="note"/);
  });
});
