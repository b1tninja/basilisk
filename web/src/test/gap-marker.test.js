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
    // `pending && !active` is the caret's condition: a drop hover outranks it
    // and renders the + with its drop-active accent, which is a control again.
    const out = html({ label: "Drop here", active: true, pending: true, onClick: () => {} });
    expect(out).toMatch(/^<button type="button"/);
    expect(out).toMatch(/cell-recipe-gap-drop-active/);
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
