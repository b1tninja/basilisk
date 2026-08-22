/**
 * The shelf's landmark says what it is, in every configuration that ships.
 *
 * `OpsShelf` had a `hideSearch` prop that **no caller set** — the external
 * `#ops-filter` field its doc comment deferred to exists nowhere in the tree,
 * and a grep for the prop found only its own declaration, its own default, and
 * its own three reads. A finished mechanism with no consumer looks exactly
 * like a finished feature, which is why it had quietly acquired a second job:
 * `namesItself = !bare && !hideSearch` gated whether the `<aside>` got
 * `aria-labelledby`, so a prop nothing could set stood in front of the shelf's
 * accessible name.
 *
 * `!bare` was the other half and it was already dead in that position: the
 * `bare` branch returns a plain `<div>` before the `<aside>` is ever
 * constructed, so the only render that reads the flag is one where `bare` is
 * false. The whole condition could only ever evaluate true. It is gone, and
 * `aria-labelledby={headingId}` is unconditional.
 *
 * Which leaves nothing in the unit suite holding that name down.
 * `e2e/toolkit-accessible-names.e2e.js` asserts `shelfName === "Toolkit"` on
 * the built bundle, but it needs chromium and a `dist/`, so a source change
 * that drops the name passes every fast test. This is the fast test: the
 * component is rendered for real with `react-dom/server` and the landmark's
 * accessible name is resolved from the markup the way a browser resolves it —
 * `aria-labelledby` to the element that id names, not by reading an attribute
 * and trusting it points somewhere.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { OpsShelf } from "../toolkit/widgets/OpsShelf.tsx";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SHELF_SRC = read("../toolkit/widgets/OpsShelf.tsx");

/** A handful of real-shaped rows — the name under test is chrome, not content. */
const OPS = [
  { name: "base64.encode", toolbox: "encoding", shelf: "text", input: "bytes" },
  { name: "genkey", toolbox: "webcrypto", shelf: "keys", input: "none" },
];

const render = (props) =>
  renderToStaticMarkup(
    React.createElement(OpsShelf, {
      ops: OPS,
      filter: "",
      onFilter: () => {},
      onAppend: () => {},
      ...props,
    })
  );

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const strip = (s) => s.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();

/** The opening `<aside …>` tag, or null if the shelf drew no landmark. */
function asideTag(html) {
  const m = html.match(/<aside\b[^>]*>/);
  return m ? m[0] : null;
}

/**
 * The accessible name of an element, computed the way the browser computes it
 * for a landmark: `aria-labelledby` resolved through the document, then
 * `aria-label`. Resolving the id is the point — an `aria-labelledby` naming an
 * element that is not rendered names nothing, and reading the attribute alone
 * would score that as fixed.
 */
function accessibleName(tag, html) {
  const lb = tag.match(/aria-labelledby="([^"]*)"/);
  if (lb && lb[1].trim()) {
    const text = lb[1]
      .trim()
      .split(/\s+/)
      .map((id) => {
        const m = html.match(
          new RegExp(`<(\\w+)\\b[^>]*\\bid="${esc(id)}"[^>]*>([\\s\\S]*?)</\\1>`)
        );
        return m ? strip(m[2]) : "";
      })
      .join(" ")
      .trim();
    if (text) return { name: text, from: "labelledby" };
  }
  const al = tag.match(/aria-label="([^"]*)"/);
  if (al && al[1].trim()) return { name: al[1].trim(), from: "aria-label" };
  return { name: "", from: "none" };
}

describe("the ops shelf names its own landmark", () => {
  it("renders the landmark the assertions below are about", () => {
    // A render that threw, or one that stopped drawing an <aside>, would make
    // every claim under it vacuous.
    const html = render({});
    expect(asideTag(html), "the shelf drew no <aside>").not.toBeNull();
    expect(html).toContain("ops-shelf-heading");
  });

  it("gives the aside the name the shelf prints on itself", () => {
    const html = render({});
    const { name, from } = accessibleName(asideTag(html), html);
    expect(from, "the landmark is not named through a heading").toBe("labelledby");
    expect(name).toBe("Toolkit");
  });

  it("names it in every configuration a caller can ask for", () => {
    // The props a caller actually passes today — `ToolkitShell` sets className,
    // tipFit, tip, caretBanner and castStatus; the widget catalog sets bare.
    // None of them may take the landmark's name away.
    const configs = [
      ["default", {}],
      ["className", { className: "w-full" }],
      ["caret", {
        tipFit: new Set(["base64.encode"]),
        tip: { base: "bytes" },
        caretBanner: React.createElement("div", null, "Caret · after genkey"),
      }],
      ["filtered", { filter: "base64" }],
      ["no matches", { filter: "zzzznotanop" }],
      ["cast", { castStatus: { webcrypto: "pass" } }],
    ];
    const unnamed = [];
    for (const [label, props] of configs) {
      const html = render(props);
      const tag = asideTag(html);
      const { name } = tag ? accessibleName(tag, html) : { name: "" };
      if (name !== "Toolkit") unnamed.push(`${label}: ${JSON.stringify(name)}`);
    }
    expect(unnamed, `configurations whose landmark lost its name:\n  ${unnamed.join("\n  ")}`)
      .toEqual([]);
  });

  it("draws no landmark at all when the host owns the chrome", () => {
    // `bare` is the live sibling prop and it is the reason the name can be
    // unconditional: it returns before the <aside>, so there is never an
    // unnamed landmark to guard against. If this ever starts rendering an
    // <aside>, the claim above stops covering it.
    const html = render({ bare: true });
    expect(asideTag(html), "a bare shelf drew a landmark it cannot name").toBeNull();
    expect(html, "a bare shelf printed a heading its host already prints").not.toContain(
      "ops-shelf-heading"
    );
  });

  it("ships the search field in every configuration, bare included", () => {
    // What `hideSearch` claimed to offer. No caller wanted it, and the field
    // is the shelf's only way in for keyboard and for anyone who cannot scan
    // a 75-row tree — so its presence is not a prop, it is the contract.
    for (const props of [{}, { bare: true }, { filter: "zzzznotanop" }]) {
      const html = render(props);
      expect(html).toMatch(/aria-label="Search toolkit \([^"]*\)"/);
    }
  });

  it("keeps the name off any prop, so no caller can switch it off", () => {
    const code = SHELF_SRC.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
    expect(code, "`hideSearch` is back").not.toMatch(/hideSearch/);
    expect(code).toMatch(/aria-labelledby=\{headingId\}/);
    expect(code, "the landmark's name is conditional again").not.toMatch(
      /aria-labelledby=\{[^}]*\?/
    );
  });
});
