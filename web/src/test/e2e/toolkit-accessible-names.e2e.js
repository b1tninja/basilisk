/**
 * What the toolkit shell announces, measured on the shipped bundle.
 *
 * Two defects of one shape, both closed here and both able to come back
 * silently because neither is visible on screen.
 *
 * ## 1. The add buttons announced documentation instead of the op
 *
 * Every solo row in the shelf is a name, and beside it a 22×20 square whose
 * only text is `+`. `AddButton` filled `title` — and, because it copied
 * `title` into `aria-label`, the accessible name — with the op's registry
 * doc. Measured on `dist/` at 1440×900 with an empty notebook, before the
 * fix: **38 of the shelf's 75 add buttons had an accessible name over 100
 * characters, 29 of them over 200, the longest 1039**, and the paragraph
 * never contained the op's own name. Focusing `genkey` said "Generate a
 * WebCrypto keypair/key. Curves: `ec/p256`…" for 245 characters without once
 * saying `genkey`. That is 07d4eea's defect — a control whose ARIA does not
 * describe the control — wearing accessibility clothing.
 *
 * `startsWith` and not `includes`, deliberately. `genkey`'s doc contains the
 * string "genkey" (in its usage example) and `ecdh`'s starts with "ECDH", so
 * a containment check passes on the *broken* page for both. The length cap is
 * the other half: a name that opens with the op and then runs on for a
 * paragraph is the same defect with a prefix bolted on.
 *
 * ## 2. The page had no main and no outline
 *
 * `h1: 0, h2: 0, h3: 1` — heading navigation did nothing, and the lone `h3`
 * was "Your browser vault", four levels down inside the tray. The notebook,
 * the subject of the page, sat in no landmark at all: `nav`, one `aside`, and
 * an `<article>`-scoped `<header>` that is not a landmark either.
 *
 * ## What each of these can be broken by, and is not
 *
 * The names are computed the way a browser computes them — aria-labelledby,
 * then aria-label, then content, then title — rather than read off one
 * attribute, because reading `aria-label` alone scores a page that sets
 * `title` only as fixed, and reading `title` alone scores this page's fix as
 * broken. One name is cross-checked against Playwright's own accname
 * implementation so the local copy cannot quietly drift into agreeing with
 * itself.
 *
 * The doc did not go away; it moved. `title` still carries it, which is both
 * the hover tooltip a pointer has always had on these rows (a solo row has no
 * ToolCard behind it) and the accessible *description* now that `aria-label`
 * supplies the name. Deleting `title` would "fix" the name and lose the
 * documentation, so that is asserted too.
 *
 * Serves `dist/` like every spec here, so `npm run build` must have run.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DIST_ROOT, chromiumAvailability, serveDist } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the announcement is measured in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[toolkit-accessible-names.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/**
 * Runs in the page. Serialised into the browser, so it stands alone.
 *
 * The accessible-name order for a `<button>`: aria-labelledby, then
 * aria-label, then its own text content, then title. `title` is last, which
 * is the whole point — it is what a control falls back on when it has said
 * nothing better, not a place to put a paragraph.
 */
function shelfNames() {
  const nameOf = (el) => {
    const lb = el.getAttribute("aria-labelledby");
    if (lb) {
      const t = lb
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() || "")
        .join(" ")
        .trim();
      if (t) return { name: t, from: "labelledby" };
    }
    const al = el.getAttribute("aria-label");
    if (al && al.trim()) return { name: al.trim(), from: "aria-label" };
    const txt = (el.textContent || "").trim();
    if (txt) return { name: txt, from: "content" };
    const ti = el.getAttribute("title");
    if (ti && ti.trim()) return { name: ti.trim(), from: "title" };
    return { name: "", from: "none" };
  };

  const rows = [];
  for (const cat of document.querySelectorAll(".ops-category")) {
    for (const code of cat.querySelectorAll("code")) {
      const row = code.parentElement;
      const op = (code.textContent || "").trim();
      for (const button of row.querySelectorAll("button")) {
        const { name, from } = nameOf(button);
        rows.push({
          op,
          name,
          from,
          title: (button.getAttribute("title") || "").trim(),
          glyphOnly: (button.textContent || "").trim().length <= 1,
          add: (button.textContent || "").trim() === "+",
        });
      }
    }
  }
  return rows;
}

/** Landmarks, headings, and whether anything about them takes a tab stop. */
function outline() {
  const nameOfRegion = (el) => {
    const lb = el.getAttribute("aria-labelledby");
    if (lb) return document.getElementById(lb)?.textContent?.trim() || "";
    return (el.getAttribute("aria-label") || "").trim();
  };
  const main = document.querySelector("main, [role=main]");
  const notebook = document.querySelector(".toolkit-notebook");
  const shelf = document.querySelector(".ops-panel aside, aside.ops-panel");
  const tray = document.querySelector(".toolkit-tray");
  const structural = [
    ...document.querySelectorAll("main, aside, h1, h2, h3, h4, h5, h6"),
  ];
  return {
    mainCount: document.querySelectorAll("main, [role=main]").length,
    mainName: main ? nameOfRegion(main) : null,
    mainIsNotebook: !!(main && notebook && main === notebook),
    notebookInMain: !!notebook?.closest("main, [role=main]"),
    headings: {
      h1: [...document.querySelectorAll("h1")].map((h) => h.textContent.trim()),
      h2: [...document.querySelectorAll("h2")].map((h) => h.textContent.trim()),
      h3: [...document.querySelectorAll("h3")].map((h) => h.textContent.trim()),
    },
    // The h1 wraps the top bar's rename control and must not put a box around
    // it. Left as an ordinary block heading the control goes back to being
    // `inline-block`, sits on a text baseline, and the line box's descender
    // space grows the bar by a pixel — which moves every pane below it.
    headingBoxes: [...document.querySelectorAll("h1")]
      .filter((h) => h.firstElementChild)
      .map((h) =>
        Math.round(h.getBoundingClientRect().height) -
        Math.round(h.firstElementChild.getBoundingClientRect().height)
      ),
    shelfTag: shelf?.tagName.toLowerCase() || null,
    shelfName: shelf ? nameOfRegion(shelf) : null,
    trayTag: tray?.tagName.toLowerCase() || null,
    trayName: tray ? nameOfRegion(tray) : null,
    // A landmark or a heading is not a control. If one has picked up a tab
    // stop, the ring the viewport-overflow spec pins has silently grown.
    focusableStructure: structural
      .filter((el) => el.hasAttribute("tabindex") && el.getAttribute("tabindex") !== "-1")
      .map((el) => `${el.tagName.toLowerCase()}[tabindex=${el.getAttribute("tabindex")}]`),
  };
}

describe.skipIf(!availability.ok)("the toolkit shell says what it is", () => {
  /** @type {Awaited<ReturnType<typeof serveDist>>} */
  let server;
  /** @type {import("playwright").Browser} */
  let browser;
  /** @type {import("playwright").Page} */
  let page;
  /** @type {ReturnType<typeof shelfNames>} */
  let rows;
  /** @type {ReturnType<typeof outline>} */
  let structure;

  beforeAll(async () => {
    const { chromium } = await import("playwright");
    server = await serveDist(DIST_ROOT);
    browser = await chromium.launch();
    // The width the defect was measured at, and the one where all three panes
    // are open at once.
    page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
    await page.waitForFunction(() => document.readyState === "complete");
    await page.waitForSelector(".ops-category code");
    await page.waitForTimeout(500);
    rows = await page.evaluate(shelfNames);
    structure = await page.evaluate(outline);
  });

  afterAll(async () => {
    await page?.close();
    await browser?.close();
    await server?.close();
  });

  it("finds the shelf it is measuring", () => {
    // A selector that has rotted returns an empty sweep, and an empty sweep
    // passes every assertion below it.
    expect(rows.filter((r) => r.add).length).toBeGreaterThan(40);
    expect(rows.filter((r) => !r.add).length).toBeGreaterThan(10);
  });

  it("names every add button for the op it adds", () => {
    const wrong = rows
      .filter((r) => r.add)
      .filter((r) => !r.name.toLowerCase().startsWith(`${r.op.toLowerCase()} `))
      .map((r) => `${r.op}: named from ${r.from} — ${JSON.stringify(r.name.slice(0, 90))}`);
    expect(wrong, `${wrong.length} add buttons do not open with their op:\n  ${wrong.join("\n  ")}`)
      .toEqual([]);
  });

  it("never announces a paragraph where a name belongs", () => {
    // 60 is well clear of the longest legitimate name here ("import PKCS#8 —
    // add to the recipe", 36) and well under the shortest doc that was being
    // read out in its place.
    const long = rows
      .filter((r) => r.glyphOnly && r.name.length > 60)
      .map((r) => `${r.op}: ${r.name.length} chars from ${r.from}`);
    expect(long, `glyph-only controls announcing prose:\n  ${long.join("\n  ")}`).toEqual([]);
  });

  it("keeps the doc as the description a pointer and a reader both get", () => {
    // The cheap way to pass the two assertions above is to delete `title`,
    // which would take the hover tooltip and the accessible description with
    // it. On a fitting row the tooltip *is* the documentation — these rows
    // have no ToolCard behind them, unlike the pair rows.
    const documented = rows.filter((r) => r.add && r.title.length > 100);
    expect(
      documented.length,
      "no add button carries its op's doc any more — the description was dropped, not moved"
    ).toBeGreaterThan(10);
    // …and the doc is the description, never the name.
    const asName = documented.filter((r) => r.name === r.title).map((r) => r.op);
    expect(asName, `docs being used as the accessible name: ${asName.join(", ")}`).toEqual([]);
  });

  it("leaves the pair rows naming their own direction", () => {
    // The control. These handles were already right — `base64 — encode` — and
    // a change to `AddButton` must not reach them. If this fails alongside the
    // assertions above, the sweep is measuring the wrong thing.
    const handles = rows.filter((r) => !r.add && r.glyphOnly);
    const wrong = handles
      .filter((r) => !/ — (encode|decode)(,|$)/.test(r.name))
      .map((r) => `${r.op}: ${JSON.stringify(r.name.slice(0, 90))}`);
    expect(handles.length).toBeGreaterThan(10);
    expect(wrong, `direction handles not naming their direction:\n  ${wrong.join("\n  ")}`).toEqual([]);
  });

  it("agrees with the browser's own name computation", async () => {
    // The sweep above is a local reimplementation of the accessible-name
    // algorithm, and a reimplementation that only ever checks itself can drift
    // anywhere. Playwright's `getByRole` resolves the name the way the spec
    // does, and `genkey` is the op whose 245-character doc was the original
    // report.
    const resolved = await page
      .getByRole("button", { name: "genkey — add to the recipe", exact: true })
      .count();
    expect(resolved, "playwright's accname does not see the name this file asserts").toBe(1);
  });

  it("puts the notebook in a main named by the notebook's title", () => {
    expect(structure.mainCount, "exactly one main per page").toBe(1);
    expect(structure.notebookInMain, "the notebook is not inside any main").toBe(true);
    expect(structure.mainIsNotebook, "main is not the notebook pane itself").toBe(true);
    // Named from the top bar's h1, which is the notebook's title control — so
    // renaming the notebook renames the landmark, and there is only ever one
    // copy of the string.
    expect(structure.mainName).toBe(structure.headings.h1[0]);
    expect(structure.mainName?.length, "the main landmark has no name").toBeGreaterThan(0);
  });

  it("gives the page an outline and every pane a named region", () => {
    expect(structure.headings.h1, "the page has no h1").toHaveLength(1);
    expect(structure.headings.h2).toEqual(expect.arrayContaining(["Toolkit", "Session tray"]));
    // The vault's heading is what the page had before any of this, and it
    // needs an h2 above it to hang from rather than being the whole outline.
    expect(structure.headings.h3).toContain("Your browser vault");
    expect(structure.shelfTag).toBe("aside");
    expect(structure.shelfName).toBe("Toolkit");
    expect(structure.trayTag).toBe("aside");
    expect(structure.trayName).toBe("Session tray");
  });

  it("costs the top bar no height", () => {
    // The heading is here for the outline and owes the picture nothing. A
    // non-zero difference is the bar growing around a control that has not
    // changed size — invisible in a screenshot, a pixel of drift on every
    // pane below it.
    expect(
      structure.headingBoxes,
      `an h1 is taller than the control inside it: ${structure.headingBoxes.join(", ")}`
    ).toEqual([0]);
  });

  it("adds no tab stop while doing it", () => {
    // `viewport-overflow.e2e.js` pins the ring's *order* at two widths;
    // cdf8f8c is what put the notebook 19th instead of 146th. This is the
    // narrower claim that belongs with the change that could break it: a
    // landmark and a heading are structure, and structure is not focusable.
    expect(
      structure.focusableStructure,
      `landmarks/headings took a tab stop: ${structure.focusableStructure.join(", ")}`
    ).toEqual([]);
  });
});
