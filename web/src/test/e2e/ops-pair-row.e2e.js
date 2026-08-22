/**
 * A conjugate row in the ops shelf is two ops, and says so.
 *
 * `listDrawerRows` has built every conjugate row with a `caption` since it was
 * written — the step's `pairCaption`, or `forward / reverse` assembled from
 * the two labels — and **nothing read it**. `OpsShelf.tsx` contained zero
 * references to `.caption`. So the row was named by whichever of its two ops
 * the registry happened to list first: measured on `dist/` at 1440×900 with an
 * empty notebook, all 14 conjugate rows on the default page announced nothing
 * at all as a row, and the card a pointer opened on the OpenPGP row was headed
 * `gpg.encrypt` / `Recipe gpg.encrypt` / `Outputs` — a card describing a sink,
 * on a row whose other half is a source called `gpg.decrypt` that appears
 * nowhere in it. A field computed and never read is the defect this repo keeps
 * finding, and this is the presentational half of it.
 *
 * The other half is art. `STEP_GLYPHS` gives five of the browse tree's
 * conjugate pairs two glyphs rather than one — `gpg-encrypt`/`gpg-decrypt`,
 * `split`/`recover`, `input`/`out`, `file-read`/`file-save` — and the reverse
 * op of a pair is never rendered anywhere (`listDrawerRows` drops it with
 * `if (s.conjugateOf) continue` and `OpsTile` draws the forward op's glyph), so
 * `gpg-decrypt` was in the bundle and on no screen. Both direction handles
 * drew the same two chevrons every other row draws.
 *
 * ## What each claim here is worth, and what it is not
 *
 * The row's printed `<code>` is deliberately **unchanged** and asserted to be
 * unchanged. That column is monospace and every string in it is a token you
 * can type into a recipe, drag into a cell, and find again by searching for
 * it; `gpg` is not an op and could not be run, and the shelf filters on op
 * names, so a row printing its family name would stop matching the query that
 * found it. The family name goes where it costs no pixels and no token: the
 * row's accessible name as a `group`, and the card's eyebrow.
 *
 * The glyph claim is made against `GLYPH_PATHS` itself, by comparing the `d`
 * attributes the page actually painted with the ones the registry declares —
 * geometry, not markup, because React serialises `<path … />` as
 * `<path …></path>` and a string compare would be asserting the serialiser.
 * `gpg.sign` is the control in the same assertion: its pair has one asset, so
 * it must still draw the chevrons. A change that put op art on every handle
 * would pass the `gpg.encrypt` half and fail there.
 *
 * The card claim reads the card's `<header>` and not the card, because
 * `gpg.encrypt`'s own doc is 500 characters about decrypting and would satisfy
 * any containment check run against the whole thing — the same trap that let a
 * name assertion pass on a broken page in 191f2ed (`genkey`'s doc contains
 * "genkey").
 *
 * Serves `dist/` like every spec here, so `npm run build` must have run.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GLYPH_PATHS } from "../../lib/toolkit/glyphs.js";
import { DIST_ROOT, chromiumAvailability, serveDist } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the shelf is measured in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[ops-pair-row.e2e] skipping — chromium not installed (${availability.reason})`);
}

/** The `d` of every path in a glyph body, in order. What was painted, not how. */
function pathData(svgInner) {
  return [...String(svgInner || "").matchAll(/\sd="([^"]*)"/g)].map((m) => m[1]);
}

/**
 * Runs in the page. Every conjugate row, as the browser sees it.
 *
 * A conjugate row is identified by shape rather than by a class: one `<code>`
 * and exactly two buttons beside it. Solo rows have one button (the `+`), so
 * the two kinds cannot be confused, and a row that lost a handle would drop
 * out of the sweep — which is what the sentinel below is for.
 */
function pairRows() {
  const nameOf = (el) => {
    const lb = el.getAttribute("aria-labelledby");
    if (lb) {
      const t = lb
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() || "")
        .join(" ")
        .trim();
      if (t) return t;
    }
    const al = el.getAttribute("aria-label");
    if (al && al.trim()) return al.trim();
    const txt = (el.textContent || "").trim();
    if (txt) return txt;
    return (el.getAttribute("title") || "").trim();
  };

  /**
   * A `group` is not named by its contents — `nameFromContent` is false for
   * the role — so the row's name is aria-labelledby, aria-label, title, and
   * then nothing. Written separately from `nameOf` above, because sharing the
   * button's algorithm let the row "pass" on a page with no label at all: it
   * fell through to the row's own text, which is the op name and the caret
   * caption run together, and that is neither empty nor equal to the op.
   */
  const nameOfGroup = (el) => {
    const lb = el.getAttribute("aria-labelledby");
    if (lb) {
      const t = lb
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() || "")
        .join(" ")
        .trim();
      if (t) return t;
    }
    const al = el.getAttribute("aria-label");
    if (al && al.trim()) return al.trim();
    return (el.getAttribute("title") || "").trim();
  };

  const rows = [];
  for (const code of document.querySelectorAll(".ops-category code")) {
    const row = code.parentElement;
    const buttons = [...row.querySelectorAll("button")];
    if (buttons.length !== 2) continue;
    rows.push({
      /** The token printed in the row's mono column. */
      op: (code.textContent || "").trim(),
      role: row.getAttribute("role"),
      groupName: nameOfGroup(row),
      handles: buttons.map((b) => ({
        name: nameOf(b),
        dir: b.getAttribute("data-dir"),
        svg: b.querySelector("svg")?.innerHTML || "",
        text: (b.textContent || "").trim(),
      })),
    });
  }
  return rows;
}

describe.skipIf(!availability.ok)("a conjugate row in the ops shelf is two ops", () => {
  /** @type {Awaited<ReturnType<typeof serveDist>>} */
  let server;
  /** @type {import("playwright").Browser} */
  let browser;
  /** @type {import("playwright").Page} */
  let page;
  /** @type {ReturnType<typeof pairRows>} */
  let rows;

  beforeAll(async () => {
    const { chromium } = await import("playwright");
    server = await serveDist(DIST_ROOT);
    browser = await chromium.launch();
    page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
    await page.waitForFunction(() => document.readyState === "complete");
    await page.waitForSelector(".ops-category code");
    await page.waitForTimeout(500);
    rows = await page.evaluate(pairRows);
  });

  afterAll(async () => {
    await page?.close();
    await browser?.close();
    await server?.close();
  });

  const rowFor = (op) => rows.find((r) => r.op === op);

  it("finds the conjugate rows it is measuring", () => {
    // A selector that has rotted returns an empty sweep, and an empty sweep
    // passes every assertion below it. 14 rows on the default page; the floor
    // is well under that and well over zero.
    expect(rows.length, "no conjugate rows found in the shelf at all").toBeGreaterThan(8);
    expect(rowFor("gpg.encrypt"), "the OpenPGP row this file is about is not on the page").toBeTruthy();
    expect(rowFor("gpg.sign"), "the control row is not on the page").toBeTruthy();
  });

  it("names each row for the pair, not for whichever op came first", () => {
    const unnamed = rows.filter((r) => r.role !== "group" || !r.groupName).map((r) => r.op);
    expect(unnamed, `conjugate rows announcing nothing as a row: ${unnamed.join(", ")}`).toEqual([]);

    // The cheap way to satisfy the line above is to label the row with the op
    // it already prints, which is the state being fixed: a row called
    // `gpg.encrypt` that is also `gpg.decrypt`. Compared case-sensitively and
    // on purpose — `blip39`'s caption is "BLIP39", the closest any row comes
    // to its own token, and a fallback to `s.name` would collapse it exactly.
    const selfNamed = rows.filter((r) => r.groupName === r.op).map((r) => r.op);
    expect(
      selfNamed,
      `rows named by one of their two ops rather than by the pair: ${selfNamed.join(", ")}`
    ).toEqual([]);
  });

  it("keeps the printed token a token", () => {
    // The counterweight to the assertion above, and the reason the family name
    // went to the group and not to the `<code>`. Every string in that column
    // is something you can type; a row reading `gpg` or `Encrypt / decrypt`
    // would be a name in the recipe's own font that the recipe cannot parse.
    expect(rowFor("gpg.encrypt").op).toBe("gpg.encrypt");
    expect(rowFor("sss.split").op).toBe("sss.split");
  });

  it("resolves that name through the browser's own accname", async () => {
    // The sweep above is a local reimplementation of the accessible-name
    // algorithm and a reimplementation that only checks itself can drift
    // anywhere. Playwright resolves the name the way the spec does — and this
    // asks for the group *by* the caption, which is the string that had no
    // consumer at all.
    const group = page.getByRole("group", { name: "Encrypt / decrypt", exact: true });
    expect(await group.count(), "no group is named by the OpenPGP row's caption").toBe(1);
    // …and it is the row with both ops on it, not some other element that
    // happens to carry the words.
    expect(await group.getByRole("button", { name: "gpg.encrypt — encode" }).count()).toBe(1);
    expect(await group.getByRole("button", { name: "gpg.decrypt — decode" }).count()).toBe(1);
  });

  it("draws the pair's own art where the registry gives it two glyphs", () => {
    const gpg = rowFor("gpg.encrypt");
    // `gpg.encrypt` is a sink and `gpg.decrypt` a source: the second handle
    // does not run the first one backwards, it starts the value afresh. Two
    // mirrored chevrons say it does. A sealed padlock and an opened one are
    // what the registry already had to say instead.
    expect(pathData(gpg.handles[0].svg), "the encode handle is not drawing gpg-encrypt").toEqual(
      pathData(GLYPH_PATHS["gpg-encrypt"])
    );
    expect(pathData(gpg.handles[1].svg), "the decode handle is not drawing gpg-decrypt").toEqual(
      pathData(GLYPH_PATHS["gpg-decrypt"])
    );
    // Not vacuous by accident: the two glyphs must differ, or the assertion
    // above would also pass with one asset painted twice.
    expect(pathData(GLYPH_PATHS["gpg-encrypt"])).not.toEqual(pathData(GLYPH_PATHS["gpg-decrypt"]));

    const splits = rowFor("sss.split");
    expect(pathData(splits.handles[0].svg)).toEqual(pathData(GLYPH_PATHS["split"]));
    expect(pathData(splits.handles[1].svg)).toEqual(pathData(GLYPH_PATHS["recover"]));
  });

  it("leaves the arrows on the rows whose pair has one glyph", () => {
    // The control, and the half a "put the op's glyph on every handle" change
    // would break. `gpg.sign` and `gpg.verify` share `gpg-sign`, `wrap` and
    // `unwrap` share `wrap` — painting one asset on both handles would say
    // nothing and cost the only mark that distinguishes them.
    for (const op of ["gpg.sign", "wrap", "stream.seal"]) {
      const row = rowFor(op);
      expect(row, `${op} is not on the page`).toBeTruthy();
      expect(pathData(row.handles[0].svg), `${op}'s encode handle lost its arrow`).toEqual(
        pathData(GLYPH_PATHS["encode"])
      );
      expect(pathData(row.handles[1].svg), `${op}'s decode handle lost its arrow`).toEqual(
        pathData(GLYPH_PATHS["decode"])
      );
    }
  });

  it("still lets every handle name its own op and direction", () => {
    // The control 191f2ed left behind, re-made here because this change is
    // exactly the kind that breaks it: a glyph-only button whose art now
    // carries meaning is one step from being thought to name itself. The art
    // is `aria-hidden` and the name is still text.
    const wrong = [];
    for (const r of rows) {
      for (const h of r.handles) {
        if (!/ — (encode|decode)(,|$)/.test(h.name)) wrong.push(`${r.op}: ${JSON.stringify(h.name)}`);
        if (h.text.length > 0) wrong.push(`${r.op}: handle has text content ${JSON.stringify(h.text)}`);
      }
    }
    expect(wrong, `handles not naming their direction:\n  ${wrong.join("\n  ")}`).toEqual([]);
    // Every name opens with an op name, so the family name on the group never
    // became the only thing said.
    const gpg = rowFor("gpg.encrypt");
    expect(gpg.handles[0].name.startsWith("gpg.encrypt ")).toBe(true);
    expect(gpg.handles[1].name.startsWith("gpg.decrypt ")).toBe(true);
  });

  it("hides the art from the name computation", async () => {
    const hidden = await page.evaluate(() =>
      [...document.querySelectorAll(".ops-category button svg")].every(
        (s) => s.getAttribute("aria-hidden") === "true" && s.getAttribute("focusable") === "false"
      )
    );
    expect(hidden, "a glyph inside a button is exposed to the accessibility tree").toBe(true);
  });

  it("opens a card that names the pair and the other direction", async () => {
    // The shelf is a scroll area and the OpenPGP row is below the fold on a
    // 900px viewport, so the row has to be brought into view before its box
    // means anything — a `mouse.move` to a clipped coordinate hovers whatever
    // is actually painted there, which is nothing.
    const row = await page.evaluateHandle(() => {
      const code = [...document.querySelectorAll(".ops-category code")].find(
        (c) => c.textContent.trim() === "gpg.encrypt"
      );
      return code?.parentElement || null;
    });
    await row.asElement().scrollIntoViewIfNeeded();
    await page.waitForTimeout(200);
    const box = await row.asElement().boundingBox();
    // Two moves, because the card is a Radix tooltip and Radix opens on
    // pointer *enter*. A single `mouse.move` from wherever the pointer already
    // is can land inside the row without ever crossing its boundary.
    await page.mouse.move(700, 400);
    await page.mouse.move(box.x + 20, box.y + box.height / 2, { steps: 8 });
    await page.waitForSelector(".tool-card", { timeout: 10000 });
    await page.waitForTimeout(300);

    // The header, not the card. `gpg.encrypt`'s doc is five hundred characters
    // that include "decrypted back", so a containment check against the whole
    // card passes on the page this file exists to describe.
    const head = await page.evaluate(() =>
      document.querySelector(".tool-card header")?.textContent?.trim() || ""
    );
    expect(head, "the card header does not name the pair").toContain("Encrypt / decrypt");
    expect(head, "the card header does not name the op it documents").toContain("gpg.encrypt");
    expect(head, "the card header does not name the other direction").toContain("gpg.decrypt");

    // …and it is still the forward op's card, not a summary that replaced it.
    const body = await page.evaluate(() =>
      document.querySelector(".tool-card")?.textContent?.trim() || ""
    );
    expect(body, "the card stopped documenting the op's params").toContain("PKESK");
  });
});
