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
 * The row's printed `<code>` **has changed**, and the assertion that pinned it
 * is turned over below rather than deleted. It read `gpg.encrypt` and now
 * reads `gpg`, with `encrypt` and `decrypt` on the two handles — the owner's
 * call, over the argument this file used to carry. That argument was that the
 * column is a token you can type, and it is answered rather than merely
 * overruled: the *row* is the token now, the assertion below requires the
 * family plus the word on the handle to be exactly the op that handle
 * announces, and a second one requires both spellings to still reach this row
 * through the search field. A column printing a name nothing could find would
 * still be the defect the old assertion guarded against; that is the claim,
 * and it is checked rather than asserted away.
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
    const handles = buttons.map((b) => ({
      name: nameOf(b),
      dir: b.getAttribute("data-dir"),
      svg: b.querySelector("svg")?.innerHTML || "",
      text: (b.textContent || "").trim(),
    }));
    rows.push({
      /**
       * The op the row is *about*, which is no longer the string it prints.
       * Taken from the forward handle's accessible name, which opens with the
       * op and is asserted to below — so a row that stopped naming its own op
       * falls out of every lookup here at once and the sentinel catches it,
       * rather than each assertion quietly reading `undefined`.
       */
      /* The name is the op, plus `, unavailable: …` when the caret does not
       * fit it. It used to carry ` — encode` as well, which is why this once
       * split on the dash; the button prints the direction now, so the name
       * stopped repeating it. Strip only the reason. */
      op: handles[0].name.split(", unavailable:")[0],
      /** The family printed in the row's mono column — "" where there is none. */
      family: (code.textContent || "").trim(),
      role: row.getAttribute("role"),
      groupName: nameOfGroup(row),
      handles,
    });
  }
  return rows;
}

/**
 * Whether anything on a conjugate row is cut off, as the browser lays it out.
 *
 * The row grew from a name and two squares to a name and two named buttons,
 * and `symencrypt` / `symdecrypt` is 166px of handles for a 131px line at the
 * panel's 160px minimum. The answer is `flex-wrap` — the handles move to a
 * second line together, then stack — and the thing worth pinning is not which
 * of those three shapes a given width produces but that none of them is the
 * fourth one: a handle hanging over the panel edge, or a name shortened to fit.
 *
 * `scrollWidth > clientWidth` is the test for a clipped string, and the box
 * comparison is the test for one that escaped its row. Both are read off the
 * built page, because this is a claim about layout and there is nowhere else
 * to read it.
 */
function rowOverflow() {
  const bad = [];
  for (const code of document.querySelectorAll(".ops-category code")) {
    const row = code.parentElement;
    const buttons = [...row.querySelectorAll("button")];
    if (buttons.length !== 2) continue;
    const rb = row.getBoundingClientRect();
    const at = `${code.textContent.trim() || "\u2205"}|${buttons
      .map((b) => b.textContent.trim())
      .join("|")}`;
    if (code.scrollWidth > code.clientWidth + 1) bad.push(`${at}: family is clipped`);
    for (const b of buttons) {
      const bb = b.getBoundingClientRect();
      if (b.scrollWidth > b.clientWidth + 1) {
        bad.push(`${at}: handle ${JSON.stringify(b.textContent.trim())} is clipped`);
      }
      if (bb.left < rb.left - 0.5 || bb.right > rb.right + 0.5) {
        bad.push(`${at}: handle ${JSON.stringify(b.textContent.trim())} is outside the row`);
      }
    }
  }
  const cat = document.querySelector(".ops-category");
  return { bad, rows: document.querySelectorAll(".ops-category code").length, cat: [cat.scrollWidth, cat.clientWidth] };
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
  /** query → the conjugate rows it leaves on the shelf, `family|fwd|rev`. */
  let searched = {};

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

    // The caret's fit filter collapses a toolbox at zero fit, and a collapsed
    // toolbox renders none of the rows a query selected — which would make
    // every search below "fail" for a reason that has nothing to do with the
    // search. `Show all` suspends the fit filter; the query is what is being
    // measured.
    await page.getByRole("button", { name: /Show all/ }).first().click();
    await page.waitForTimeout(200);
    for (const q of [
      "gpg.encrypt",
      "gpg.decrypt",
      "symdecrypt",
      "unwrap",
      "gpg.genkey",
    ]) {
      await page.fill(".ops-panel input", q);
      await page.waitForTimeout(250);
      searched[q] = await page.evaluate(() =>
        [...document.querySelectorAll(".ops-category code")]
          .filter((c) => c.parentElement.querySelectorAll("button").length === 2)
          .map((c) => {
            const bs = [...c.parentElement.querySelectorAll("button")];
            return [c.textContent.trim(), ...bs.map((b) => b.textContent.trim())].join("|");
          })
      );
    }
    await page.fill(".ops-panel input", "");
    await page.waitForTimeout(250);
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
    // The search sweep runs once up there for the same reason this one does:
    // an empty map would satisfy its assertions by handing back `undefined`.
    expect(Object.keys(searched).length, "the search sweep never ran").toBe(5);
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

  it("prints the family, and spells the whole op across the row", () => {
    // The turned-over assertion. It used to read
    //   expect(rowFor("gpg.encrypt").op).toBe("gpg.encrypt")
    // and it was guarding something real: that column is monospace and every
    // string in it was a name you could type. The owner's call is that the row
    // says `gpg` with `encrypt` and `decrypt` on the buttons, so the claim
    // moves from the column to the row and gets stricter on the way — every
    // handle, on every conjugate row, has to spell its own op out of the
    // family beside it. A friendly verb (`Encrypt`, or `otp.uri`'s `Build`)
    // or an abbreviation would satisfy "prints something" and fails this.
    expect(rowFor("gpg.encrypt").family).toBe("gpg");
    expect(rowFor("gpg.encrypt").handles.map((h) => h.text)).toEqual(["encrypt", "decrypt"]);

    const wrong = [];
    for (const r of rows) {
      for (const h of r.handles) {
        const op = h.name.split(", unavailable:")[0];
        const spelled = r.family ? `${r.family}.${h.text}` : h.text;
        if (spelled !== op) wrong.push(`${op}: the row spells ${JSON.stringify(spelled)}`);
      }
    }
    expect(wrong, `handles that do not spell their own op:\n  ${wrong.join("\n  ")}`).toEqual([]);

    // …and a row whose two ops share nothing prints no family rather than one
    // of the two names. `wrap` / `unwrap` have only their toolbox in common,
    // and the section header above them is already printing it.
    expect(rowFor("wrap").family).toBe("");
    // The families are what separates two rows the section cannot: these are
    // both toolbox `sss`, both `split` / `combine`.
    expect(rowFor("sss.split").family).toBe("sss");
    expect(rowFor("vss.split").family).toBe("vss");
  });

  it("still finds this row by either of the two names it now shows", () => {
    // The other half of the turned-over claim, and the defect 4eddc32
    // reported and left open. `listDrawerRows` draws a pair on its forward op
    // and drops the reverse, so a query matching only the reverse rendered no
    // row at all — typing `unwrap` produced nothing. Survivable while `unwrap`
    // was on no screen; the handle prints it now.
    expect(searched["gpg.encrypt"], "`gpg.encrypt` reaches no row").toContain("gpg|encrypt|decrypt");
    expect(searched["gpg.decrypt"], "`gpg.decrypt` reaches no row").toContain("gpg|encrypt|decrypt");
    expect(searched["symdecrypt"], "`symdecrypt` reaches no row").toContain(
      "gpg|symencrypt|symdecrypt"
    );
    // The reverse half of a row that prints no family at all.
    expect(searched["unwrap"], "`unwrap` reaches no wrap row").toContain("|wrap|unwrap");
    // The control, and what stops "follow the conjugate" from becoming "match
    // everything": a solo op pulls no pair row in behind it.
    expect(searched["gpg.genkey"], "a solo query dragged a pair row in").toEqual([]);
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
    expect(await group.getByRole("button", { name: "gpg.encrypt", exact: true }).count()).toBe(1);
    expect(await group.getByRole("button", { name: "gpg.decrypt", exact: true }).count()).toBe(1);
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
        // The direction used to live in the name because the handle was a
        // wordless chevron. It is the button's own word now, so the claim moved
        // with it: the handle *says* its direction rather than announcing it
        // twice. `blip39.encode — encode` is what this used to permit.
        if (!/^(encode|decode|[a-z0-9.-]+)$/.test(h.text) || !h.text)
          wrong.push(`${r.op}: ${JSON.stringify(h.text)}`);
        // Turned over, not dropped. This read `h.text.length > 0`, because
        // the handles were glyph-only and the risk was art being taken for
        // a name. They carry a word now, on purpose, so the claim becomes
        // the one that still bites: the name a reader hears opens with the
        // *whole* op, not with the short word the button shows. A handle
        // announcing `encrypt — encode` would have satisfied the old check
        // and fails this one.
        // No `h.text &&` guard: a handle that lost its word would slip
        // through one, and every handle on a conjugate row has one. A row
        // that genuinely draws an empty spacer has no accessible name either,
        // and the check above it reports that first.
        if (!h.name.startsWith(`${r.family ? `${r.family}.` : ""}${h.text}`)) {
          wrong.push(
            `${r.op}: handle says ${JSON.stringify(h.text)}, announces ${JSON.stringify(h.name)}`
          );
        }
      }
    }
    expect(wrong, `handles not naming their direction:\n  ${wrong.join("\n  ")}`).toEqual([]);
    // Every name opens with an op name, so the family name on the group never
    // became the only thing said.
    const gpg = rowFor("gpg.encrypt");
    expect(gpg.handles[0].name.startsWith("gpg.encrypt")).toBe(true);
    expect(gpg.handles[1].name.startsWith("gpg.decrypt")).toBe(true);
    // …and the visible word is inside the name it labels (WCAG 2.5.3), which
    // is what lets someone say "encrypt" to a voice control and hit the button
    // they are looking at.
    expect(gpg.handles[0].name).toContain(gpg.handles[0].text);
  });

  it("hides the art from the name computation", async () => {
    const hidden = await page.evaluate(() =>
      [...document.querySelectorAll(".ops-category button svg")].every(
        (s) => s.getAttribute("aria-hidden") === "true" && s.getAttribute("focusable") === "false"
      )
    );
    expect(hidden, "a glyph inside a button is exposed to the accessibility tree").toBe(true);
  });

  it("fits the panel at its default width and at its minimum", async () => {
    // `OPS_PANE_LIMITS` is { min: 160, max: 520, def: 220 }, and both ends are
    // measured rather than assumed. `symencrypt` / `symdecrypt` is the worst
    // case in the registry and is on the page at both.
    const measured = {};
    for (const width of [220, 160]) {
      const p2 = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      // The same key `ToolkitShell` reads its pane layout back out of.
      await p2.addInitScript((w) => {
        localStorage.setItem("basilisk.toolkit.layout", JSON.stringify({ opsW: w }));
      }, width);
      await p2.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
      await p2.waitForSelector(".ops-category code");
      // Every toolbox open, so the sweep sees the OpenPGP rows and not just
      // whatever the caret happens to leave expanded.
      await p2.getByRole("button", { name: /Show all/ }).first().click();
      await p2.waitForTimeout(400);
      measured[width] = await p2.evaluate(rowOverflow);
      await p2.close();
    }
    for (const width of [220, 160]) {
      const m = measured[width];
      // An empty sweep passes; so does one taken before the shelf rendered.
      expect(m.rows, `nothing on the shelf at ${width}px`).toBeGreaterThan(20);
      expect(
        m.bad,
        `at ${width}px the row does not fit:\n  ${m.bad.join("\n  ")}`
      ).toEqual([]);
      // …and the shelf itself does not scroll sideways to make room, which is
      // the other way a row can "fit" while being unreadable.
      expect(m.cat[0], `the shelf overflows horizontally at ${width}px`).toBe(m.cat[1]);
    }
  });

  it("opens a card that names the pair and the other direction", async () => {
    // The shelf is a scroll area and the OpenPGP row is below the fold on a
    // 900px viewport, so the row has to be brought into view before its box
    // means anything — a `mouse.move` to a clipped coordinate hovers whatever
    // is actually painted there, which is nothing.
    const row = await page.evaluateHandle(() => {
      // Found by the handle's name, not the mono column: that column prints
      // `gpg` now, and three rows share it.
      const btn = [...document.querySelectorAll(".ops-category button")].find(
        (b) => b.getAttribute("aria-label") === "gpg.encrypt"
      );
      return btn?.closest("[role=group]") || null;
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
