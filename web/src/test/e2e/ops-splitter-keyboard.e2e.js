/**
 * The Toolkit splitter is operable by keyboard, and says where it is.
 *
 * `role="separator"` with `aria-label="Resize Toolkit panel"` had been on this
 * element with no `tabIndex` and no `onKeyDown` — a name announcing a control
 * that a keyboard could not reach, let alone move. Measured on the shipped
 * bundle before the repair: four hundred `Tab` presses never landed on it,
 * `element.focus()` did nothing, and `ArrowRight` left the panel at 220px.
 *
 * ## Why this is not in `viewport-overflow.e2e.js`
 *
 * That file's subject is what a real viewport does to widths, and it earns its
 * browser by measuring something no `environment: "node"` run can see. This
 * one earns the same browser for a different reason: focus. `tabIndex`,
 * `display: none`, and sequential focus navigation are decided by the layout
 * engine and by nothing in React, which is exactly why "a hidden control is
 * not in the tab ring" has to be pressed rather than reasoned about. The two
 * files meet at 1000px and disagree about nothing — that one asserts the
 * splitter is *drawn* in the second column, this one asserts it is *operable*
 * while it is.
 *
 * ## What is deliberately pinned
 *
 * The step sizes, because a keybinding is a promise about a specific amount:
 * "some number of pixels" is not a contract anyone can rely on, and a test
 * that accepts any nonzero movement passes with a 1px step that nobody could
 * use. The bounds are *not* pinned to literals — they are read off the
 * element's own `aria-valuemin`/`aria-valuemax` and then the keyboard is
 * asked to honour them. That is the sharper claim: it fails both when the
 * clamp goes away and when the advertised range and the enforced range drift
 * apart, which is the failure two copies of a clamping expression produce.
 *
 * Serves `dist/` like every spec here, so `npm run build` must have run.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DIST_ROOT, chromiumAvailability, serveDist } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the focus ring is measured in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[ops-splitter-keyboard.e2e] skipping — chromium not installed (${availability.reason})`);
}

/** One arrow press, in px, and the coarse step `Shift` buys. Must match `OPS_PANE_STEP`. */
const STEP = 16;
const COARSE = STEP * 4;

/** The desktop width where the workspace is still a row and the splitter is drawn. */
const WIDE = 1280;

/** localStorage key the panel width is remembered under (`LAYOUT_KEY`). */
const LAYOUT_KEY = "basilisk.toolkit.layout";

describe.skipIf(!availability.ok)("the Toolkit splitter is operable by keyboard", () => {
  /** @type {Awaited<ReturnType<typeof serveDist>>} */
  let server;
  /** @type {import("playwright").Browser} */
  let browser;

  beforeAll(async () => {
    const { chromium } = await import("playwright");
    server = await serveDist(DIST_ROOT);
    browser = await chromium.launch();
  });

  afterAll(async () => {
    await browser?.close();
    await server?.close();
  });

  /**
   * A loaded toolkit with the splitter focused, plus the two readings every
   * assertion below is made of.
   *
   * `newPage` is a fresh context, so each test starts with an empty
   * localStorage and the panel at its default — which matters, because half
   * of what is asserted here is what gets *written* to that storage.
   */
  async function open(width = WIDE) {
    const page = await browser.newPage({ viewport: { width, height: 900 } });
    await page.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
    await page.waitForFunction(() => document.readyState === "complete");
    await page.waitForFunction(() => Boolean(document.querySelector(".ops-panel")));
    await page.waitForTimeout(300);
    /** Panel width as laid out, and the value the splitter announces for it. */
    const read = () =>
      page.evaluate(() => {
        const sp = document.querySelector(".ops-splitter");
        const panel = document.querySelector(".ops-panel");
        return {
          painted: panel ? Math.round(panel.getBoundingClientRect().width) : null,
          announced: sp ? Number(sp.getAttribute("aria-valuenow")) : null,
          stored: window.localStorage.getItem("basilisk.toolkit.layout"),
        };
      });
    /** The range the element publishes, which the keyboard then has to honour. */
    const bounds = () =>
      page.evaluate(() => {
        const sp = document.querySelector(".ops-splitter");
        return { min: Number(sp.getAttribute("aria-valuemin")), max: Number(sp.getAttribute("aria-valuemax")) };
      });
    return { page, read, bounds };
  }

  /**
   * Focus by pressing `Tab`, never by calling `.focus()`.
   *
   * The defect was a control that could not be *reached*, and `.focus()`
   * reaches things sequential navigation does not — a `tabindex="-1"` div
   * takes it happily. So the reachability claim and every operability claim
   * below are made through the same ring a person walks. Returns the number
   * of presses it took, or -1.
   */
  async function tabToSplitter(page, limit = 400) {
    await page.evaluate(() => document.body.focus());
    for (let i = 1; i <= limit; i++) {
      await page.keyboard.press("Tab");
      const hit = await page.evaluate(() =>
        Boolean(document.activeElement?.classList?.contains("ops-splitter"))
      );
      if (hit) return i;
    }
    return -1;
  }

  it("is reachable by Tab, and sits with the pane it resizes", async () => {
    const { page } = await open();
    try {
      const presses = await tabToSplitter(page);
      expect(presses, "Tab never reached the splitter in 400 presses").toBeGreaterThan(0);

      // Where it landed, relative to the two panes on either side of it in the
      // document. Immediately after the panel's last control is the position
      // that makes sense — you walk the panel, and the last stop is the handle
      // for the panel's width — and before the tray, which comes after it in
      // source. Asserted as containment rather than an index, because the
      // shelf's control count is content, not contract.
      const place = await page.evaluate(() => {
        const sp = document.querySelector(".ops-splitter");
        const ops = document.querySelector(".ops-panel");
        const tray = document.querySelector(".toolkit-tray");
        const ring = [
          ...document.querySelectorAll(
            'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]),' +
              ' textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'
          ),
        ].filter((el) => el.getClientRects().length > 0);
        const at = ring.indexOf(sp);
        const lastOps = ring.reduce((acc, el, i) => (ops.contains(el) ? i : acc), -1);
        const firstTray = ring.findIndex((el) => tray.contains(el));
        return { at, lastOps, firstTray, insidePane: ops.contains(sp) };
      });
      expect(place.insidePane, "the splitter must be its own stop, not a control inside the panel").toBe(false);
      expect(place.lastOps, `the panel has nothing tabbable in it: ${JSON.stringify(place)}`).toBeGreaterThan(-1);
      expect(place.at, `the splitter comes before the panel it resizes: ${JSON.stringify(place)}`).toBeGreaterThan(
        place.lastOps
      );
      expect(place.at, `the splitter comes after the tray: ${JSON.stringify(place)}`).toBeLessThan(place.firstTray);
    } finally {
      await page.close();
    }
  });

  it("moves the panel edge the way the arrow points, and says so", async () => {
    const { page, read } = await open();
    try {
      expect(await tabToSplitter(page)).toBeGreaterThan(0);
      const start = await read();
      expect(start.announced, "aria-valuenow does not match the painted width").toBe(start.painted);

      await page.keyboard.press("ArrowRight");
      const wider = await read();
      // The panel is drawn to the left of the handle, so Right widens it.
      expect(wider.painted, "ArrowRight did not widen the panel by one step").toBe(start.painted + STEP);
      expect(wider.announced, "aria-valuenow did not follow the width it announces").toBe(wider.painted);

      await page.keyboard.press("ArrowLeft");
      expect((await read()).painted, "ArrowLeft did not undo ArrowRight").toBe(start.painted);

      await page.keyboard.press("Shift+ArrowRight");
      expect((await read()).painted, "Shift did not buy the coarse step").toBe(start.painted + COARSE);
    } finally {
      await page.close();
    }
  });

  it("holds to the range it advertises, from either end", async () => {
    const { page, read, bounds } = await open();
    try {
      expect(await tabToSplitter(page)).toBeGreaterThan(0);
      const { min, max } = await bounds();
      expect(min, "the splitter advertises no range").toBeGreaterThan(0);
      expect(max).toBeGreaterThan(min);

      await page.keyboard.press("End");
      expect((await read()).painted, "End is not the advertised maximum").toBe(max);
      for (let i = 0; i < 6; i++) await page.keyboard.press("ArrowRight");
      const overMax = await read();
      expect(overMax.painted, "six presses past End went over the advertised maximum").toBe(max);
      expect(overMax.announced, "the announced value went over its own maximum").toBe(max);

      await page.keyboard.press("Home");
      expect((await read()).painted, "Home is not the advertised minimum").toBe(min);
      for (let i = 0; i < 6; i++) await page.keyboard.press("Shift+ArrowLeft");
      const underMin = await read();
      expect(underMin.painted, "six coarse presses past Home went under the advertised minimum").toBe(min);
      expect(underMin.announced, "the announced value went under its own minimum").toBe(min);
    } finally {
      await page.close();
    }
  });

  it("remembers a width set by key, across a reload", async () => {
    const { page, read } = await open();
    try {
      expect(await tabToSplitter(page)).toBeGreaterThan(0);
      const start = await read();
      await page.keyboard.press("ArrowRight");
      await page.keyboard.press("ArrowRight");
      const set = await read();
      expect(set.painted).toBe(start.painted + 2 * STEP);
      // The drag persists on `pointerup`; a key press has no such end, so the
      // write has to happen per press or not at all.
      expect(
        JSON.parse(set.stored ?? "{}").opsW,
        `the keyboard width was not stored: ${set.stored}`
      ).toBe(set.painted);

      await page.reload({ waitUntil: "load" });
      await page.waitForFunction(() => document.readyState === "complete");
      await page.waitForFunction(() => Boolean(document.querySelector(".ops-panel")));
      await page.waitForTimeout(300);
      expect((await read()).painted, "the width did not survive a reload").toBe(set.painted);
    } finally {
      await page.close();
    }
  });

  /**
   * The two roads to reset must arrive at the same place, storage included.
   *
   * Not just the same pixel width — the same *stored state*. Reset means "no
   * preference", written as `opsW: null` and dropped by `saveToolkitLayout`,
   * so afterwards the key is absent. A copy of the reset that wrote today's
   * default instead would paint identically and be a different thing: it
   * would pin 220 into storage and outlive any change to the default. Which
   * is the only version of this that a width-only assertion would miss.
   */
  it("resets to the same place from the keyboard and from the pointer", async () => {
    const { page, read } = await open();
    try {
      expect(await tabToSplitter(page)).toBeGreaterThan(0);

      await page.keyboard.press("End");
      await page.keyboard.press("Enter");
      const byKey = await read();

      await page.keyboard.press("End");
      expect((await read()).painted, "End did not move the panel off the default").not.toBe(byKey.painted);
      await page.dblclick(".ops-splitter");
      await page.waitForTimeout(80);
      const byPointer = await read();

      expect(byPointer.painted, "double-click and Enter reset to different widths").toBe(byKey.painted);
      expect(
        [JSON.parse(byKey.stored ?? "{}").opsW, JSON.parse(byPointer.stored ?? "{}").opsW],
        `reset must clear the stored width, not store the default: key ${byKey.stored}, pointer ${byPointer.stored}`
      ).toEqual([undefined, undefined]);
    } finally {
      await page.close();
    }
  });

  /**
   * Below 1000px the splitter is `display: none`, and a control that is not
   * displayed must not be a tab stop.
   *
   * `tabIndex` and `display` interact through layout and not through React,
   * so this is pressed rather than assumed: `.focus()` on a `display: none`
   * element is a no-op, which is what makes the hiding sufficient and a
   * `tabIndex={0}` written unconditionally safe. The key press afterwards is
   * the part that would catch a handler wired somewhere it could still fire
   * with the element gone — stacked, the panes do not share a width, so there
   * is nothing for a resize to mean.
   */
  for (const width of [375, 768]) {
    it(`is out of reach while it is hidden, at ${width}px`, async () => {
      const { page, read } = await open(width);
      try {
        const state = await page.evaluate(() => {
          const sp = document.querySelector(".ops-splitter");
          sp.focus();
          return {
            present: Boolean(sp),
            display: getComputedStyle(sp).display,
            rendered: sp.getClientRects().length,
            took: document.activeElement === sp,
          };
        });
        expect(state.present, "the splitter is not in the document at all").toBe(true);
        expect(state.display, "the stacked layout is drawing the splitter").toBe("none");
        expect(state.rendered, "a hidden splitter still has a box").toBe(0);
        expect(state.took, "a hidden splitter took focus").toBe(false);

        const before = await read();
        await page.keyboard.press("ArrowRight");
        await page.waitForTimeout(80);
        expect((await read()).painted, "a key moved a pane that no longer shares its width").toBe(before.painted);
      } finally {
        await page.close();
      }
    });
  }
});
