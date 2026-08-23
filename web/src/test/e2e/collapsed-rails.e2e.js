/**
 * A collapsed pane is still a control, and still has to leave the row.
 *
 * Both side panes collapse to a 28px vertical strip — `.ops-rail` on the left,
 * `.tray-rail` on the right — and `cdf8f8c` drove those states by hand at both
 * widths without leaving anything behind. The layout suite covers the default
 * state only, so the two states a person reaches by pressing Collapse were
 * pinned by nothing.
 *
 * ## What is actually at risk here
 *
 * The rails are the one part of the workspace whose *width* is set twice. The
 * markup asks for `w-[28px]`, and a media query at the stacking width overrides
 * it with `width: auto`, because a 28px vertical strip is meaningless once the
 * three columns become three stacked rows — it would be a 28px-wide sliver of a
 * full-width row with its label written sideways. That override is a
 * two-class selector beating a utility class, which is exactly the kind of
 * thing that survives a refactor by luck.
 *
 * So this asserts the collapsed pane at both widths: a strip when the row is a
 * row, and not a strip when it is not.
 *
 * Serves `dist/` like every spec here, so `npm run build` must have run.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DIST_ROOT, chromiumAvailability, serveDist } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the rails are measured in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[collapsed-rails.e2e] skipping — chromium not installed (${availability.reason})`);
}

/** Wide enough for the three-column row; the stacking rule is under 1000px. */
const ROW = 1440;
/** A phone, where the columns stack and a vertical strip stops meaning anything. */
const STACKED = 375;

describe.skipIf(!availability.ok)("a collapsed pane keeps working", () => {
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
   * A toolkit page, optionally opened with the ops panel already collapsed.
   *
   * Through `localStorage` rather than by pressing the control, because that is
   * how a person meets this state on their second visit — `opsCollapsed` is
   * persisted, so the collapsed pane is the *first* thing the page draws, and a
   * test that only ever reached it by clicking would not cover that.
   */
  async function open(width, { opsCollapsed = false } = {}) {
    const page = await browser.newPage({ viewport: { width, height: 900 } });
    if (opsCollapsed) {
      await page.addInitScript(() => {
        localStorage.setItem("basilisk.toolkit.layout", JSON.stringify({ opsCollapsed: true }));
      });
    }
    await page.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
    await page.waitForFunction(() => document.readyState === "complete");
    await page.waitForTimeout(600);
    return page;
  }

  it("draws the panel and no rail when it is not collapsed", async () => {
    // The control. Without it, every assertion below is satisfied by a shell
    // that renders neither.
    const page = await open(ROW);
    try {
      expect(await page.locator(".ops-panel").count()).toBe(1);
      expect(await page.locator(".ops-rail").count()).toBe(0);
    } finally {
      await page.close();
    }
  });

  it("draws a rail and no panel when it is", async () => {
    const page = await open(ROW, { opsCollapsed: true });
    try {
      expect(await page.locator(".ops-rail").count()).toBe(1);
      expect(
        await page.locator(".ops-panel").count(),
        "both forms of the pane are on screen at once"
      ).toBe(0);
    } finally {
      await page.close();
    }
  });

  it("gives the rail a name and a way back", async () => {
    // A 28px strip with its label written sideways is unreadable to a screen
    // reader unless it says what it is, and unusable to everyone if pressing
    // it does nothing.
    const page = await open(ROW, { opsCollapsed: true });
    try {
      const rail = page.locator(".ops-rail");
      expect(await rail.getAttribute("title")).toBe("Expand Toolkit panel");
      await rail.click();
      await page.waitForTimeout(300);
      expect(await page.locator(".ops-panel").count(), "the rail did not expand").toBe(1);
      expect(await page.locator(".ops-rail").count()).toBe(0);
    } finally {
      await page.close();
    }
  });

  it("is a 28px strip while the row is a row", async () => {
    const page = await open(ROW, { opsCollapsed: true });
    try {
      const box = await page.locator(".ops-rail").boundingBox();
      expect(Math.round(box.width)).toBe(28);
      // Taller than it is wide, which is what makes the sideways label right.
      expect(box.height).toBeGreaterThan(box.width * 3);
    } finally {
      await page.close();
    }
  });

  it("stops being a strip once the columns stack", async () => {
    // The override this file was written for. `width: auto` on a two-class
    // selector beats the `w-[28px]` utility — a rule that survives a refactor
    // by luck, and whose failure is a 28px sliver of a full-width row with its
    // label on its side.
    const page = await open(STACKED, { opsCollapsed: true });
    try {
      const box = await page.locator(".ops-rail").boundingBox();
      expect(
        Math.round(box.width),
        "the collapsed pane is still a vertical strip on a stacked layout"
      ).not.toBe(28);
      expect(box.width).toBeGreaterThan(STACKED / 2);
    } finally {
      await page.close();
    }
  });

  it("collapses the tray to its own rail and back", async () => {
    // The mirror of the left-hand pane, and driven by pressing the control
    // because this one is not persisted — a reader only ever reaches it here.
    const page = await open(ROW);
    try {
      await page.getByLabel("Collapse tray").click();
      await page.waitForTimeout(300);
      const rail = page.locator(".tray-rail");
      expect(await rail.count(), "the tray did not collapse to a rail").toBe(1);
      expect(await rail.getAttribute("title")).toBe("Expand session tray");
      expect(Math.round((await rail.boundingBox()).width)).toBe(28);
      await rail.click();
      await page.waitForTimeout(300);
      expect(await page.locator(".tray-rail").count(), "the tray rail did not expand").toBe(0);
    } finally {
      await page.close();
    }
  });
});
