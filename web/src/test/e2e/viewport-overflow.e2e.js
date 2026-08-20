/**
 * No shipped page scrolls sideways, and when one does, this says which element.
 *
 * A page that scrolls horizontally on a phone is a defect on its own, and it
 * is the one class of layout bug that no `environment: "node"` test can see:
 * it is produced by flexbox resolving widths against a real viewport, and only
 * a real viewport produces it. Both instances found here had been shipping for
 * as long as the elements involved had existed.
 *
 * ## Why the obvious probe does not work
 *
 * "List every element whose `getBoundingClientRect().right` exceeds the
 * viewport" is the natural check and it stops working the moment anything on
 * the page scrolls: a child inside an `overflow-x: auto` ancestor still reports
 * its *laid-out* position, so a tab strip that correctly scrolls 200px of tabs
 * inside a 300px box looks exactly like a tab strip pushing the document 200px
 * sideways. A previous attempt at this measurement was abandoned for that
 * reason, with the remaining overflow unattributed.
 *
 * `offender()` below walks *up* instead. An element's overflow is contained if
 * some ancestor both clips on the x axis and does not itself stick out past the
 * viewport; only elements with no such ancestor reach the document. `body` and
 * `html` are explicitly not containers — an overflow value on the body
 * propagates to the viewport, so "contained by body" *is* the sideways-
 * scrolling page. And the causal element is the outermost surviving one:
 * children of an element that is already pushing the page are consequences.
 *
 * ## What the widths are for
 *
 * 375 and 768 are the two that were broken, by two unrelated causes — the
 * toolkit's three-column workspace claiming 553px of chrome before the notebook
 * got any, and the nav's link row refusing to shrink and pushing the sign-in
 * button off the right edge. 1280 is the control: that width was never
 * overflowing, and a fix for the narrow ones that broke it would be a trade,
 * not a fix.
 *
 * Serves `dist/` like every spec here, so `npm run build` must have run.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DIST_ROOT, chromiumAvailability, serveDist } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the layout is measured in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[viewport-overflow.e2e] skipping — chromium not installed (${availability.reason})`);
}

/** Every page the build emits, by the clean URL a person types. */
const PAGES = ["/", "/published", "/key", "/stats", "/verify", "/toolkit", "/toolkit-widgets", "/preferences"];

/** Phone, tablet, and a desktop control that must stay at zero throughout. */
const WIDTHS = [375, 768, 1280];

/**
 * Runs in the page. Returns the overflow in px and the element to blame.
 *
 * Kept as one function rather than composed helpers because it is serialised
 * into the browser, where nothing else in this file exists.
 */
function offender() {
  const vw = document.documentElement.clientWidth;
  const overflow = document.scrollingElement.scrollWidth - vw;
  const clipsX = (el) => /auto|hidden|scroll|clip/.test(getComputedStyle(el).overflowX);
  const escapes = [];
  for (const el of document.querySelectorAll("*")) {
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) continue;
    if (rect.right <= vw) continue;
    let contained = false;
    for (let p = el.parentElement; p && p.tagName !== "BODY" && p.tagName !== "HTML"; p = p.parentElement) {
      if (clipsX(p) && p.getBoundingClientRect().right - vw <= 1) {
        contained = true;
        break;
      }
    }
    if (!contained) escapes.push(el);
  }
  const set = new Set(escapes);
  const describe = (el) => {
    const rect = el.getBoundingClientRect();
    const name = `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}`;
    const cls = String(el.className?.baseVal ?? el.className ?? "").trim().slice(0, 90);
    let chain = "";
    for (let p = el.parentElement; p; p = p.parentElement) {
      const pcls = String(p.className?.baseVal ?? p.className ?? "").trim().slice(0, 40);
      chain += ` < ${p.tagName.toLowerCase()}${pcls ? `.${pcls.split(/\s+/)[0]}` : ""}`;
      if (p.tagName === "BODY") break;
    }
    return `<${name} class="${cls}"> right ${Math.round(rect.right)} of ${vw}${chain}`;
  };
  const outermost = escapes.filter((el) => {
    for (let p = el.parentElement; p; p = p.parentElement) if (set.has(p)) return false;
    return true;
  });
  return { overflow, blame: outermost.map(describe) };
}

describe.skipIf(!availability.ok)("no shipped page scrolls sideways", () => {
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
   * Stacked, the side panes need a ceiling of their own.
   *
   * Horizontal overflow is what this file was written for, and it would not
   * have caught the reason the cap exists: once `.toolkit-workspace` stacks
   * below 1000px, nothing bounds the shelf's own scroll area, so it grew to
   * 4342px of operations sitting above the notebook. The page did not scroll
   * sideways for that — it just put the subject of the page an entire screen
   * and a half out of reach, which is the same defect the width fix was
   * about, turned ninety degrees.
   *
   * Asserted against the viewport rather than a pixel count, because the cap
   * is written in `dvh` and a number here would pin the arithmetic instead of
   * the property: no single pane may be taller than the window it is in.
   */
  it("bounds each stacked pane to the window at 375px", async () => {
    const page = await browser.newPage({ viewport: { width: 375, height: 900 } });
    try {
      await page.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
      await page.waitForFunction(() => document.readyState === "complete");
      await page.waitForTimeout(500);
      const tall = await page.evaluate(() => {
        const vh = window.innerHeight;
        const out = [];
        for (const sel of [".toolkit-shelf", ".toolkit-tray", ".ops-panel"]) {
          for (const el of document.querySelectorAll(sel)) {
            const h = Math.round(el.getBoundingClientRect().height);
            if (h > vh) out.push(`${sel} is ${h}px in a ${vh}px window`);
          }
        }
        return out;
      });
      expect(tall, tall.join(" | ")).toEqual([]);
    } finally {
      await page.close();
    }
  });

  for (const width of WIDTHS) {
    for (const path of PAGES) {
      it(`${path} at ${width}px`, async () => {
        const page = await browser.newPage({ viewport: { width, height: 900 } });
        try {
          await page.goto(`${server.origin}${path}`, { waitUntil: "load" });
          // The toolkit mounts its workspace after the bundle boots, and the
          // widest thing on the page is in it. Waiting on the network alone
          // measured an empty shell.
          await page.waitForFunction(() => document.readyState === "complete");
          await page.waitForTimeout(500);
          const { overflow, blame } = await page.evaluate(offender);
          expect(
            overflow,
            overflow > 0
              ? `${path} at ${width}px scrolls ${overflow}px sideways. Uncontained:\n  ${blame.join("\n  ")}`
              : ""
          ).toBe(0);
        } finally {
          await page.close();
        }
      });
    }
  }
});
