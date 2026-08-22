/**
 * Every shipped page puts its content in exactly one `<main>`.
 *
 * `191f2ed` gave `/toolkit` a `<main>` and an `<h1>` after finding it had
 * neither, and recorded that the other pages had not been looked at. They had
 * not: a sweep of all eight found `<nav>` on every one of them and `<main>` on
 * none except `/toolkit`, so on seven pages the entire document body was one
 * undifferentiated region -- a screen reader's landmark list offered "banner,
 * navigation" and then nothing, and "skip to content" had nowhere to skip to.
 *
 * Six of the seven share `components/Layout.tsx`, so they shared one fix. The
 * seventh, `/toolkit-widgets`, is the widget catalog and builds its own chrome.
 *
 * ## Why this is an e2e test and not a unit test
 *
 * Every one of these pages is a `createRoot` mount into an empty `<div id>`;
 * the HTML on disk contains no `<main>` and never will. The landmark exists
 * only after React runs, so the only place the question can be asked is a real
 * browser with the real bundle -- which is also the only place a *second*
 * `<main>` could appear, from two components each adding one.
 *
 * Serves `dist/` like every spec here, so `npm run build` must have run.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DIST_ROOT, chromiumAvailability, serveDist } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the landmarks are measured in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[site-landmarks.e2e] skipping — chromium not installed (${availability.reason})`);
}

/**
 * Every page the build emits, by the clean URL a person types -- the same list
 * `viewport-overflow.e2e.js` sweeps, and for the same reason: a page missing
 * from it is a page nobody is checking.
 */
const PAGES = ["/", "/published", "/key", "/stats", "/verify", "/toolkit", "/toolkit-widgets", "/preferences"];

describe.skipIf(!availability.ok)("every page has one main landmark", () => {
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

  it("gives each page exactly one <main>, and a nav outside it", async () => {
    const bad = [];
    for (const path of PAGES) {
      const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
      try {
        await page.goto(`${server.origin}${path}`, { waitUntil: "load" });
        await page.waitForFunction(() => document.readyState === "complete");
        await page.waitForSelector("main", { timeout: 8000 }).catch(() => {});
        const seen = await page.evaluate(() => ({
          main: document.querySelectorAll("main").length,
          // A `<nav>` inside the main region is a landmark that swallowed the
          // one meant to sit beside it, which reads as no navigation at all.
          navInMain: document.querySelectorAll("main nav").length,
          // Content that ends up outside every region is what this test is
          // actually about; an empty `<main>` would satisfy a bare count.
          mainText: (document.querySelector("main")?.textContent || "").trim().length,
        }));
        if (seen.main !== 1) bad.push(`${path}: ${seen.main} <main> elements, expected 1`);
        else if (seen.mainText < 20) bad.push(`${path}: <main> holds ${seen.mainText} chars of text`);
        if (seen.navInMain > 0)
          bad.push(`${path}: ${seen.navInMain} <nav> inside <main>`);
      } finally {
        await page.close();
      }
    }
    expect(bad).toEqual([]);
  }, 120_000);
});
