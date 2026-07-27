import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const base = (process.argv[2] || "http://127.0.0.1:5173").replace(/\/$/, "");
const out = resolve(dirname(fileURLToPath(import.meta.url)), "../tmp/snapshots/ux");
await mkdir(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 900 },
  colorScheme: "dark",
});
await page.addInitScript(() => {
  try {
    const layout = JSON.parse(localStorage.getItem("basilisk.toolkit.layout") || "{}");
    layout.opsCollapsed = false;
    localStorage.setItem("basilisk.toolkit.layout", JSON.stringify(layout));
  } catch {
    /* ignore */
  }
});
await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.evaluate(() => {
  const gal = document.querySelector("#preset-gallery");
  if (gal instanceof HTMLDetailsElement) gal.open = false;
});
const recipe = `genkey ec/p256 | tee
  - .public | export spki | pem.encode | out @public
| export pkcs8 | pem.encode | out @private`;
// Prefer cell Raw editor; fall back to full notebook source details.
const rawBtn = page.locator('button[data-cell-recipe-view="raw"]').first();
if (await rawBtn.count()) await rawBtn.click();
await page.waitForTimeout(200);
let ta = page.locator(".cell-recipe-ta").first();
if (!(await ta.count())) {
  await page.locator("details.recipe-text-details").evaluate((el) => {
    el.open = true;
  });
  ta = page.locator("#recipe-text").first();
}
await ta.waitFor({ state: "attached", timeout: 10000 });
await ta.fill(recipe);
await ta.dispatchEvent("input");
await ta.dispatchEvent("change");
await ta.blur();
await page.waitForTimeout(500);
const preview = page.locator('button[data-cell-recipe-view="preview"]').first();
if (await preview.count()) await preview.click();
await page.waitForTimeout(300);
const path = resolve(out, "20-recipe-indent-preview.png");
await page.locator(".cell-recipe-summary").first().screenshot({ path });
console.log("wrote", path);
await browser.close();
