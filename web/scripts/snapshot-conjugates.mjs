/**
 * Screenshot toolkit conjugate UX after layout fix.
 * Usage: node scripts/snapshot-conjugates.mjs [baseUrl] [suffix]
 */
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const base = process.argv[2] || "http://127.0.0.1:5173";
const suffix = process.argv[3] || "after";
const out = resolve("tmp/snapshots/conjugates");
await mkdir(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 960 },
  colorScheme: "dark",
});

await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".ops-item-icon", { timeout: 30000 });

await page.evaluate(() => {
  // Expand Encoding toolbox
  document.querySelectorAll(".ops-category-toggle").forEach((btn) => {
    const label = (btn.textContent || "").toLowerCase();
    if (label.includes("encoding") && btn.getAttribute("aria-expanded") === "false") {
      btn.click();
    }
  });
  // Expand Binary shelf
  document.querySelectorAll(".ops-shelf-toggle").forEach((btn) => {
    const label = (btn.textContent || "").toLowerCase();
    if (label.includes("binary") && btn.getAttribute("aria-expanded") === "false") {
      btn.click();
    }
  });
  // Collapse other toolboxes to focus Encoding
  document.querySelectorAll(".ops-category-toggle").forEach((btn) => {
    const label = (btn.textContent || "").toLowerCase();
    if (!label.includes("encoding") && btn.getAttribute("aria-expanded") === "true") {
      btn.click();
    }
  });
});
await page.waitForTimeout(500);

const encoding = page.locator(".ops-category[data-toolbox='encoding']");
if (await encoding.count()) {
  await encoding.scrollIntoViewIfNeeded();
  await encoding.screenshot({ path: resolve(out, `${suffix}-encoding.png`) });
}

const pair = page.locator(".ops-category[data-toolbox='encoding'] .ops-pair:not(.ops-pair-solo)").first();
if (await pair.count()) {
  await pair.screenshot({ path: resolve(out, `${suffix}-ops-pair.png`) });
  const text = await pair.innerText();
  console.log("pair text:", JSON.stringify(text));
}

await page.locator(".chef-ops").screenshot({ path: resolve(out, `${suffix}-ops-drawer.png`) });

await page.locator(".toolkit-presets-summary").click();
await page.waitForTimeout(300);
const split = page.locator("[data-preset-cat='Split & recover']");
if (await split.count()) await split.click();
await page.waitForTimeout(200);
const presetPair = page.locator(".preset-pair").first();
if (await presetPair.count()) {
  await presetPair.screenshot({ path: resolve(out, `${suffix}-preset-pair.png`) });
}
await page.locator("#preset-grid").screenshot({ path: resolve(out, `${suffix}-templates.png`) });

await browser.close();
console.log("wrote", out, suffix);
