import { chromium } from "playwright";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir } from "node:fs/promises";

const base = (process.argv[2] || "http://127.0.0.1:5173").replace(/\/$/, "");
const out = resolve(dirname(fileURLToPath(import.meta.url)), "../tmp/snapshots/ux");
await mkdir(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 960 },
  colorScheme: "dark",
});

await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".notebook-cell");

// Prefer a recover / shares template
await page.locator("#preset-gallery summary").click();
await page.waitForTimeout(200);
const tpl = page
  .locator("#preset-grid button, #preset-grid [data-preset], .preset-card button")
  .filter({ hasText: /recover|share|combine|mnemonic/i })
  .first();
if (await tpl.count()) {
  await tpl.click();
} else {
  await page.keyboard.press("Escape");
  await page.locator("details.recipe-text-details summary").click();
  await page
    .locator("#recipe-text")
    .fill("shares | blip39 -d | recover | out @master");
  await page.locator("#recipe-text").dispatchEvent("change");
}
await page.waitForTimeout(600);

const inline = await page.locator(".builder-card [data-runtime-slot]:not([hidden])").count();
const fallback = await page.locator(".cell-inputs-fallback:not([hidden])").count();
const kicker = await page.locator(".builder-card .cell-runtime-kicker").count();
console.log({ inline, fallback, kicker });

await page.locator(".notebook-cell").first().screenshot({
  path: resolve(out, "15-inline-runtime.png"),
});
await page.screenshot({ path: resolve(out, "16-inline-runtime-page.png") });

await browser.close();
