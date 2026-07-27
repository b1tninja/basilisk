/**
 * Capture local screenshots of the tool-card preview fixture.
 * Usage: node scripts/snapshot-tool-card.mjs [baseUrl]
 */
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(__dirname, "../tmp/snapshots");
const base = process.argv[2] || "http://127.0.0.1:5173";

await mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1280, height: 900 },
  colorScheme: "dark",
});

const url = `${base.replace(/\/$/, "")}/tool-card-preview.html`;
console.log("Opening", url);
await page.goto(url, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".tool-card", { timeout: 15000 });
await page.waitForTimeout(300);

const overview = resolve(outDir, "tool-card-overview.png");
await page.screenshot({ path: overview, fullPage: true });
console.log("Wrote", overview);

const cards = page.locator("#cards .tool-card").first();
const cardShot = resolve(outDir, "tool-card-detail.png");
await cards.screenshot({ path: cardShot });
console.log("Wrote", cardShot);

const floating = page.locator("#ops-tool-card .tool-card");
if (await floating.count()) {
  const hoverShot = resolve(outDir, "tool-card-hover.png");
  await page.locator(".preview-live").screenshot({ path: hoverShot });
  console.log("Wrote", hoverShot);
}

// Also try live Toolkit hover if the page boots
try {
  await page.goto(`${base.replace(/\/$/, "")}/toolkit.html`, {
    waitUntil: "networkidle",
    timeout: 45000,
  });
  await page.waitForSelector(".ops-item-icon", { timeout: 20000 });
  const tile = page.locator(".ops-item-icon").first();
  await tile.hover();
  await page.waitForSelector("#ops-tool-card .tool-card", { timeout: 5000 });
  await page.waitForTimeout(250);
  const toolkitShot = resolve(outDir, "toolkit-ops-hover.png");
  await page.screenshot({ path: toolkitShot, fullPage: false });
  console.log("Wrote", toolkitShot);
} catch (err) {
  console.warn("Toolkit hover snapshot skipped:", err.message);
}

await browser.close();
console.log("Done.");
