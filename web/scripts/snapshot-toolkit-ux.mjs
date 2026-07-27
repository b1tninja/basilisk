/**
 * Capture a small UX screenshot set from the live Toolkit.
 * Usage: node scripts/snapshot-toolkit-ux.mjs [baseUrl]
 */
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(__dirname, "../tmp/snapshots/ux");
const base = (process.argv[2] || "http://127.0.0.1:5173").replace(/\/$/, "");

await mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 960 },
  colorScheme: "dark",
});

async function shot(name, fn) {
  const path = resolve(outDir, `${name}.png`);
  await fn();
  await page.waitForTimeout(350);
  await page.screenshot({ path, fullPage: false });
  console.log("wrote", path);
  return path;
}

console.log("Opening", `${base}/toolkit`);
await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".ops-item-icon", { timeout: 20000 });

await shot("01-toolkit-overview", async () => {});

await shot("02-ops-tool-card", async () => {
  const tile = page.locator(".ops-item-icon:visible").first();
  await tile.scrollIntoViewIfNeeded();
  await tile.hover();
  await page.waitForSelector("#ops-tool-card .tool-card", { timeout: 5000 });
});

await shot("03-ops-pane-crop", async () => {
  await page.locator(".chef-ops").screenshot({
    path: resolve(outDir, "03-ops-pane-crop.png"),
  });
  console.log("wrote", resolve(outDir, "03-ops-pane-crop.png"));
});

// Load a multi-output recipe (shares) if possible via fragment / template
await shot("04-shares-outputs", async () => {
  // Prefer a known SSS-ish notebook from templates if present
  const templates = page.locator("#preset-gallery summary, .toolkit-presets-summary");
  if (await templates.count()) {
    await templates.first().click();
    await page.waitForTimeout(200);
    const shareTpl = page
      .locator("#preset-gallery button, #preset-gallery a, .toolbar-menu-item")
      .filter({ hasText: /split|share|P-256|recover/i })
      .first();
    if (await shareTpl.count()) {
      await shareTpl.click();
      await page.waitForTimeout(600);
    } else {
      await page.keyboard.press("Escape");
    }
  }
  // Ensure we have some notebook content
  await page.waitForSelector(".notebook-cell, .builder-step, #notebook-cells", {
    timeout: 10000,
  });
});

await shot("05-mobile-narrow", async () => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
  await page.waitForSelector(".ops-item-icon, .chef-ops", { timeout: 20000 });
});

await page.setViewportSize({ width: 1440, height: 960 });
await page.goto(`${base}/tool-card-preview.html`, {
  waitUntil: "networkidle",
  timeout: 30000,
});
await page.waitForSelector(".tool-card", { timeout: 15000 });
await shot("06-tool-card-fixture", async () => {});

await browser.close();
console.log("Done →", outDir);
