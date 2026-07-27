import { chromium } from "playwright";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir } from "node:fs/promises";

const base = (process.argv[2] || "http://127.0.0.1:5173").replace(/\/$/, "");
const out = resolve(dirname(fileURLToPath(import.meta.url)), "../tmp/snapshots/ux");
await mkdir(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 900 },
  colorScheme: "dark",
});

await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.locator(".chef-workspace").waitFor({ state: "attached", timeout: 20000 });
const ws = page.locator(".chef-workspace");
if (await ws.evaluate((el) => el.classList.contains("ops-collapsed"))) {
  const toggle = page.locator('[data-collapse="ops"]').first();
  if (await toggle.count()) await toggle.click({ force: true });
  else await ws.evaluate((el) => el.classList.remove("ops-collapsed"));
  await page.waitForTimeout(300);
}
await page.locator("[data-ops-open-toolbox]").first().waitFor({ state: "visible", timeout: 20000 });
await page.locator(".chef-ops").screenshot({ path: resolve(out, "11-ops-drill-root.png") });

await page.locator('[data-ops-open-toolbox="webcrypto"]').first().click();
await page.waitForTimeout(350);
await page.locator(".chef-ops").screenshot({ path: resolve(out, "12-ops-drill-shelves.png") });

const keys = page.locator('[data-ops-open-shelf="keys"]');
if (await keys.count()) await keys.first().click();
else {
  const shelf = page.locator("[data-ops-open-shelf]").first();
  if (await shelf.count()) await shelf.click();
}
await page.waitForTimeout(350);
await page.locator(".chef-ops").screenshot({ path: resolve(out, "13-ops-drill-tools.png") });

const tip = await page.locator("#ops-hint").innerText().catch(() => "");
const crumb = await page
  .locator(".ops-drill-crumb")
  .innerText()
  .catch(() => "");
const tool = page.locator(".chef-ops [data-op]:visible").first();
if (await tool.count()) {
  await tool.hover({ force: true });
  await page.waitForSelector("#ops-tool-card .tool-card", { timeout: 5000 }).catch(() => {});
  await page.screenshot({ path: resolve(out, "14-ops-drill-toolcard.png") });
} else {
  await page.screenshot({ path: resolve(out, "14-ops-drill-toolcard.png") });
}
console.log({
  tip: tip.slice(0, 100),
  crumb,
  shelvesAtLevel: await page.locator("[data-ops-open-shelf]").count(),
  tools: await page.locator("[data-op]").count(),
  card: await page.locator("#ops-tool-card .tool-card").count(),
});

await browser.close();
