/**
 * Capture toolkit UX shots for merged chip-editor review.
 * Usage: node scripts/snapshot-ux-overwhelm.mjs [baseUrl]
 */
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(__dirname, "../tmp/snapshots/ux-review");
const base = (process.argv[2] || "http://127.0.0.1:5173").replace(/\/$/, "");

await mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 960 },
  colorScheme: "dark",
});

async function shot(name) {
  const path = resolve(outDir, `${name}.png`);
  await page.waitForTimeout(350);
  await page.screenshot({ path, fullPage: false });
  console.log("wrote", path);
}

async function loadCellRecipe(text) {
  const rawTab = page
    .locator(".cell-recipe-mode-btn")
    .filter({ hasText: /^Raw$/i })
    .first();
  await rawTab.click();
  const ta = page.locator("[data-cell-recipe-ta]").first();
  await ta.waitFor({ timeout: 15000 });
  await ta.fill(text);
  await ta.blur();
  const previewTab = page
    .locator(".cell-recipe-mode-btn")
    .filter({ hasText: /^Preview$/i })
    .first();
  await previewTab.click();
  await page.waitForTimeout(500);
}

await page.addInitScript(() => {
  try {
    const raw = localStorage.getItem("basilisk.toolkit.layout");
    const layout = raw ? JSON.parse(raw) : {};
    layout.opsCollapsed = false;
    localStorage.setItem("basilisk.toolkit.layout", JSON.stringify(layout));
  } catch {
    /* ignore */
  }
});

console.log("Opening", `${base}/toolkit`);
await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".ops-item-icon, .chef-ops, .notebook-cell", {
  timeout: 20000,
});

await shot("01-empty-overview");

await loadCellRecipe(`genkey ec/p256 | tee
  - :private | inspect
  - :public | export spki | pem | out @public
| export pkcs8 | pem | out @private`);

await shot("02-tee-chip-editor");

const notebook = page.locator(".notebook-cell").first();
if (await notebook.count()) {
  await notebook.screenshot({
    path: resolve(outDir, "03-notebook-cell-crop.png"),
  });
  console.log("wrote", resolve(outDir, "03-notebook-cell-crop.png"));
}

const flow = page.locator(".cell-recipe-flow").first();
if (await flow.count()) {
  await flow.screenshot({
    path: resolve(outDir, "04-chip-flow-crop.png"),
  });
  console.log("wrote", resolve(outDir, "04-chip-flow-crop.png"));
}

// Select genkey chip → inline params
const genkeyChip = page
  .locator("button.builder-ingredient-chip-edit")
  .filter({ hasText: /genkey/i })
  .first();
if (await genkeyChip.count()) {
  await genkeyChip.click();
  await page.waitForTimeout(300);
  await shot("05-chip-inline-params");
  const inline = page.locator(".cell-recipe-inline-edit").first();
  if (await inline.count()) {
    await inline.screenshot({
      path: resolve(outDir, "06-inline-edit-crop.png"),
    });
    console.log("wrote", resolve(outDir, "06-inline-edit-crop.png"));
  }
}

// Cards toggle (power-user tall cards)
const cardsTab = page
  .locator(".cell-recipe-mode-btn")
  .filter({ hasText: /^Cards$/i })
  .first();
if (await cardsTab.count()) {
  await cardsTab.click();
  await page.waitForTimeout(300);
  await shot("07-cards-toggled-on");
}

await page.locator(".chef-ops, .ops-drawer, #ops-drawer").first().screenshot({
  path: resolve(outDir, "08-ops-drawer-crop.png"),
}).catch(() => {});

await browser.close();
console.log("done →", outDir);
