/**
 * Capture the merged chip editor — the notebook cell, its chip flow, and the
 * inline parameter panel a selected chip opens.
 *
 * Usage: node scripts/snapshot-ux-overwhelm.mjs [baseUrl]
 *
 * Repointed at the current shell. The capture it was taking still exists —
 * `.cell-recipe-flow` (RecipeChipFlow) and `.cell-recipe-inline-edit`
 * (ToolkitShell) are both live — but every control it reached them through
 * had been renamed away:
 *
 *   `.chef-ops`                  → `.ops-panel`
 *   `.notebook-cell`             → the cell is `.toolkit-notebook article` (no class hook)
 *   `.cell-recipe-mode-btn`      → `ModeToggle`, a radiogroup labelled "Recipe view"
 *   Raw / Preview / Cards        → Pipeline / Source — "Cards" no longer exists
 *   `[data-cell-recipe-ta]`      → the cell's own `textarea` in Source view
 *   `.builder-ingredient-chip-edit` → `.builder-ingredient-chip` (SuggestChip, variant "placed")
 *
 * The recipe text was stale too: `pem.encode` is not an op the parser accepts
 * (`pem` is), and a branch selector is spelled `:public`, not `.public`. With
 * the old text the cell parsed to nothing and every shot below was of an empty
 * notebook — which is exactly the failure this file now refuses to ship: each
 * step asserts what it found before it photographs it.
 */
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(__dirname, "../tmp/snapshots/ux-review");
const base = (process.argv[2] || "http://localhost:4188").replace(/\/$/, "");

await mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 960 },
  colorScheme: "dark",
});
page.on("pageerror", (e) => console.error("page error:", e.message));

async function shot(name) {
  const path = resolve(outDir, `${name}.png`);
  await page.waitForTimeout(350);
  await page.screenshot({ path, fullPage: false });
  console.log("wrote", path);
}

/** Screenshot one element, or fail loudly — never write a blank crop. */
async function cropOf(selector, what, name) {
  const n = await page.locator(selector).count();
  if (!n) throw new Error(`${what}: no element matched ${selector}`);
  const loc = page.locator(selector).first();
  await loc.scrollIntoViewIfNeeded();
  const path = resolve(outDir, `${name}.png`);
  await loc.screenshot({ path });
  console.log("wrote", path);
}

await page.addInitScript(() => {
  try {
    const layout = JSON.parse(
      localStorage.getItem("basilisk.toolkit.layout") || "{}"
    );
    layout.opsCollapsed = false;
    localStorage.setItem("basilisk.toolkit.layout", JSON.stringify(layout));
  } catch {
    /* ignore */
  }
});

console.log("Opening", `${base}/toolkit`);
await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".toolkit-workspace", { timeout: 30000 });
await page.waitForSelector(".ops-panel", { timeout: 30000 });
await page.waitForSelector(".toolkit-notebook article", { timeout: 30000 });

await shot("01-empty-overview");

const cell = page.locator(".toolkit-notebook article").first();

/**
 * Put a recipe in the cell through the view toggle, the way a person does:
 * Source → type → commit on blur → Pipeline.
 */
async function loadCellRecipe(text) {
  await cell.getByRole("radio", { name: "Source" }).click();
  await page.waitForTimeout(200);
  const ta = cell.locator("textarea").first();
  await ta.waitFor({ timeout: 15000 });
  await ta.click();
  await ta.fill(text);
  // The cell commits on blur; moving focus off is what applies the text.
  await page.keyboard.press("Tab");
  await page.waitForTimeout(600);
  await cell.getByRole("radio", { name: "Pipeline" }).click();
  await page.waitForTimeout(600);
  const chips = await page.locator(".builder-ingredient-chip").count();
  if (!chips) {
    throw new Error(
      `the cell parsed to no steps from ${JSON.stringify(text)} — the recipe is ` +
        `stale, or the chip class changed`
    );
  }
  console.log("placed chips:", chips);
}

await loadCellRecipe(
  "genkey ec/p256 | tee\n" +
    "  - :private | inspect\n" +
    "  - :public | export spki | pem | out @public\n" +
    "| export pkcs8 | pem | out @private"
);

await shot("02-tee-chip-editor");
await cropOf(".toolkit-notebook article", "the notebook cell", "03-notebook-cell-crop");
await cropOf(".cell-recipe-flow", "the chip flow", "04-chip-flow-crop");

// Select the genkey chip → inline params.
const genkeyChip = page
  .locator(".builder-ingredient-chip")
  .filter({ hasText: /genkey/i })
  .first();
if (!(await genkeyChip.count())) {
  throw new Error("no genkey chip in the flow — the recipe or the chip class changed");
}
await genkeyChip.click();
await page.waitForSelector(".cell-recipe-inline-edit", { timeout: 10000 });
await shot("05-chip-inline-params");
await cropOf(".cell-recipe-inline-edit", "the inline param panel", "06-inline-edit-crop");

/*
 * There is no "Cards" view any more — `CellView` is `pipeline | source` — so
 * the shot that used to toggle it is gone rather than left as a no-op click.
 */

await cropOf(".ops-panel", "the ops panel", "07-ops-panel-crop");

await browser.close();
console.log("done →", outDir);
