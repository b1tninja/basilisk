/**
 * Screenshot the conjugate pair rows in the ops shelf, and the paired
 * templates in the preset menu.
 *
 * Usage: node scripts/snapshot-conjugates.mjs [baseUrl] [suffix]
 *
 * Repointed at the current shell. It used to drive `.chef-ops`,
 * `.ops-category-toggle`, `.ops-shelf-toggle` and `.ops-pair` — the legacy
 * shell's names, which the build emits zero times. The current shell renders:
 *
 *   `.ops-panel`                                the ops pane            (ToolkitShell)
 *   `.ops-category[data-toolbox="…"]`           one toolbox section     (OpsShelf)
 *   `.ops-category > button[aria-expanded]`     its expand/collapse     (OpsShelf/SectionHeader)
 *   `[role="group"][aria-label]`                one conjugate pair row  (OpsTile)
 *   `button[data-dir]`                          its two direction handles
 *
 * A pair row is the `role="group"` — `OpsTile` sets it exactly when the row
 * has a caption, and every pair row does; solo rows (`OpsRow`) are plain divs
 * with no role, which is the distinction `.ops-pair:not(.ops-pair-solo)` used
 * to draw.
 *
 * Every locator this needs goes through `must()`. A capture script that
 * silently writes a blank PNG is worse than one that is gone, because
 * somebody will trust the image.
 */
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const base = (process.argv[2] || "http://localhost:4188").replace(/\/$/, "");
const suffix = process.argv[3] || "after";
const out = resolve(__dirname, "../tmp/snapshots/conjugates");
await mkdir(out, { recursive: true });

/** The toolbox this capture is about. `registry.js` spells it `encoding`. */
const TOOLBOX = "encoding";

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 960 },
  colorScheme: "dark",
});
page.on("pageerror", (e) => console.error("page error:", e.message));

/** Resolve a locator or fail loudly — never screenshot nothing. */
async function must(selector, what) {
  const loc = page.locator(selector).first();
  const n = await page.locator(selector).count();
  if (!n) throw new Error(`${what}: no element matched ${selector}`);
  return loc;
}

async function shotOf(selector, what, name) {
  const loc = await must(selector, what);
  await loc.scrollIntoViewIfNeeded();
  const path = resolve(out, `${suffix}-${name}.png`);
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
await page.waitForSelector(".ops-panel", { timeout: 30000 });
await page.waitForSelector(".ops-category", { timeout: 30000 });

/*
 * Focus the toolbox: open it, close the rest. The shelf expands in place now
 * — there is no drill-down and no separate shelf toggle, so the toolbox header
 * is the only control involved.
 */
const header = await must(
  `.ops-category[data-toolbox="${TOOLBOX}"] > button`,
  `the ${TOOLBOX} toolbox header`
);
if ((await header.getAttribute("aria-expanded")) === "false") {
  await header.click();
  await page.waitForTimeout(250);
}
const others = page.locator(
  `.ops-category:not([data-toolbox="${TOOLBOX}"]) > button[aria-expanded="true"]`
);
for (let i = (await others.count()) - 1; i >= 0; i -= 1) {
  await others.nth(i).click();
  await page.waitForTimeout(60);
}
await page.waitForTimeout(400);

const rows = `.ops-category[data-toolbox="${TOOLBOX}"] [role="group"]`;
const rowCount = await page.locator(rows).count();
if (!rowCount) {
  throw new Error(
    `no conjugate pair rows in the ${TOOLBOX} toolbox — the shelf renders a pair as ` +
      `role="group"; if that changed, this script needs repointing again`
  );
}
console.log(
  "pair rows:",
  await page.locator(rows).evaluateAll((els) =>
    els.map((el) => el.getAttribute("aria-label"))
  )
);

await shotOf(
  `.ops-category[data-toolbox="${TOOLBOX}"]`,
  `the ${TOOLBOX} toolbox`,
  TOOLBOX
);
await shotOf(rows, "a conjugate pair row", "ops-pair");
console.log("pair text:", JSON.stringify(await page.locator(rows).first().innerText()));
await shotOf(".ops-panel", "the ops panel", "ops-panel");

/*
 * Paired templates. `#preset-gallery` / `#preset-grid` / `[data-preset-cat]`
 * are gone with the legacy shell; `PresetMenu.tsx` renders a dropdown whose
 * trigger keeps the `.toolkit-presets-summary` hook, a `.preset-cat-btn` rail,
 * and `.preset-pair` for a companion pair.
 */
(await must(".toolkit-presets-summary", "the templates trigger")).click();
await page.waitForSelector(".preset-menu", { timeout: 10000 });
await page.waitForTimeout(300);

const splitCat = page
  .locator(".preset-cat-btn")
  .filter({ hasText: /Split & recover/i })
  .first();
if (!(await splitCat.count())) {
  throw new Error("no 'Split & recover' template category — see recipe.js PRESET_GROUPS");
}
await splitCat.click();
await page.waitForTimeout(350);

await shotOf(".preset-pair", "a companion template pair", "preset-pair");
await shotOf(".preset-menu-panel", "the template panel", "templates");

await browser.close();
console.log("Done →", out, `(${suffix})`);
