/**
 * Fresh UX screenshot pack for post-fix resume.
 * Usage: node scripts/snapshot-ux-resume.mjs [baseUrl]
 */
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const base = (process.argv[2] || "http://127.0.0.1:5173").replace(/\/$/, "");
const out = resolve(dirname(fileURLToPath(import.meta.url)), "../tmp/snapshots/ux");
await mkdir(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 960 },
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

async function shot(name) {
  const path = resolve(out, `${name}.png`);
  await page.waitForTimeout(350);
  await page.screenshot({ path, fullPage: false });
  console.log("wrote", path);
}

async function closeOverlays() {
  await page.keyboard.press("Escape").catch(() => {});
  await page.evaluate(() => {
    const gal = document.querySelector("#preset-gallery");
    if (gal instanceof HTMLDetailsElement) gal.open = false;
    document.querySelectorAll("details.toolbar-menu[open]").forEach((d) => {
      if (d.id !== "preset-gallery") d.open = false;
    });
  });
}

async function loadRecipe(text) {
  const rawBtn = page.locator('button[data-cell-recipe-view="raw"]').first();
  if (await rawBtn.count()) await rawBtn.click();
  await page.waitForTimeout(150);
  let ta = page.locator(".cell-recipe-ta").first();
  if (!(await ta.count())) {
    await page.locator("details.recipe-text-details").evaluate((el) => {
      el.open = true;
    });
    ta = page.locator("#recipe-text").first();
  }
  await ta.waitFor({ state: "attached", timeout: 10000 });
  await ta.fill(text);
  await ta.dispatchEvent("input");
  await ta.dispatchEvent("change");
  await ta.blur();
  await page.waitForTimeout(500);
  const preview = page.locator('button[data-cell-recipe-view="preview"]').first();
  if (await preview.count()) await preview.click();
  await page.waitForTimeout(300);
}

async function ensureOpsExpanded() {
  const ws = page.locator(".chef-workspace");
  if (!(await ws.count())) return;
  if (await ws.evaluate((el) => el.classList.contains("ops-collapsed"))) {
    const toggle = page.locator('[data-collapse="ops"]').first();
    if (await toggle.count()) await toggle.click({ force: true });
    else await ws.evaluate((el) => el.classList.remove("ops-collapsed"));
    await page.waitForTimeout(250);
  }
}

console.log("Opening", `${base}/toolkit`);
await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".chef-ops, .notebook-cell", { timeout: 20000 });
await closeOverlays();
await ensureOpsExpanded();

await shot("01-toolkit-overview");

await loadRecipe(`genkey ec/p256 | tee
  - .public | export spki | pem.encode | out @public
| export pkcs8 | pem.encode | out @private`);
await closeOverlays();
await shot("21-tee-indent-preview");
await page.locator(".cell-recipe-summary").first().screenshot({
  path: resolve(out, "20-recipe-indent-preview.png"),
});
console.log("wrote", resolve(out, "20-recipe-indent-preview.png"));

await page.locator(".chef-ops").screenshot({
  path: resolve(out, "03-ops-pane-crop.png"),
});
console.log("wrote", resolve(out, "03-ops-pane-crop.png"));

// Encrypt + recipient binder
await loadRecipe(`input | gpg.encrypt | out @msg`);
await closeOverlays();
await page.waitForTimeout(400);
const binder = page.locator(".recipient-binder, .cell-bind-messaging").first();
if (await binder.count()) {
  await binder.scrollIntoViewIfNeeded();
  const search = page.locator(".binder-search").first();
  if (await search.count()) {
    await search.click();
    await search.fill("alice@example.com");
    await page.waitForTimeout(200);
  }
  await shot("22-encrypt-recipient-binder");
  const ks = page.locator(".keyserver-control").first();
  if (await ks.count()) {
    await ks.screenshot({ path: resolve(out, "23-keyserver-control.png") });
    console.log("wrote", resolve(out, "23-keyserver-control.png"));
  }
} else {
  await shot("22-encrypt-recipient-binder");
}

// Header chrome (Session menu / thinned actions)
await loadRecipe(`genkey ec/p256 | export pkcs8 | pem.encode | out @private`);
await closeOverlays();
await page.locator("#notebook-header").screenshot({
  path: resolve(out, "24-notebook-header.png"),
});
console.log("wrote", resolve(out, "24-notebook-header.png"));

await page.setViewportSize({ width: 390, height: 844 });
await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".chef-ops, .notebook-cell", { timeout: 20000 });
await shot("05-mobile-narrow");

await browser.close();
console.log("Done →", out);
