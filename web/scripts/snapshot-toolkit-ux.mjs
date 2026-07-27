/**
 * Capture a UX screenshot set from the live Toolkit (legacy notebook UI).
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
  if (fn) await fn();
  await page.waitForTimeout(400);
  await page.screenshot({ path, fullPage: false });
  console.log("wrote", path);
  return path;
}

async function loadRecipe(text) {
  const details = page.locator("details.recipe-text-details, details.cell-recipe-details");
  if (await details.count()) {
    await details.first().evaluate((el) => {
      el.open = true;
    });
  }
  const ta = page.locator("#recipe-text, .cell-recipe-raw textarea, textarea.cell-recipe-editor").first();
  await ta.waitFor({ timeout: 10000 });
  await ta.fill(text);
  await ta.dispatchEvent("input");
  await ta.dispatchEvent("change");
  await ta.blur();
  await page.waitForTimeout(500);
}

async function ensureOpsExpanded() {
  const ws = page.locator(".chef-workspace");
  if (!(await ws.count())) return;
  const collapsed = await ws.evaluate((el) =>
    el.classList.contains("ops-collapsed")
  );
  if (!collapsed) return;
  const toggle = page.locator('[data-collapse="ops"]').first();
  if (await toggle.count()) {
    await toggle.click({ force: true });
  } else {
    await ws.evaluate((el) => el.classList.remove("ops-collapsed"));
  }
  await page.waitForTimeout(300);
}

async function closeOverlays() {
  await page.keyboard.press("Escape").catch(() => {});
  await page.evaluate(() => {
    const gal = document.querySelector("#preset-gallery");
    if (gal instanceof HTMLDetailsElement) gal.open = false;
    document
      .querySelectorAll("dialog[open], .toolbar-menu.open, .popover.open")
      .forEach((el) => {
        if (el instanceof HTMLDialogElement) el.close();
        else el.classList.remove("open");
      });
  });
  await page.waitForTimeout(150);
}

console.log("Opening", `${base}/toolkit`);
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
await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
await page.waitForSelector(".ops-item-icon, .chef-ops, .notebook-cell", {
  timeout: 20000,
});
await closeOverlays();
await ensureOpsExpanded();

await shot("01-toolkit-overview");

await shot("02-ops-tool-card", async () => {
  const tile = page.locator(".ops-item-icon:visible, [data-op]:visible").first();
  await tile.scrollIntoViewIfNeeded();
  await tile.hover();
  await page
    .waitForSelector("#ops-tool-card .tool-card, .tool-card", { timeout: 5000 })
    .catch(() => {});
});

await page.locator(".chef-ops").screenshot({
  path: resolve(outDir, "03-ops-pane-crop.png"),
}).catch(async () => {
  await shot("03-ops-pane-crop");
});
console.log("wrote", resolve(outDir, "03-ops-pane-crop.png"));

await shot("04-shares-outputs", async () => {
  const templates = page.locator(
    "#preset-gallery summary, .toolkit-presets-summary"
  );
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
  await page
    .waitForSelector(".notebook-cell, .builder-step, #notebook-cells", {
      timeout: 10000,
    })
    .catch(() => {});
});

await shot("17-tee-nest-builder", async () => {
  await closeOverlays();
  await loadRecipe(`genkey ec/p256 | tee
  - .public | export spki | pem.encode | out @public
| export pkcs8 | pem.encode | out @private`);
  await closeOverlays();
  await page
    .waitForSelector(
      ".builder-flow-block, .builder-step, .notebook-cell .builder-card",
      { timeout: 10000 }
    )
    .catch(() => {});
});

await shot("18-tee-branch-hover", async () => {
  const branch = page
    .locator(
      ".builder-flow-block, .tee-branch, .builder-branch, [data-branch]"
    )
    .first();
  if (await branch.count()) {
    await branch.hover();
    await page.waitForTimeout(300);
  }
  const chip = page.locator(".suggest-next-chips button, .ops-chip, .type-chip").first();
  if (await chip.count()) {
    await chip.hover();
    await page.waitForTimeout(300);
  }
});

await shot("19-recipe-raw-toggle", async () => {
  const rawBtn = page
    .locator("button, [role='tab']")
    .filter({ hasText: /^Raw$/i })
    .first();
  if (await rawBtn.count()) {
    await rawBtn.click();
    await page.waitForTimeout(400);
  } else {
    const details = page.locator("details.recipe-text-details");
    if (await details.count()) {
      await details.first().evaluate((el) => {
        el.open = true;
      });
    }
  }
});

await shot("05-mobile-narrow", async () => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 60000 });
  await page.waitForSelector(".ops-item-icon, .chef-ops, .notebook-cell", {
    timeout: 20000,
  });
});

await page.setViewportSize({ width: 1440, height: 960 });
const previewUrl = `${base}/tool-card-preview.html`;
const previewOk = await page
  .goto(previewUrl, { waitUntil: "networkidle", timeout: 15000 })
  .then(() => true)
  .catch(() => false);
if (previewOk) {
  await page.waitForSelector(".tool-card", { timeout: 15000 }).catch(() => {});
  await shot("06-tool-card-fixture");
}

await browser.close();
console.log("Done →", outDir);
