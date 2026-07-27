import { chromium } from "playwright";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const base = process.argv[2] || "http://127.0.0.1:5173";
const out = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../tmp/snapshots/toolkit-ops-hover.png"
);

const b = await chromium.launch({ headless: true });
const p = await b.newPage({
  viewport: { width: 1400, height: 900 },
  colorScheme: "dark",
});
const errs = [];
p.on("console", (m) => {
  if (m.type() === "error") errs.push(m.text());
});

await p.goto(`${base}/toolkit`, { waitUntil: "networkidle", timeout: 45000 });
await p.waitForSelector(".ops-item-icon");
await p.waitForTimeout(400);

const info = await p.evaluate(() => {
  const csp =
    document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content ||
    "";
  const tile = document.querySelector(".ops-item-icon");
  const cs = tile ? getComputedStyle(tile) : null;
  return {
    bg: getComputedStyle(document.body).backgroundColor,
    title: document.title,
    brand: getComputedStyle(document.documentElement).getPropertyValue("--brand").trim(),
    tileCursor: cs?.cursor || null,
    cspHasUnsafeInline: csp.includes("style-src 'self' 'unsafe-inline'"),
  };
});

const hasIcon = await p.locator(".ops-item-icon").count();
await p.locator(".ops-item-icon:visible").first().hover();
await p.waitForTimeout(400);
const card = await p.locator("#ops-tool-card .tool-card").count();

console.log(
  JSON.stringify({ ...info, hasIcon, card, errs: errs.slice(0, 8) }, null, 2)
);
await p.screenshot({ path: out, fullPage: false });
console.log("wrote", out);
await b.close();
