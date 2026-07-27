/**
 * Guard: smoke stubs / catalogs must stay out of production entry points.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

const webRoot = fileURLToPath(new URL("../..", import.meta.url));
const forbid = [
  "verb-smoke",
  "toolkit-smoke-stubs",
  "installWebAuthnPrfStub",
  "installHkpFetchMock",
  "basilisk-verb-smoke-cred",
];

/**
 * @param {string} dir
 * @param {(p: string) => boolean} pred
 * @returns {string[]}
 */
function walk(dir, pred) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist" || name === "test") continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walk(p, pred));
    else if (pred(p)) out.push(p);
  }
  return out;
}

describe("toolkit smoke isolation", () => {
  it("production src does not reference smoke stubs or catalogs", () => {
    const roots = [join(webRoot, "src", "lib"), join(webRoot, "src", "pages")];
    /** @type {string[]} */
    const hits = [];
    for (const root of roots) {
      for (const file of walk(root, (p) => /\.(js|html)$/.test(p))) {
        const text = readFileSync(file, "utf8");
        for (const needle of forbid) {
          if (text.includes(needle)) {
            hits.push(`${relative(webRoot, file)}: ${needle}`);
          }
        }
      }
    }
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("vite toolkit entry does not pull test helpers", () => {
    const vite = readFileSync(join(webRoot, "vite.config.js"), "utf8");
    for (const needle of forbid) {
      expect(vite.includes(needle), needle).toBe(false);
    }
    // Toolkit page entry should stay pages/html — not test/
    expect(vite).toMatch(/toolkit\.html|pages\/toolkit/);
  });
});
