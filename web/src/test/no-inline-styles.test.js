/**
 * Guard against reintroducing inline style attributes, which CSP style-src 'self' blocks.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WEB_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(WEB_ROOT, "src");
const STYLE_ATTR = /style\s*=\s*"/i;

function walk(dir, pred, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const st = statSync(path);
    if (st.isDirectory()) {
      if (name === "node_modules" || name === "dist" || name === "static") continue;
      walk(path, pred, out);
    } else if (pred(path)) {
      out.push(path);
    }
  }
  return out;
}

function offenders(paths) {
  /** @type {{ file: string, line: number, text: string }[]} */
  const hits = [];
  for (const path of paths) {
    const lines = readFileSync(path, "utf8").split(/\r?\n/);
    lines.forEach((text, i) => {
      if (STYLE_ATTR.test(text)) {
        hits.push({
          file: relative(WEB_ROOT, path).replace(/\\/g, "/"),
          line: i + 1,
          text: text.trim(),
        });
      }
    });
  }
  return hits;
}

describe("no inline style attributes (CSP style-src 'self')", () => {
  it("src JS and page HTML bodies have no style=\"...\"", () => {
    const jsFiles = walk(
      SRC_ROOT,
      (p) => p.endsWith(".js") && !p.includes(`${join("src", "test")}`)
    );
    // Include test files that are not this guard? Skip all tests — they shouldn't ship markup.
    const htmlFiles = walk(WEB_ROOT, (p) => {
      if (!p.endsWith(".html")) return false;
      const rel = relative(WEB_ROOT, p).replace(/\\/g, "/");
      return !rel.startsWith("dist/") && !rel.startsWith("static/") && !rel.includes("/");
    });

    const hits = offenders([...jsFiles, ...htmlFiles]);
    expect(
      hits,
      hits.map((h) => `${h.file}:${h.line}: ${h.text}`).join("\n")
    ).toEqual([]);
  });
});
