/**
 * Guard against inline styles, which `style-src 'self'` blocks at runtime.
 *
 * This guard had two blind spots that let 23 violations accumulate unnoticed:
 * it only walked `.js` files (so every React component was exempt), and it only
 * matched the HTML `style="…"` attribute (so JSX style objects were exempt).
 * Both produce the same `element.style` write the CSP refuses, reported in the
 * console as "Applying inline style violates … 'style-src self'".
 *
 * Fixing the scope surfaced a backlog too large to convert in one pass, so the
 * guard runs as a *ratchet*: known files carry a recorded count, and the test
 * fails if any file exceeds it or if a new file appears. Converting a site
 * means lowering its number — the baseline may go down, never up.
 *
 * Converting looks like `ConnectionsPanel`: give the element a data attribute
 * and enumerate the states in `toolkit.css`. That works because these are all
 * closed sets (toolbox, peer state, run state), not arbitrary user colour.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WEB_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(WEB_ROOT, "src");

/** HTML `style="…"` and JSX `style={{…}}` — both become element.style writes. */
const INLINE_STYLE = /style\s*=\s*(?:"|\{\{)/;

/**
 * Inline-style sites still to convert, per file.
 *
 * Every entry is a pre-existing violation, not an exemption on principle:
 * each is a real CSP error in the console today. Lower these as they are
 * converted; do not add to them.
 */
const BASELINE = {
  "src/pages/index.tsx": 3,
  "src/pages/toolkit.tsx": 1,
  "src/toolkit/ToolkitShell.tsx": 2,
  "src/toolkit/widgets/Glyph.tsx": 1,
  "src/toolkit/widgets/NetworkArtifact.tsx": 3,
  // OpsShelf (was 4) and TopBar (was 6) converted to data attributes +
  // enumerated CSS — toolbox-dot / suite-tone rules in toolkit.css.
  "src/toolkit/widgets/RunBar.tsx": 1,
  // SessionStrip (was 1) converted with the per-peer work — the status dot's
  // tone and live glow are `[data-session-tone]` rules in toolkit.css.
};

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

function rel(path) {
  return relative(WEB_ROOT, path).replace(/\\/g, "/");
}

/** @returns {Map<string, {line:number,text:string}[]>} */
function offendersByFile(paths) {
  const byFile = new Map();
  for (const path of paths) {
    const hits = [];
    readFileSync(path, "utf8")
      .split(/\r?\n/)
      .forEach((text, i) => {
        if (INLINE_STYLE.test(text)) hits.push({ line: i + 1, text: text.trim() });
      });
    if (hits.length) byFile.set(rel(path), hits);
  }
  return byFile;
}

function sourceFiles() {
  const src = walk(
    SRC_ROOT,
    (p) => /\.(js|ts|tsx)$/.test(p) && !p.includes(`${join("src", "test")}`)
  );
  const html = walk(WEB_ROOT, (p) => {
    if (!p.endsWith(".html")) return false;
    const r = rel(p);
    return !r.startsWith("dist/") && !r.startsWith("static/") && !r.includes("/");
  });
  return [...src, ...html];
}

describe("inline styles (CSP style-src 'self')", () => {
  const byFile = offendersByFile(sourceFiles());

  it("adds no inline styles in files that had none", () => {
    const added = [...byFile.keys()].filter((f) => !(f in BASELINE));
    expect(
      added,
      `New file(s) with inline styles — use a data attribute + CSS instead:\n${added
        .map((f) => `${f}: ${byFile.get(f)[0].text}`)
        .join("\n")}`
    ).toEqual([]);
  });

  it("does not grow the count in files that already had some", () => {
    const grown = [];
    for (const [file, max] of Object.entries(BASELINE)) {
      const n = byFile.get(file)?.length ?? 0;
      if (n > max) grown.push(`${file}: ${n} > ${max}`);
    }
    expect(grown, grown.join("\n")).toEqual([]);
  });

  it("keeps the baseline honest — lower it once a file is converted", () => {
    // Catches a stale entry left behind after conversion, so the list shrinks
    // toward nothing rather than quietly granting permanent exemptions.
    const stale = [];
    for (const [file, max] of Object.entries(BASELINE)) {
      const n = byFile.get(file)?.length ?? 0;
      if (n < max) stale.push(`${file}: now ${n}, baseline still ${max}`);
    }
    expect(stale, stale.join("\n")).toEqual([]);
  });
});
