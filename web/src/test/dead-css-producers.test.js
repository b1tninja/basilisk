/**
 * Every class the stylesheets define has to be one something can put on an
 * element.
 *
 * This is the same defect the repo keeps finding, in CSS: a finished thing with
 * no consumer. `.chef-*` and `.pane-*` went first, then this sweep found 415
 * more — a whole pre-React vocabulary (`.builder-*`, `.ops-drill-*`,
 * `.session-tray-*`, `.notebook-header-*`) still being carried, restyled and
 * token-migrated by every pass that touched the file, for markup that no longer
 * exists. Nothing failed while it accumulated, which is why it accumulated.
 *
 * ## Why a class name is safe to sweep this way
 *
 * A class reaches the browser as a **string literal** — in JSX, in a template,
 * in an HTML attribute — and a bundler preserves string literals. So "the name
 * appears nowhere in the source" really does mean "no element can carry it".
 * The same check is worthless for a function identifier, which the build
 * mangles; do not reuse the shape for one.
 *
 * ## The one exception, and why it is a list rather than a cleverer scan
 *
 * A class assembled at runtime never appears whole: `packet-map.js` returns
 * `` `pkt-color-${colorIndex % 8}` ``, so all eight `.pkt-color-N` rules are
 * reached and a literal sweep is simply wrong about them.
 *
 * Detecting that automatically was tried and abandoned. Harvesting every static
 * fragment that sits beside an interpolation finds the real constructors — and
 * also `` `${row.from} finished cell ${row.cell}.` `` (prose), `` `ops-${count}-${hash}` ``
 * (a registry fingerprint), and `` key={`gap-${i}`} `` (a React key). A regex
 * cannot tell a class from a filename from a sentence; on this repo the
 * generous version rescued 152 candidates of which 20 were real. So the
 * constructors are written down instead, each next to the file that builds it,
 * and the list may only shrink: an entry that no longer matches any defined
 * class fails, and so does one whose constructor has left its file.
 */
import { execFileSync as run } from "node:child_process";
import { readFileSync as read } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO = fileURLToPath(new URL("../../..", import.meta.url));
const CSS = ["web/src/css/site.css", "web/src/css/toolkit.css"];

/** Extensions that can carry a class name. `.css` is the definition side. */
const TEXT = /\.(ts|tsx|js|jsx|mjs|html|py|jinja|j2|md|json)$/;

/**
 * The keys of `TOOLBOX_META`, which are the only values `toolbox-${tb}` takes.
 *
 * Read rather than restated so the exemption cannot outgrow the registry:
 * `/^toolbox-\w+$/` would shelter a `.toolbox-cobol` nobody ever ships.
 */
function toolboxKeys() {
  const src = read(REPO + "web/src/lib/toolkit/registry.js", "utf8");
  const block = /export const TOOLBOX_META = \{([\s\S]*?)\n\};/.exec(src);
  if (!block) return [];
  return [...block[1].matchAll(/^ {2}([a-z][\w]*):\s*\{/gm)].map((m) => m[1]);
}

const TOOLBOXES = toolboxKeys();

/**
 * Classes assembled at runtime, so no literal exists to find.
 *
 * `match` is the family; `builtBy` is the file that builds it and `expression`
 * a fragment of the line that does, so an entry cannot outlive its constructor.
 * This list may only shrink.
 */
const CONSTRUCTED = [
  {
    match: /^pkt-color-[0-7]$/,
    builtBy: "web/src/lib/packet-map.js",
    expression: "`pkt-color-${colorIndex % 8}`",
    why: "eight tag colours, indexed by span, for the packet map and hex view",
  },
  {
    match: new RegExp(`^toolbox-(${TOOLBOXES.join("|")})$`),
    builtBy: "web/src/toolkit/widgets/ToolCard.tsx",
    expression: "`toolbox-badge toolbox-${tb}`",
    why: "one tint per toolbox; `tb` is a key of TOOLBOX_META in lib/toolkit/registry.js",
  },
  {
    match: /^trust-(trusted|marginal|never)$/,
    builtBy: "web/src/lib/trust.js",
    expression: 'class="trust-badge trust-${level}"',
    why: "the three local trust levels, which trust.js validates before writing",
  },
];

/** Class selectors declared by the two stylesheets, as name -> file. */
function definedClasses() {
  const out = new Map();
  for (const rel of CSS) {
    const text = read(REPO + rel, "utf8").replace(/\/\*[\s\S]*?\*\//g, " ");
    for (const [, head] of text.matchAll(/([^{}]+)\{/g)) {
      if (head.trim().startsWith("@")) continue;
      for (const [, name] of head.matchAll(/\.([a-zA-Z][\w-]*)/g)) {
        if (!out.has(name)) out.set(name, rel);
      }
    }
  }
  return out;
}

/**
 * Every class-shaped token in every tracked non-CSS text file.
 *
 * Enumerated from `git ls-files` rather than by walking a chosen directory:
 * the first version of this sweep hand-walked `web/src` and `web/*.html`, never
 * saw `basilisk/web/templates/claim.html`, and reported a number drawn from an
 * incomplete list. Asking git is what makes the sweep's own coverage checkable.
 */
function producedTokens() {
  const files = run("git", ["ls-files"], { cwd: REPO, encoding: "utf8", maxBuffer: 1 << 26 })
    .split("\n")
    .filter((f) => TEXT.test(f) && !f.endsWith(".css") && !f.includes("/css/"));
  const tokens = new Set();
  for (const rel of files) {
    let text;
    try {
      text = read(REPO + rel, "utf8");
    } catch {
      continue; // a tracked file that is not on disk in this checkout
    }
    for (const tok of text.split(/[^A-Za-z0-9_-]+/)) if (tok) tokens.add(tok);
  }
  return { tokens, count: files.length };
}

describe("every CSS class has a producer", () => {
  const defined = definedClasses();
  const { tokens, count } = producedTokens();

  it("is measuring both stylesheets and the whole tracked tree", () => {
    // An empty sweep passes every assertion below it.
    expect(count, "git ls-files returned almost nothing — the cwd is wrong").toBeGreaterThan(500);
    expect(defined.size, "no class selectors parsed out of the stylesheets").toBeGreaterThan(400);
    expect(new Set(defined.values()).size, "only one stylesheet was read").toBe(2);
    expect(tokens.has("ops-panel"), "a known-live class is missing from the haystack").toBe(true);
    // An exemption built from an empty list would match nothing and quietly
    // stop exempting — or, with a bad join, match everything.
    expect(TOOLBOXES.length, "TOOLBOX_META did not parse out of registry.js").toBeGreaterThan(10);
    expect(TOOLBOXES).toContain("webcrypto");
  });

  it("defines no class that nothing in the repo can put on an element", () => {
    const orphans = [];
    for (const [name, file] of defined) {
      if (tokens.has(name)) continue;
      if (CONSTRUCTED.some((c) => c.match.test(name))) continue;
      orphans.push(`${file}: .${name}`);
    }
    expect(
      orphans,
      "these class selectors are styled but unreachable — no literal anywhere in the " +
        "tracked tree names them, and no entry in CONSTRUCTED builds them. Delete the " +
        "rules, or add the constructor to CONSTRUCTED with the file that builds it:\n" +
        orphans.join("\n")
    ).toEqual([]);
  });

  it("keeps no exemption whose classes are gone", () => {
    const stale = CONSTRUCTED.filter(
      (c) => ![...defined.keys()].some((name) => c.match.test(name))
    ).map((c) => String(c.match));
    expect(
      stale,
      `these exemptions match no class the stylesheets still define — the rules went, ` +
        `so the exemption should go too: ${stale.join(", ")}`
    ).toEqual([]);
  });

  it("keeps no exemption whose constructor has left its file", () => {
    // The list is a record of where each name is built, not a mute allowlist.
    // If the expression moves or is deleted, the exemption stops being evidence.
    const broken = [];
    for (const c of CONSTRUCTED) {
      const src = read(REPO + c.builtBy, "utf8");
      if (!src.includes(c.expression)) broken.push(`${c.builtBy}: ${c.expression}`);
    }
    expect(
      broken,
      `an exemption names a constructor its file no longer contains, so it is no ` +
        `longer evidence that anything builds the class: ${broken.join(", ")}`
    ).toEqual([]);
  });
});
