/**
 * The modal scroll lock, and why no `<style>` element carries it.
 *
 * Reported as a Sheet defect and measured on the built site at :4188, where it
 * turned out to be wider than that. Every Radix Dialog *and* every dropdown
 * pulls in `react-remove-scroll`, whose `react-remove-scroll-bar` half created
 * a `<style>` element at runtime and appended its CSS as a text node.
 * `style-src 'self'` refuses that:
 *
 *   violatedDirective: "style-src-elem", disposition: "enforce",
 *   blockedURI: "inline", sourceFile: assets/myKeys-*.js
 *
 * The element landed in `<head>` with a null `.sheet`, so its rules never
 * applied. On /toolkit that hid behind `body.layout-app { overflow: hidden }`
 * and looked like nothing was wrong; on /my-keys, whose body really scrolls,
 * the page went on scrolling behind an open menu. Invisible in `vite serve`,
 * where the dev CSP is relaxed — the first trap in HANDOFF.md, again.
 *
 * The fix follows the ScrollArea precedent exactly: the library keeps the part
 * that needs script, the stylesheet states the part that is only CSS. These
 * tests pin both halves and the seam between them.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
/** Comments removed, so prose explaining an absence cannot satisfy a test about it. */
const codeOnly = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

const SHIM = read("../lib/scroll-lock.js");
const SHIM_CODE = codeOnly(SHIM);
const VITE = read("../../vite.config.js");
const VITE_CODE = codeOnly(VITE);
const SITE_CSS = read("../css/site.css");
/**
 * The same treatment for CSS, and for the same reason: the rule below asserts
 * that `scrollbar-gutter` is *absent*, and the comment above the scroll-lock
 * block explains at length why it is absent. Without this the explanation
 * fails the test it explains.
 */
const SITE_CSS_CODE = SITE_CSS.replace(/\/\*[\s\S]*?\*\//g, "");

describe("the injecting package is aliased away", () => {
  it("points the bare specifier at lib/scroll-lock", () => {
    expect(VITE_CODE).toMatch(/react-remove-scroll-bar/);
    expect(VITE_CODE).toMatch(/src\/lib\/scroll-lock\.js/);
  });

  it("anchors the alias so the /constants subpath still reaches the package", () => {
    // A string alias matches `pattern` and everything under `pattern/`, which
    // would have rewritten `react-remove-scroll-bar/constants` — imported by
    // react-remove-scroll's UI.js — into a path inside our own file.
    expect(VITE_CODE).toMatch(/\/\^react-remove-scroll-bar\$\//);
  });

  it("keeps the @ alias working after the move to array form", () => {
    expect(VITE_CODE).toMatch(/find:\s*"@"/);
  });
});

describe("the replacement injects nothing", () => {
  it("never builds a style element", () => {
    for (const forbidden of [
      /createElement\(\s*["']style["']/,
      /react-style-singleton/,
      /styleSingleton/,
      /insertAdjacentHTML/,
      /innerHTML/,
      /cssText/,
    ]) {
      expect(SHIM_CODE, String(forbidden)).not.toMatch(forbidden);
    }
  });

  it("sets the attribute the stylesheet keys off", () => {
    expect(SHIM_CODE).toMatch(/data-scroll-locked/);
    expect(SHIM_CODE).toMatch(/setAttribute\(lockAttribute/);
    expect(SHIM_CODE).toMatch(/removeAttribute\(lockAttribute/);
  });

  it("reference-counts rather than toggling a flag", () => {
    // Locks nest — a dropdown opened inside a Sheet unmounts while the Sheet is
    // still open, and a boolean would unlock the page underneath it.
    expect(SHIM_CODE).toMatch(/parseInt\(/);
    expect(SHIM_CODE).toMatch(/depth \+ 1/);
  });

  it("routes the one continuous value through the constructed stylesheet", () => {
    // The scrollbar width is 0 on overlay platforms and ~15px elsewhere, so it
    // cannot be a static rule; every inline route to it is refused.
    expect(SHIM_CODE).toMatch(/from "\.\/css-vars\.js"/);
    expect(SHIM_CODE).toMatch(/setCssVar\(gutterVariable/);
    expect(SHIM_CODE).toMatch(/gutterVariable = "--scroll-lock-gutter"/);
  });

  it("publishes the gutter under a name of ours, not the library's", () => {
    // `lib/css-vars` writes to :root and never clears, and the library's
    // `--removed-body-scroll-bar-size` was scoped to the locked body — its own
    // docs say to expect it undefined and fall back. Writing it globally would
    // leave `right:`/`margin-right:` consumers compensating for a scrollbar
    // that is on screen. The constant stays exported, and stays unset.
    expect(SHIM_CODE).not.toMatch(/setCssVar\(\s*"--removed-body-scroll-bar-size"/);
    expect(SHIM_CODE).not.toMatch(/setCssVar\(\s*removedBarSizeVariable/);
  });

  it("measures only the outermost lock", () => {
    // Once `overflow: hidden` is on there is no scrollbar left to measure, so a
    // nested lock would publish 0 and undo the outer one's compensation.
    expect(SHIM_CODE).toMatch(/depth === 0/);
  });
});

describe("the replacement covers the package it stands in for", () => {
  it("exports everything the real index exports", () => {
    // The alias is invisible at the import site, so an upgrade that adds an
    // export would otherwise fail as an undefined at runtime, in the build
    // only. Read from the package's own ESM entry rather than a hand-kept list.
    const real = readFileSync(
      fileURLToPath(
        new URL(
          "../../node_modules/react-remove-scroll-bar/dist/es2015/index.js",
          import.meta.url
        )
      ),
      "utf8"
    );
    const declared = real.match(/export\s*\{([^}]*)\}/)?.[1] || "";
    const names = declared
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    expect(names.length).toBeGreaterThan(3);
    for (const name of names) {
      expect(SHIM_CODE, `missing export: ${name}`).toMatch(
        new RegExp(`\\b${name}\\b`)
      );
    }
  });
});

describe("site.css states the rules the injection used to carry", () => {
  it("locks the body and contains overscroll", () => {
    const rule = SITE_CSS_CODE.match(/body\[data-scroll-locked\]\s*\{[^}]*\}/)?.[0];
    expect(rule, "no body[data-scroll-locked] rule").toBeTruthy();
    expect(rule).toMatch(/overflow:\s*hidden\s*!important/);
    expect(rule).toMatch(/overscroll-behavior:\s*contain/);
  });

  it("pads the scroll container by the measured gutter", () => {
    // Padding the container, not rewriting body's margins the way the library
    // did: `body { max-width: 1000px; margin: 0 auto }` means zeroing that
    // margin throws every ordinary page's content against one edge.
    const rule = SITE_CSS_CODE.match(
      /html:has\(>\s*body\[data-scroll-locked\]\)\s*\{[^}]*\}/
    )?.[0];
    expect(rule, "no html:has(> body[data-scroll-locked]) rule").toBeTruthy();
    expect(rule).toMatch(/overflow:\s*hidden/);
    expect(rule).toMatch(/padding-right:\s*var\(--scroll-lock-gutter,\s*0px\)/);
    // The fallback is not decoration: it is what holds the page still on the
    // first frame of a lock, before the effect has published a measurement.
    expect(rule).toMatch(/,\s*0px\)/);
  });

  it("does not reserve a gutter the platform never took", () => {
    // `scrollbar-gutter: stable` was the shortcut, and Chromium reserves the
    // gutter even where overlay scrollbars take no width at all: measured on
    // the built page, it moved a centred body 7.5px on every menu open, in the
    // exact class of case the compensation exists to prevent.
    expect(SITE_CSS_CODE).not.toMatch(/scrollbar-gutter/);
  });

  it("lives in site.css, which every page loads", () => {
    // Dropdowns are on every page; toolkit.css is on two of them.
    const TOOLKIT_CSS = read("../css/toolkit.css");
    expect(TOOLKIT_CSS).not.toMatch(/data-scroll-locked/);
    expect(read("../components/Layout.tsx")).toMatch(/css\/site\.css/);
  });
});

describe("the policy is not asked to bless the injection", () => {
  it("carries no style-src hash on any page", () => {
    // A `sha256-` exemption would have silenced the report and left a runtime
    // <style> write on the page — the thing style-src exists to stop — and
    // would need re-deriving every time the library changed a byte of that CSS.
    // `my-keys.html` and `quorum.html` were retired into the toolkit;
    // `published.html` is the page that inherited the first one's account half
    // and its scrolling body, which is the property that put it on this list.
    for (const page of [
      "toolkit.html",
      "published.html",
      "index.html",
      "key.html",
      "preferences.html",
    ]) {
      const html = read(`../../${page}`);
      expect(html, page).toMatch(/style-src 'self';/);
      expect(html, page).not.toMatch(/style-src[^;]*sha256-/);
      expect(html, page).not.toMatch(/style-src[^;]*unsafe-inline/);
    }
  });
});
