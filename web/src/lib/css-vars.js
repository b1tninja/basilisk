/**
 * CSP-safe dynamic styling — set a CSS custom property from JS without an
 * inline style.
 *
 * The problem this exists for: a resizable panel and a progress bar carry
 * genuinely continuous values, so no enumerated stylesheet can cover them the
 * way `[data-peer-state]` covers a closed set. Every obvious remedy is an
 * inline style that `style-src 'self'` refuses in production — a React style
 * prop, an `element.style.width` write, and an
 * `element.style.setProperty("--w", …)` call all take the same blocked path,
 * and injecting a `<style>` element is refused by `style-src-elem`.
 *
 * (Phrased without the literal JSX prop on purpose: `no-inline-styles.test.js`
 * greps sources for it and is deliberately too naive to skip comments — a
 * guard that parsed JS to avoid false positives could also be fooled.)
 *
 * A *constructed* stylesheet is not an inline style: it is CSSOM built by
 * script that is already trusted, so CSP does not gate it. One sheet is
 * adopted once and its single `:root` rule is rewritten in place, which also
 * keeps this cheap — no rule churn, no growing sheet.
 *
 * Values are written into a stylesheet, so they are only ever numbers with a
 * unit that this module formats. Callers pass numbers; nothing here
 * interpolates caller-supplied text into CSS.
 * @module lib/css-vars
 */

/** @type {CSSStyleSheet|null} */
let sheet = null;
/** @type {Map<string, string>} */
const vars = new Map();

function supported() {
  return (
    typeof document !== "undefined" &&
    typeof CSSStyleSheet === "function" &&
    "adoptedStyleSheets" in Document.prototype &&
    // Constructed sheets need the constructor to accept no arguments.
    (() => {
      try {
        new CSSStyleSheet();
        return true;
      } catch {
        return false;
      }
    })()
  );
}

function ensureSheet() {
  if (sheet) return sheet;
  if (!supported()) return null;
  sheet = new CSSStyleSheet();
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
  return sheet;
}

function flush() {
  const s = ensureSheet();
  if (!s) return;
  const body = [...vars.entries()].map(([k, v]) => `${k}:${v}`).join(";");
  // replaceSync rather than insertRule: one rule, rewritten wholesale, so the
  // sheet never accumulates stale declarations.
  s.replaceSync(`:root{${body}}`);
}

/**
 * Set a `--custom-property` on :root to a numeric value with a unit.
 *
 * @param {string} name  must look like `--kebab-name`
 * @param {number} value non-finite values are ignored rather than emitting
 *   `NaN`, which would silently void the whole rule
 * @param {"px"|"%"|""} [unit]
 * @returns {boolean} whether the value was applied
 */
export function setCssVar(name, value, unit = "px") {
  if (!/^--[a-z0-9-]+$/i.test(String(name))) return false;
  if (!Number.isFinite(value)) return false;
  const next = `${Math.round(Number(value) * 1000) / 1000}${unit}`;
  if (vars.get(name) === next) return true; // no-op: avoid needless reflow
  vars.set(name, next);
  flush();
  return true;
}

/** Current value of a var this module set (tests + diagnostics). */
export function getCssVar(name) {
  return vars.get(name) ?? null;
}

/** Drop everything — used by tests to isolate cases. */
export function resetCssVars() {
  vars.clear();
  if (sheet) sheet.replaceSync(":root{}");
}
