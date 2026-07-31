/**
 * CSP-safe dynamic styling (lib/css-vars).
 *
 * Continuous values — a resizable panel, a progress fill — cannot be covered
 * by an enumerated stylesheet, and every inline route to them is refused by
 * `style-src 'self'`. This module writes them into a *constructed* stylesheet
 * instead, which CSP does not gate.
 */
import { afterEach, describe, expect, it } from "vitest";
import { getCssVar, resetCssVars, setCssVar } from "../lib/css-vars.js";

afterEach(() => resetCssVars());

describe("setCssVar", () => {
  it("stores a numeric value with its unit", () => {
    expect(setCssVar("--ops-width", 320, "px")).toBe(true);
    expect(getCssVar("--ops-width")).toBe("320px");
    setCssVar("--run-progress", 42.5, "%");
    expect(getCssVar("--run-progress")).toBe("42.5%");
  });

  it("refuses a name that is not a custom property", () => {
    // The value is interpolated into a stylesheet, so the name is constrained
    // rather than trusted — `width:red;}` must not be able to ride in on it.
    for (const bad of ["width", "--bad;color:red", "--x{}", "", "-x"]) {
      expect(setCssVar(bad, 1), bad).toBe(false);
    }
  });

  it("ignores non-finite values instead of emitting NaN", () => {
    // `NaN px` would void the whole :root rule, silently killing every other
    // variable in it — a much worse failure than not applying one update.
    for (const bad of [NaN, Infinity, -Infinity, undefined, null, "12"]) {
      expect(setCssVar("--ops-width", bad), String(bad)).toBe(false);
    }
    expect(getCssVar("--ops-width")).toBeNull();
  });

  it("is idempotent for an unchanged value", () => {
    setCssVar("--ops-width", 300);
    expect(setCssVar("--ops-width", 300)).toBe(true);
    expect(getCssVar("--ops-width")).toBe("300px");
  });

  it("rounds rather than emitting float noise", () => {
    setCssVar("--run-progress", 33.333333333, "%");
    expect(getCssVar("--run-progress")).toBe("33.333%");
  });

  it("keeps several variables side by side", () => {
    setCssVar("--ops-width", 280);
    setCssVar("--run-progress", 10, "%");
    expect(getCssVar("--ops-width")).toBe("280px");
    expect(getCssVar("--run-progress")).toBe("10%");
  });
});

describe("the stylesheet has usable fallbacks", () => {
  it("declares a default width and progress so the first paint is sane", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const css = readFileSync(
      fileURLToPath(new URL("../css/toolkit.css", import.meta.url)),
      "utf8"
    );
    // Before the first resize — or on an engine without constructed
    // stylesheets — the panel must still have a width.
    expect(css).toMatch(/\.ops-panel\s*\{[^}]*var\(--ops-width,\s*\d+px\)/);
    expect(css).toMatch(/\.run-progress-fill\s*\{[^}]*var\(--run-progress,\s*0%\)/);
  });
});
